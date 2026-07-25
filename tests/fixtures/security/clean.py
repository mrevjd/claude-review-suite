"""CLEAN-FIXTURE -- the same seven situations as vulnerable.py, written correctly.

A review of this file must produce no Critical and no High findings.
"""

import hmac
import ipaddress
import json
import logging
import os
import secrets
import socket
import sqlite3
import subprocess
import uuid
from hashlib import scrypt
from urllib.parse import urlparse

import requests

log = logging.getLogger(__name__)


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

# SEC-04: credentials come from the environment, never from source, and the code fails closed rather
# than falling back to a committed default.
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
STRIPE_KEY = os.environ["STRIPE_KEY"]

# SEC-05: scrypt parameters kept together so they can be raised in one place as hardware improves.
SCRYPT_PARAMS = {"n": 2**15, "r": 8, "p": 1, "dklen": 32}
SALT_BYTES = 16

# SEC-06: outbound fetches are restricted to hosts we intend to talk to.
AVATAR_HOST_ALLOWLIST = frozenset({"avatars.example.com", "cdn.example.com"})


# SEC-01: authentication is applied, and the admin action additionally requires the admin role.
# Deny-by-default belongs at the router in a real app; here the decorator is unconditional and the
# role check is explicit rather than assumed from the path prefix.
@app.require_auth
@app.route("/admin/refund", methods=["POST"])
def admin_refund(request):
    if request.user.role != "admin":
        return {"error": "forbidden"}, 403

    try:
        amount = int(request.form["amount_cents"])
    except (KeyError, ValueError):
        return {"error": "amount_cents must be an integer"}, 400

    if amount <= 0:
        return {"error": "amount_cents must be positive"}, 400

    account = request.form["account"]
    with db:
        db.execute(
            "UPDATE accounts SET balance = balance - ? WHERE id = ?",
            (amount, account),
        )
    return {"refunded": amount}


@app.require_auth
@app.route("/invoices/<invoice_id>")
def get_invoice(request, invoice_id):
    # SEC-02: the query is scoped by the authenticated principal, so an ID belonging to someone else
    # simply does not match. Ownership is enforced in the query, not remembered by the handler.
    row = db.execute(
        "SELECT id, total FROM invoices WHERE id = ? AND customer_id = ?",
        (invoice_id, request.user.customer_id),
    ).fetchone()

    if row is None:
        return {"error": "not found"}, 404

    # SEC-07: an explicit field allow-list, so adding a sensitive column to the table cannot
    # silently start exposing it.
    return {"invoice": {"id": row[0], "total": row[1]}}


@app.require_auth
@app.route("/reports/export")
def export_report(request):
    # SEC-03: the value is validated to a known shape and passed as a separate argv element with no
    # shell, so there is no string for an injected command to live in.
    month = request.args.get("month", "")
    if not _is_month(month):
        return {"error": "month must look like YYYY-MM"}, 400

    out = subprocess.check_output(
        ["/usr/local/bin/report", f"--month={month}"],
        shell=False,
        timeout=30,
    )
    return {"report": out.decode()}


def _is_month(value):
    if len(value) != 7 or value[4] != "-":
        return False
    year, _, month = value.partition("-")
    return year.isdigit() and month.isdigit() and 1 <= int(month) <= 12


def store_password(user_id, password):
    # SEC-05: a real KDF with a per-user random salt, so a database dump costs an attacker real time
    # per candidate password instead of a table lookup.
    salt = secrets.token_bytes(SALT_BYTES)
    digest = scrypt(password.encode(), salt=salt, **SCRYPT_PARAMS)
    with db:
        db.execute(
            "UPDATE users SET pass_salt = ?, pass_hash = ? WHERE id = ?",
            (salt, digest, user_id),
        )


def verify_password(password, salt, expected_hash):
    # SEC-01: constant-time comparison, so timing does not leak how much of the digest matched.
    candidate = scrypt(password.encode(), salt=salt, **SCRYPT_PARAMS)
    return hmac.compare_digest(candidate, expected_hash)


def new_reset_token():
    # SEC-05: a CSPRNG, so the token cannot be predicted from previously issued ones.
    return secrets.token_urlsafe(32)


@app.route("/prefs/restore", methods=["POST"])
def restore_prefs(request):
    # SEC-06: JSON is data only -- no class is constructed and no code runs during parsing.
    try:
        prefs = json.loads(request.body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"error": "prefs must be JSON"}, 400

    if not isinstance(prefs, dict):
        return {"error": "prefs must be a JSON object"}, 400

    return {"prefs": prefs}


def _is_public_host(host):
    """Resolve the host and refuse anything that is not a public unicast address.

    Note what this does *not* give you: the address checked here and the address the HTTP client
    later connects to are two independent resolutions, so a host whose DNS an attacker controls can
    answer once with a public address and again with 169.254.169.254. Closing that gap means
    pinning the address -- resolve once, connect to that IP, and pass the hostname through the Host
    header and TLS SNI -- which needs a custom connection adapter rather than a bare requests.get.
    The allow-list below is what makes the residual risk acceptable here: an attacker would already
    need control of a host we ship in AVATAR_HOST_ALLOWLIST.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False

    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return False
    return True


@app.require_auth
@app.route("/fetch-avatar")
def fetch_avatar(request):
    # SEC-06: three layers, in order of how much they actually buy. The host allow-list is the one
    # doing the real work; the public-address check catches an allow-listed host that starts
    # resolving somewhere internal; not following redirects stops a 302 from walking the request
    # somewhere the first two checks never saw. See _is_public_host for what remains open.
    parsed = urlparse(request.args.get("url", ""))

    if parsed.scheme != "https" or parsed.hostname not in AVATAR_HOST_ALLOWLIST:
        return {"error": "avatar host not allowed"}, 400
    if not _is_public_host(parsed.hostname):
        return {"error": "avatar host does not resolve to a public address"}, 400

    resp = requests.get(parsed.geturl(), timeout=5, allow_redirects=False)
    if resp.status_code != 200:
        return {"error": "avatar fetch failed"}, 502

    return {"body": resp.content[:1024]}


@app.route("/login", methods=["POST"])
def login(request):
    email = request.form.get("email", "")
    password = request.form.get("password", "")

    row = db.execute(
        "SELECT id, pass_salt, pass_hash FROM users WHERE email = ?", (email,)
    ).fetchone()

    # SEC-07: both failure modes return the same status and the same body, so the endpoint is not an
    # enumeration oracle. The dummy verification keeps the timing comparable for an unknown email.
    if row is None:
        verify_password(password, b"\x00" * SALT_BYTES, b"\x00" * SCRYPT_PARAMS["dklen"])
        return {"error": "invalid email or password"}, 401

    if not verify_password(password, row[1], row[2]):
        return {"error": "invalid email or password"}, 401

    return {"token": new_reset_token()}


@app.route("/orders/<order_id>")
def get_order(request, order_id):
    # SEC-07: the detail is logged server-side against a correlation ID; the client gets the ID and
    # nothing else, so internal paths, versions and the environment stay inside.
    try:
        row = db.execute(
            "SELECT id, total FROM orders WHERE id = ?", (order_id,)
        ).fetchone()
    except sqlite3.Error:
        incident = uuid.uuid4().hex
        log.exception("order lookup failed (incident=%s, order_id=%s)", incident, order_id)
        return {"error": "internal error", "incident": incident}, 500

    if row is None:
        return {"error": "not found"}, 404

    return {"order": {"id": row[0], "total": row[1]}}
