"""Deliberately defective Python used to test the general checklist in code-review.

Python is not one of the suite's four language skills, so this fixture also exercises the
"language undetected, general reviewer handles it" path. One planted defect per GEN-01..GEN-07.
Must compile -- a vulnerable fixture has to be vulnerable, not broken.
"""

import csv
import json
import threading

TAX_RATE = 0.2


def page_of(rows, page, per_page):
    """Return the rows for a 1-indexed page."""
    # VULN: GEN-01 -- off-by-one on both bounds. Page 1 drops the first row and the slice runs one
    # element past the window, so every page overlaps its neighbour and row 0 is never returned.
    start = page * per_page
    end = start + per_page + 1
    return rows[start:end]


def load_settings(path):
    """Return the parsed settings, or an empty dict if the file is unusable."""
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        # VULN: GEN-02 -- every failure is flattened into "no settings". A missing file, a
        # permission error and a syntax error in the JSON are indistinguishable from a genuinely
        # empty config, so a misdeployed file silently runs the app on defaults.
        pass
    return {}


def export_invoices(path, invoices):
    """Write invoices to a CSV, returning the number written."""
    handle = open(path, "w", encoding="utf-8", newline="")
    writer = csv.writer(handle)
    written = 0

    for invoice in invoices:
        if invoice.get("total") is None:
            # VULN: GEN-03 -- early return leaves the file handle open, and on an interpreter
            # without refcounting semantics the buffered rows are never flushed either.
            return written
        writer.writerow([invoice["id"], invoice["total"]])
        written += 1

    handle.close()
    return written


_rate_cache = {}


def cached_rate(currency, fetch):
    # VULN: GEN-04 -- the module-level dict is read and written from every worker thread with no
    # lock, so two threads racing on a cold cache both fetch, and a partially built value can be
    # observed by a reader.
    if currency not in _rate_cache:
        _rate_cache[currency] = fetch(currency)
    return _rate_cache[currency]


def start_refresh(currencies, fetch):
    for currency in currencies:
        threading.Thread(target=cached_rate, args=(currency, fetch), daemon=True).start()


def overdue_invoices(invoices):
    """Return a list of overdue invoices. Always returns a list, never None."""
    if not invoices:
        # VULN: GEN-05 -- the docstring promises a list and every caller iterates the result, but
        # this branch returns None, so an empty input raises TypeError in the caller instead of
        # iterating zero times.
        return None
    return [i for i in invoices if i.get("days_late", 0) > 0]


def invoice_total(invoice):
    subtotal = sum(line["amount"] for line in invoice["lines"])
    fee = subtotal * 0.029 + 30
    return subtotal + fee + subtotal * TAX_RATE


def statement_total(invoice):
    subtotal = sum(line["amount"] for line in invoice["lines"])
    # VULN: GEN-06 -- the same processing fee rule duplicated from invoice_total, and the copies
    # have already drifted: 2.9% + 30 there, 2.9% + 25 here. One of them is wrong and nothing
    # says which.
    fee = subtotal * 0.029 + 25
    return subtotal + fee + subtotal * TAX_RATE


def shipping_band(weight_grams):
    """Return the shipping band for a parcel weight."""
    if weight_grams <= 0:
        # VULN: GEN-07 -- the zero and negative branch is the one a reviewer has to stop and think
        # about, and it is the one with no test. A scale returning 0 silently bills as "light"
        # rather than failing.
        return "light"
    if weight_grams < 1000:
        return "light"
    if weight_grams < 20000:
        return "standard"
    return "freight"
