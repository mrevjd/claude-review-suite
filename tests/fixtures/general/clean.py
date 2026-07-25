"""CLEAN-FIXTURE -- the same seven situations as vulnerable.py, written correctly.

A review of this file must produce no Critical and no High findings.
"""

import csv
import json
import logging
import threading

log = logging.getLogger(__name__)

TAX_RATE = 0.2
PROCESSING_RATE = 0.029
PROCESSING_FLAT_PENCE = 30


def page_of(rows, page, per_page):
    """Return the rows for a 1-indexed page. Page numbers below 1 are rejected."""
    # GEN-01: bounds are correct for a 1-indexed page, and the degenerate inputs are refused rather
    # than silently producing a wrong window.
    if page < 1 or per_page < 1:
        raise ValueError(f"page and per_page must be >= 1, got page={page} per_page={per_page}")

    start = (page - 1) * per_page
    return rows[start:start + per_page]


class SettingsError(Exception):
    """Raised when settings exist but cannot be used."""


def load_settings(path):
    """Return the parsed settings. A missing file means defaults; a broken file is an error."""
    # GEN-02: "not configured" and "misconfigured" stay distinguishable. Only the first is benign,
    # and the failure that is swallowed is swallowed on purpose, with the reason stated.
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        log.info("no settings at %s, using defaults", path)
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        raise SettingsError(f"settings at {path} are unreadable: {exc}") from exc


def export_invoices(path, invoices):
    """Write invoices to a CSV, returning the number written."""
    # GEN-03: the context manager owns the handle, so no return path -- including the raise -- can
    # leave it open or unflushed.
    written = 0
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        for invoice in invoices:
            if invoice.get("total") is None:
                raise ValueError(f"invoice {invoice.get('id')!r} has no total")
            writer.writerow([invoice["id"], invoice["total"]])
            written += 1
    return written


class RateCache:
    """GEN-04: the cache owns its lock, so every read and write goes through it."""

    def __init__(self, fetch):
        self._fetch = fetch
        self._lock = threading.Lock()
        self._rates = {}

    def rate(self, currency):
        # The lock guards the dict, not the network call. Holding it across _fetch would serialise
        # every reader behind one request, and a hung fetch would block the lot indefinitely.
        with self._lock:
            if currency in self._rates:
                return self._rates[currency]

        value = self._fetch(currency)

        # Two threads racing on a cold cache may both fetch; setdefault makes the first writer win
        # so they still agree on the result. A duplicate request is cheaper than a stalled pool.
        with self._lock:
            return self._rates.setdefault(currency, value)

    def start_refresh(self, currencies):
        threads = [
            threading.Thread(target=self.rate, args=(currency,), daemon=True)
            for currency in currencies
        ]
        for thread in threads:
            thread.start()
        return threads


def overdue_invoices(invoices):
    """Return a list of overdue invoices. Always returns a list, never None."""
    # GEN-05: the empty case returns the type the contract and every caller expect.
    if not invoices:
        return []
    return [i for i in invoices if i.get("days_late", 0) > 0]


def _processing_fee(subtotal):
    """GEN-06: the fee rule lives in one place, so the two callers below cannot drift apart."""
    return subtotal * PROCESSING_RATE + PROCESSING_FLAT_PENCE


def _subtotal(invoice):
    return sum(line["amount"] for line in invoice["lines"])


def invoice_total(invoice):
    subtotal = _subtotal(invoice)
    return subtotal + _processing_fee(subtotal) + subtotal * TAX_RATE


def statement_total(invoice):
    return invoice_total(invoice)


def shipping_band(weight_grams):
    """Return the shipping band for a parcel weight.

    GEN-07: the boundary that needed thinking about is refused explicitly, and
    tests/fixtures/general/test_shipping_band.py pins 0, -1, 999, 1000, 19999 and 20000.
    """
    if weight_grams <= 0:
        raise ValueError(f"weight must be positive, got {weight_grams}")
    if weight_grams < 1000:
        return "light"
    if weight_grams < 20000:
        return "standard"
    return "freight"
