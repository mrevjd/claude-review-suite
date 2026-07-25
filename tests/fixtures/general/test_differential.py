"""Differential tests: vulnerable.py and clean.py must disagree on every input a VULN comment
names, so an edit that quietly neutralises a plant fails this instead of just passing py_compile.

Two planted rows are deliberately not covered here: GEN-03 (a leaked file handle needs OS-level fd
introspection to assert portably) and GEN-04 (the race needs contention to show, and asserting it
deterministically would make this suite flaky, not more correct).

Deliberately framework-free so it runs anywhere: `python3 tests/fixtures/general/test_differential.py`.
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import clean  # noqa: E402
import vulnerable  # noqa: E402


def test_gen01_page_of():
    rows = [f"r{i}" for i in range(7)]
    vuln = vulnerable.page_of(rows, 1, 3)
    good = clean.page_of(rows, 1, 3)
    assert vuln == ["r3", "r4", "r5", "r6"], f"vulnerable.page_of drifted: {vuln!r}"
    assert good == ["r0", "r1", "r2"], f"clean.page_of drifted: {good!r}"
    assert vuln != good


def test_gen02_load_settings_malformed():
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        handle.write("{not valid json")
        path = handle.name
    try:
        assert vulnerable.load_settings(path) == {}, "vulnerable.load_settings should swallow the error"
        try:
            clean.load_settings(path)
            raise AssertionError("clean.load_settings should raise SettingsError on malformed JSON")
        except clean.SettingsError:
            pass
    finally:
        Path(path).unlink()


def test_gen05_overdue_invoices_empty():
    assert vulnerable.overdue_invoices([]) is None, "vulnerable.overdue_invoices([]) drifted from None"
    assert clean.overdue_invoices([]) == [], "clean.overdue_invoices([]) drifted from []"


def test_gen06_fee_rule_drift():
    invoice = {"lines": [{"amount": 1000}]}
    assert vulnerable.invoice_total(invoice) != vulnerable.statement_total(invoice), (
        "vulnerable's two fee rules converged -- GEN-06 needs them to disagree"
    )
    assert clean.invoice_total(invoice) == clean.statement_total(invoice), (
        "clean's two fee rules should be the same rule, called twice"
    )


def test_gen07_shipping_band_boundary():
    assert vulnerable.shipping_band(0) == "light", "vulnerable.shipping_band(0) drifted"
    try:
        clean.shipping_band(0)
        raise AssertionError("clean.shipping_band(0) should raise ValueError")
    except ValueError:
        pass


if __name__ == "__main__":
    test_gen01_page_of()
    test_gen02_load_settings_malformed()
    test_gen05_overdue_invoices_empty()
    test_gen06_fee_rule_drift()
    test_gen07_shipping_band_boundary()
    print("differential tests passed: vulnerable.py and clean.py disagree where they should")
