"""Differential tests: vulnerable.py and clean.py must disagree on every input a VULN comment
names, so an edit that quietly neutralises a plant fails this instead of just passing py_compile.

All seven rows are covered. The two that needed care:

  GEN-03  counting descriptors proves nothing under CPython -- refcounting closes the handle at
          frame teardown, before the caller can look. The test holds a reference instead, which
          takes refcounting out of the picture and asks whether the *code* closes the handle.
  GEN-04  the race is forced deterministic with a threading.Barrier inside the fetch stub: both
          threads are held until both have passed the cache check, so the interleaving under test
          happens every run instead of occasionally. A sleep here would have been flaky; a barrier
          is not.

Deliberately framework-free so it runs anywhere: `python3 tests/fixtures/general/test_differential.py`.
"""

import sys
import tempfile
import threading
from pathlib import Path

# Set before the fixture imports below. Python invalidates cached bytecode on (mtime, size), and an
# edit that changes neither -- `+ 25` to `+ 30`, say -- within the same second is invisible to that
# check, so a stale .pyc silently answers for the source. Refusing to write bytecode at all removes
# the hazard, and keeps the fixture directories free of droppings.
sys.dont_write_bytecode = True

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


def test_gen03_export_leaks_handle_on_early_return():
    """Does the code close the handle, or is it relying on the interpreter to do it?

    Counting /proc/self/fd around the call cannot answer that: CPython's refcounting closes the
    handle the instant the frame is torn down, so the descriptor is already back by the time the
    caller looks -- which is exactly the caveat vulnerable.py's own comment concedes.

    Holding a reference to the handle removes refcounting from the picture. What is left is the
    question that matters: on the early-return path, vulnerable.py never calls close(), while
    clean.py's `with` block closes on every path including the raise.
    """
    captured = []
    real_open = open

    def recording_open(*args, **kwargs):
        handle = real_open(*args, **kwargs)
        captured.append(handle)
        return handle

    rows = [{"id": 1, "total": 10}, {"id": 2, "total": None}]

    with tempfile.TemporaryDirectory() as tmp:
        target = str(Path(tmp) / "out.csv")

        vulnerable.open = recording_open
        try:
            vulnerable.export_invoices(target, rows)
        finally:
            del vulnerable.open
        assert captured, "export_invoices did not open the target at all"
        assert not captured[-1].closed, (
            "vulnerable.export_invoices closed its handle on the early-return path "
            "-- GEN-03 no longer fires"
        )
        captured[-1].close()

        captured.clear()
        clean.open = recording_open
        try:
            clean.export_invoices(target, rows)
        except ValueError:
            pass  # clean.py raises rather than returning early; the handle must still be closed
        finally:
            del clean.open
        assert captured, "clean.export_invoices did not open the target at all"
        assert captured[-1].closed, (
            "clean.export_invoices left a handle open -- its `with` block should close on the "
            "raise path too"
        )


def _both_inside_fetch(call_cached_rate, reset):
    """Run two threads through a cache and report whether both were inside fetch at the same time.

    The barrier is the instrument, not just a synchroniser: it only releases when two parties reach
    it, so a successful wait *is* the proof that both threads passed the cache check before either
    stored a result. Counting fetch calls cannot show that -- a serialised path where the first
    fetch fails and the second retries also reaches two calls, which is exactly how a lock-guarded
    version slipped past an earlier version of this test.
    """
    barrier = threading.Barrier(2)
    concurrent = []
    guard = threading.Lock()

    def fetch(currency):
        try:
            barrier.wait(timeout=2)
            with guard:
                concurrent.append(True)
        except threading.BrokenBarrierError:
            pass  # the other thread never arrived: these fetches were serialised
        return object()

    reset()
    results = {}

    def worker(name):
        try:
            results[name] = call_cached_rate(fetch)
        except Exception:  # a broken barrier must not mask the assertion below
            pass

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    return len(concurrent) == 2, results


def test_gen04_unlocked_cache_allows_concurrent_fetch():
    """The check-then-act window: both threads see a cold cache and both fetch, concurrently."""
    both, _ = _both_inside_fetch(
        lambda fetch: vulnerable.cached_rate("USD", fetch),
        vulnerable._rate_cache.clear,
    )
    assert both, (
        "the two threads did not overlap inside fetch -- the check-then-act window is closed "
        "and GEN-04 no longer fires"
    )
    vulnerable._rate_cache.clear()

def test_gen04_clean_cache_converges_despite_double_fetch():
    """clean.py deliberately allows a duplicate fetch rather than holding its lock across the
    network call, and says so. The property it does guarantee is that both racers end up with the
    same object -- setdefault makes the first writer win. That is what the vulnerable version,
    whose last writer wins, cannot promise."""
    cache = clean.RateCache(lambda currency: object())
    both, results = _both_inside_fetch(lambda fetch: clean.RateCache(fetch).rate("USD"),
                                       lambda: None)
    del cache, both  # the clean version's concurrency is not the assertion here

    shared = clean.RateCache(lambda currency: object())
    out = {}

    def worker(name):
        out[name] = shared.rate("USD")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert len(set(id(v) for v in out.values())) == 1, (
        "clean RateCache handed different objects to concurrent callers -- setdefault should make "
        "the first writer win for everyone"
    )


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
    test_gen03_export_leaks_handle_on_early_return()
    test_gen04_unlocked_cache_allows_concurrent_fetch()
    test_gen04_clean_cache_converges_despite_double_fetch()
    test_gen05_overdue_invoices_empty()
    test_gen06_fee_rule_drift()
    test_gen07_shipping_band_boundary()
    print("differential tests passed: vulnerable.py and clean.py disagree where they should")
