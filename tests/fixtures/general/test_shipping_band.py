"""Boundary tests for clean.py's shipping_band -- the GEN-07 counterpart.

Deliberately framework-free so it runs anywhere: `python3 tests/fixtures/general/test_shipping_band.py`.
Pins the cases a reviewer would otherwise have to reason about by hand.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from clean import shipping_band  # noqa: E402


def test_rejects_non_positive():
    for weight in (0, -1, -1000):
        try:
            shipping_band(weight)
        except ValueError:
            continue
        raise AssertionError(f"shipping_band({weight}) should have raised ValueError")


def test_band_boundaries():
    cases = {
        1: "light",
        999: "light",
        1000: "standard",
        19999: "standard",
        20000: "freight",
        50000: "freight",
    }
    for weight, expected in cases.items():
        actual = shipping_band(weight)
        assert actual == expected, f"shipping_band({weight}) == {actual!r}, expected {expected!r}"


if __name__ == "__main__":
    test_rejects_non_positive()
    test_band_boundaries()
    print("shipping_band boundary tests passed")
