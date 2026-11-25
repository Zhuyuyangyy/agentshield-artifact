"""Exact McNemar power and minimum detectable effect (EXP-03).

The benign comparison has 97 units. This script asks what net difference the
paired design could detect at 80 percent power, and how that depends on the
discordance rate q = p01 + p10. It uses the exact two-sided McNemar rejection
region, not a normal approximation.

Definitions
-----------
For n pairs, m discordant pairs, and net difference d = p01 - p10, the
conditional rejection probability is computed from Bin(m, (1 + d/q)/2) against
the exact two-sided region of Bin(m, 0.5). The unconditional power mixes over
m ~ Bin(n, q).

Outputs
-------
experiments/statistics/results/power.json
experiments/statistics/POWER.md

Run:
    python experiments/statistics/power.py
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Dict, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "experiments" / "statistics" / "results" / "power.json"
MD = ROOT / "experiments" / "statistics" / "POWER.md"

ALPHA = 0.05
TARGET_POWER = 0.80
SIZES = (20, 40, 60, 80, 97, 150, 200)
DISCORDANCE = (0.05, 0.10, 0.20, 0.30, 0.50)
HISTORICAL = (8.03, 8.97, 12.95)


def _pmf(k: int, n: int, p: float) -> float:
    return math.comb(n, k) * (p ** k) * ((1.0 - p) ** (n - k))


def _rejection_region(m: int, alpha: float = ALPHA) -> Tuple[int, int]:
    """Exact two-sided McNemar region; (-1, m+1) means no rejection.

    ``low`` is the largest k with P(B <= k) <= alpha/2 and ``high`` the smallest
    k with P(B >= k) <= alpha/2. If either tail cannot reach alpha/2, or the two
    regions overlap, the exact test has no rejection region at this m.
    """
    low = None
    for k in range(m + 1):
        if sum(_pmf(i, m, 0.5) for i in range(k + 1)) <= alpha / 2:
            low = k
    high = None
    for k in range(m, -1, -1):
        if sum(_pmf(i, m, 0.5) for i in range(k, m + 1)) <= alpha / 2:
            high = k
    if low is None or high is None or low >= high:
        return -1, m + 1
    return low, high


def _power(n: int, q: float, d: float,
           regions: Dict[int, Tuple[int, int]]) -> float:
    if q <= 0:
        return 0.0
    p = (1.0 + d / q) / 2.0
    total = 0.0
    for m in range(n + 1):
        weight = _pmf(m, n, q)
        if weight == 0.0:
            continue
        low, high = regions[m]
        if low < 0:
            continue
        reject = (sum(_pmf(b, m, p) for b in range(low + 1))
                  + sum(_pmf(b, m, p) for b in range(high, m + 1)))
        total += weight * reject
    return total


def _mde(n: int, q: float, regions: Dict[int, Tuple[int, int]]) -> Optional[float]:
    """Smallest d with power >= target, by bisection on the monotone power curve."""
    if q == 0:
        return None
    if _power(n, q, q, regions) < TARGET_POWER:
        return None
    low, high = 0.0, q
    for _ in range(24):
        mid = (low + high) / 2.0
        if _power(n, q, mid, regions) >= TARGET_POWER:
            high = mid
        else:
            low = mid
    return round(100.0 * high, 2)


def main() -> int:
    grid: Dict[str, Dict[str, Optional[float]]] = {}
    for n in SIZES:
        regions = {m: _rejection_region(m) for m in range(n + 1)}
        grid[str(n)] = {"q": {}, "regions": regions}
        for q in DISCORDANCE:
            grid[str(n)]["q"][f"{q:.2f}"] = _mde(n, q, regions)

    # The observed benign contrast: 3 discordant traces, all one direction.
    observed_q = 3.0 / 97.0
    regions97 = grid["97"]["regions"]
    observed_power = _power(97, observed_q, observed_q, regions97)
    minimum_p = 2.0 * (0.5 ** 3)

    # Nearest discordance for each historical MDE value, keeping the same
    # alpha and power target. This is a reconciliation aid, not a claim that
    # the historical runs used this grid.
    nearest = {}
    for value in HISTORICAL:
        best_q, best_gap = None, None
        for i in range(1, 100):
            q = i / 200.0
            mde = _mde(97, q, regions97)
            if mde is None:
                continue
            gap = abs(mde - value)
            if best_gap is None or gap < best_gap:
                best_q, best_gap = q, gap
        nearest[str(value)] = {"q": best_q, "gap_pp": round(best_gap, 2)}

    # Strip the private rejection regions before serialising.
    public_grid = {
        n: {q: value for q, value in entry["q"].items()}
        for n, entry in grid.items()
    }
    result = {
        "experiment": "EXP-03 exact McNemar power",
        "method": {
            "alpha": ALPHA,
            "target_power": TARGET_POWER,
            "test": "two-sided exact McNemar",
            "power": "mixture over discordant count m ~ Bin(n, q)",
            "mde_units": "percentage points of net difference d",
        },
        "grid": public_grid,
        "observed_benign": {
            "n": 97,
            "discordant": 3,
            "q": round(observed_q, 6),
            "d_pp": round(100.0 * observed_q, 3),
            "power_at_observed_effect": round(observed_power, 3),
            "minimum_two_sided_p": minimum_p,
            "note": (
                "With three discordant pairs the smallest attainable two-sided "
                "p is 0.25, so the exact test cannot reject at 0.05 regardless "
                "of direction."
            ),
        },
        "historical_reconciliation": {
            "values_pp": list(HISTORICAL),
            "nearest": nearest,
            "note": (
                "The historical q grid is not recorded. Nearest values use the "
                "same alpha and power target; differences up to the step size "
                "are expected."
            ),
        },
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=1), encoding="utf-8")

    lines = [
        "# EXP-03 — Exact McNemar power",
        "",
        "Exact two-sided McNemar, alpha 0.05, target power 0.80. MDE is the net",
        "difference d = p01 - p10 in percentage points, as a function of the",
        "discordance rate q = p01 + p10.",
        "",
        "| n | " + " | ".join(f"q={q:.2f}" for q in DISCORDANCE) + " |",
        "|---|" + "---|" * len(DISCORDANCE),
    ]
    for n in SIZES:
        values = [public_grid[str(n)][f"{q:.2f}"] for q in DISCORDANCE]
        lines.append(f"| {n} | " + " | ".join(
            "—" if v is None else f"{v:.2f}" for v in values) + " |")
    lines += [
        "",
        f"Observed benign contrast: 3 discordant pairs, q = d = 3/97 = "
        f"{100 * observed_q:.2f} pp; exact power = {observed_power:.3f}; "
        f"smallest attainable two-sided p = {minimum_p:.2f}.",
        "",
        "The design cannot reject at 0.05 with three discordant pairs. This is",
        "a resolution statement, not evidence of equivalence.",
        "",
        "Historical reconciliation: " + ", ".join(
            f"{v} pp nearest q={nearest[str(v)]['q']:.3f}"
            for v in HISTORICAL) + ".",
        "",
        "Reproduce: `python experiments/statistics/power.py`",
    ]
    MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT).as_posix()} and {MD.relative_to(ROOT).as_posix()}")
    print(f"observed power {observed_power:.3f}; minimum p {minimum_p:.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
