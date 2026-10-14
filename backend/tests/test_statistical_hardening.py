"""Tests for the P3 statistical-hardening harness.

These pin the estimator that the pre-registration fixes: the percentile index
rule, the frozen benign-then-attack draw order, the exact McNemar p-value, the
re-banding boundary, and the paired-difference sign. They need neither the dump
nor an engine.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for path in (str(ROOT), str(ROOT / "backend")):
    if path not in sys.path:
        sys.path.insert(0, path)

from benchmark.statistical_hardening import (  # noqa: E402
    METRIC_NAMES,
    _endpoints,
    _fingerprint,
    _percentile_rank,
    cluster_ci_frozen,
    mcnemar_exact,
    paired_ci,
    rebinned_decision,
)


def _reference_cluster_ci(ben, atk, iterations, seed):
    """A literal transcription of the frozen _cluster_bootstrap_ci loop.

    Written out here so the harness routine is compared against the frozen
    estimator rather than against itself.
    """
    rng = random.Random(seed)
    nb, na = len(ben["block"]), len(atk["block"])
    est = {name: [] for name in METRIC_NAMES.values()}
    for _ in range(iterations):
        bidx = [rng.randrange(nb) for _ in range(nb)]
        aidx = [rng.randrange(na) for _ in range(na)]
        b_out = [ben["block"][i] for i in bidx]
        a_out = [atk["block"][i] for i in aidx]
        if b_out:
            est["benign_trace_block_rate"].append(sum(b_out) / len(b_out))
            est["benign_trace_intervention_rate"].append(
                sum(ben["intervene"][i] for i in bidx) / len(bidx)
            )
        if a_out:
            est["attack_trace_block_rate"].append(sum(a_out) / len(a_out))
            est["attack_trace_detection_rate"].append(
                sum(atk["intervene"][i] for i in aidx) / len(aidx)
            )
    return {name: (_endpoints(v) if v else None) for name, v in est.items()}


def test_endpoints_uses_frozen_index_rule():
    # int(0.025*(n-1)) and int(0.975*(n-1)), no interpolation.
    values = list(range(1000))
    lo, hi = _endpoints(values)
    assert lo == round(values[int(0.025 * 999)], 5)
    assert hi == round(values[int(0.975 * 999)], 5)
    assert lo <= hi


def test_endpoints_single_value_is_degenerate():
    assert _endpoints([0.25]) == [0.25, 0.25]


def test_cluster_ci_matches_frozen_estimator_stream():
    ben = {
        "block": [0, 1, 0, 0, 1, 0, 0, 0],
        "intervene": [1, 1, 0, 1, 1, 0, 1, 0],
    }
    atk = {
        "block": [0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0],
        "intervene": [1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1],
    }
    got = cluster_ci_frozen(ben, atk, iterations=250, seed=12345)
    want = _reference_cluster_ci(ben, atk, iterations=250, seed=12345)
    assert got == want


def test_cluster_ci_is_seed_deterministic():
    ben = {"block": [0, 1, 0], "intervene": [1, 1, 0]}
    atk = {"block": [0, 1, 1], "intervene": [1, 1, 0]}
    assert cluster_ci_frozen(ben, atk, iterations=100, seed=7) == \
        cluster_ci_frozen(ben, atk, iterations=100, seed=7)


def test_mcnemar_exact_known_values():
    assert mcnemar_exact(0, 0) == 1.0
    # 2 * 0.5^1 = 1.0
    assert mcnemar_exact(1, 0) == 1.0
    # 2 * 0.5^5 = 0.0625
    assert mcnemar_exact(5, 0) == 0.0625
    # symmetric in b and c
    assert mcnemar_exact(9, 2) == mcnemar_exact(2, 9)
    # a balanced table is not evidence against the null
    assert mcnemar_exact(3, 3) == 1.0


def test_rebinned_decision_boundaries_are_inclusive():
    assert rebinned_decision(0.90) == "block"
    assert rebinned_decision(0.95) == "block"
    assert rebinned_decision(0.8999) == "review"
    assert rebinned_decision(0.60) == "review"
    assert rebinned_decision(0.5999) == "allow"
    assert rebinned_decision(0.0) == "allow"


def test_paired_ci_sign_and_degenerate_case():
    a = [0] * 20
    b = [1] * 20
    ci = paired_ci({"m": (a, b)}, iterations=50, seed=1)
    # B - A is +1.0 everywhere, so the interval collapses on +1.0.
    assert ci["m"] == [1.0, 1.0]

    ci_rev = paired_ci({"m": (b, a)}, iterations=50, seed=1)
    assert ci_rev["m"] == [-1.0, -1.0]


def test_paired_ci_zero_when_arms_are_identical():
    a = [0, 1, 1, 0, 1, 0]
    ci = paired_ci({"m": (a, list(a))}, iterations=50, seed=3)
    assert ci["m"] == [0.0, 0.0]


def test_percentile_rank_bounds():
    values = [0.0, 0.1, 0.2, 0.3]
    assert _percentile_rank(values, -1.0) == 0.0
    assert _percentile_rank(values, 1.0) == 1.0
    assert _percentile_rank(values, 0.2) == 0.75


def test_fingerprint_is_order_sensitive():
    assert _fingerprint([0, 1, 1]) == _fingerprint([0, 1, 1])
    assert _fingerprint([0, 1, 1]) != _fingerprint([1, 1, 0])