"""Pin the T02 REVIEW-semantics bounds."""

import json
from pathlib import Path

RESULT = (Path(__file__).resolve().parents[2]
          / "experiments" / "identifiability" / "results" / "review_bounds.json")


def _load():
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_resolution_stays_inside_the_endpoints():
    from experiments.identifiability.review_bounds import _resolved, _trace_blocked

    sequence = ("REVIEW", "ALLOW")
    assert _trace_blocked(sequence, "log_and_allow") is False
    assert _trace_blocked(sequence, "block") is True
    assert _resolved(sequence, (False,)) is False
    assert _resolved(sequence, (True,)) is True


def test_exhaustive_checks_pass():
    data = _load()
    per_sequence = data["checks"]["per_sequence"]
    assert per_sequence["sequences"] == 1092
    assert per_sequence["all_inside"] is True
    assert per_sequence["all_sharp"] is True
    aggregate = data["checks"]["aggregate"]
    assert aggregate["log_count"] == 5
    assert aggregate["block_count"] == 8
    assert aggregate["full_integer_range"] is True


def test_attack_width_is_rule_invariant():
    data = _load()
    rules = data["empirical"]["attack"]["rules"]
    assert {item["review_only"] for item in rules.values()} == {462}
    assert {round(item["width_pp"], 2) for item in rules.values()} == {4.43}


def test_benign_widths_by_rule():
    data = _load()
    rules = data["empirical"]["benign"]["rules"]
    assert rules["no_relaxation"]["review_only"] == 9
    assert rules["global_cap"]["review_only"] == 11
    assert rules["band_split"]["review_only"] == 12
    assert rules["hard_first"]["review_only"] == 9
    assert round(rules["band_split"]["width_pp"], 2) == 12.37
    assert round(rules["hard_first"]["width_pp"], 2) == 9.28
