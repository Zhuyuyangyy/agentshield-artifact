"""Pin the T04 minimum reversal distance results."""

import json
from pathlib import Path

RESULT = (Path(__file__).resolve().parents[2]
          / "experiments" / "sensitivity" / "results" / "reversal_distance.json")


def _load():
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_census_and_prefix_gaps():
    data = _load()
    assert data["population"]["n"] == 629
    assert data["census"]["gap_pp"] == -1.112878
    assert data["constructed_prefix"]["counts"] == {
        "banking": 144, "slack": 105, "travel": 140, "workspace": 11}
    assert round(data["constructed_prefix"]["gap_pp"], 4) == 4.4521
    assert round(data["constructed_prefix"]["distance_l1"], 4) == 0.7081


def test_minimum_composition_is_reversing_and_closest():
    data = _load()
    best = data["minimum_reversing_composition"]
    suite_cells = {suite: item["cells"]
                   for suite, item in data["population"]["suites"].items()}
    assert sum(best["counts"].values()) == 400
    assert all(best["counts"][suite] <= suite_cells[suite] for suite in best["counts"])
    assert best["definition"].startswith("crossing")
    assert best["gap_pp"] > 0
    assert round(best["distance_l1"], 4) == 0.1071
    assert best["ties"] == 1
    tie = data["minimum_tie_composition"]
    strict = data["minimum_strict_reversal_composition"]
    assert tie["gap_pp"] == 0
    assert round(tie["distance_l1"], 6) == 0.121979
    assert strict["gap_pp"] > 0
    assert strict["distance_l1"] == best["distance_l1"]
    assert data["enumeration"]["complete"] is True
    assert data["enumeration"]["compositions"] == 1501380
    assert data["continuous_lower_bound"]["distance_l1"] < best["distance_l1"]
    assert data["admissible_set"]["reversing"] == 315610
    assert data["admissible_set"]["zero_gap"] == 26


def test_prefix_family_boundary_straddles_zero():
    data = _load()
    family = data["prefix_family"]
    assert family["reversing"] == 564
    assert family["preserving"] == 65
    assert family["largest_reversing"]["n"] == 564
    assert family["smallest_preserving"]["n"] == 565
    assert family["largest_reversing"]["gap_pp"] >= 0
    assert family["smallest_preserving"]["gap_pp"] < 0
    assert family["largest_reversing"]["counts"]["workspace"] == 175
    assert family["minimum_distance_over_prefixes"]["n"] == 564


def test_context_frames_keep_or_break_the_order_as_reported():
    data = _load()
    frames = data["context_frames"]
    assert frames["user_task_weights"]["reversal"] is False
    assert frames["uniform_suites"]["reversal"] is True
    assert frames["census_quota_400"]["gap_pp"] < 0
    assert len(data["not_claimed"]) == 4
