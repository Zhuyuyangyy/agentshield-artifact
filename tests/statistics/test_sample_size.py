"""Pin the sample-size and stratification results quoted in the paper."""

import json
from pathlib import Path

RESULT = (Path(__file__).resolve().parents[2]
          / "experiments" / "statistics" / "results" / "sample_size.json")


def _load():
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_census_and_prefix_are_the_expected_grids():
    data = _load()
    assert data["census"]["n"] == 629
    assert data["census"]["suites"] == {
        "banking": 144, "slack": 105, "travel": 140, "workspace": 240}
    assert data["prefix"]["suites"] == {
        "banking": 144, "slack": 105, "travel": 140, "workspace": 11}


def test_four_hundred_cell_prefix_reverses_the_census_order():
    data = _load()
    entry = data["sizes"]["400"]
    assert entry["prefix"]["gap_tool_minus_pi_pp"] == 4.25
    assert entry["prefix"]["reversal"] is True
    assert entry["uniform"]["gap_tool_minus_pi"]["mean_pp"] == -1.095
    assert entry["stratified_prefix"]["gap_tool_minus_pi"]["mean_pp"] == 4.45
    assert entry["stratified_prefix"]["gap_tool_minus_pi"]["reversal_rate"] == 1.0


def test_full_sample_has_no_reversal_under_any_mechanism():
    data = _load()
    entry = data["sizes"]["629"]
    assert entry["prefix"]["gap_tool_minus_pi_pp"] == -1.113
    assert entry["uniform"]["gap_tool_minus_pi"]["mean_pp"] == -1.113
    assert entry["stratified_census"]["gap_tool_minus_pi"]["mean_pp"] == -1.113
    assert entry["stratified_prefix"]["gap_tool_minus_pi"]["mean_pp"] == -1.113
