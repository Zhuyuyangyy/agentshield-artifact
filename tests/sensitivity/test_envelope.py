"""Pin the T03 design-envelope results."""

import json
from pathlib import Path

RESULT = (Path(__file__).resolve().parents[2]
          / "experiments" / "sensitivity" / "results" / "envelope.json")


def _load():
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_design_sets_are_finite_and_declared():
    data = _load()
    assert data["design_sets"]["study1"]["configurations"] == 16
    assert data["design_sets"]["study1"]["benign_distinct_values"] == 8
    assert data["design_sets"]["study2"]["configurations"] == 15
    assert data["design_sets"]["study2"]["frames"] == [
        "census", "prefix_400", "banking"]


def test_study1_attack_envelopes():
    data = _load()
    envelopes = data["study1"]["attack_trace_block_rate"]["envelopes"]
    assert envelopes["no_relaxation"]["width_pp"] == 6.074
    assert envelopes["global_cap"]["width_pp"] == 4.426
    assert envelopes["band_split"]["width_pp"] == 4.425
    assert envelopes["hard_first"]["width_pp"] == 4.425


def test_study1_between_system_signs():
    data = _load()
    differences = data["study1"]["attack_trace_block_rate"]["between_system"]
    tie = differences["band_split_minus_hard_first"]
    assert tie["min"]["difference_pp"] == 0
    assert tie["max"]["difference_pp"] == 0
    assert tie["sign"] == "tie"
    contrast = differences["global_cap_minus_band_split"]
    assert contrast["sign"] == "nonpositive"
    assert contrast["min"]["difference_pp"] == -0.135
    assert contrast["max"]["difference_pp"] == 0


def test_study2_only_the_top_two_pair_reverses():
    data = _load()
    study2 = data["study2"]
    assert len(study2["envelopes"]) == 5
    assert study2["sign_changes"] == ["tool_filter_minus_pi_detector"]
    assert study2["envelopes"]["none"]["width_pp"] == 14.805
    assert study2["envelopes"]["tool_filter"]["width_pp"] == 4.275
    assert study2["envelopes"]["pi_detector"]["width_pp"] == 7.255


def test_design_effect_exceeds_the_between_system_contrast():
    data = _load()
    ratio = data["licensing"]["design_to_difference_ratio"]
    assert ratio["single_system_width_pp"] == 4.4257
    assert ratio["between_system_span_pp"] == 0.1341
    assert ratio["ratio"] == 33.0
    exact = ratio["exact"]
    assert exact["denominator"] == 10439
    assert exact["band_split"]["width_numerator"] == 462
    assert exact["band_minus_global"]["span_numerator"] == 14
