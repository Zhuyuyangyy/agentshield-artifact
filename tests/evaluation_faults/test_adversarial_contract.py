"""Adversarial contract cases requested by the second and fourth audits.

Each case is a deterministic dictionary-level test: no model call, no network.
The fourth-round cases pin the boundary conditions of typed claims: unknown or
missing types, malformed intervals, unit and denominator mismatches, overlapping
partial-identification intervals, and counterfactual files whose hash is valid
but whose content does not support the claim.
"""

import copy
import hashlib
import json
import math
from pathlib import Path

from tools.gate_audit import core
from tools.gate_audit.schema import validate_report

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "tools" / "gate_audit" / "examples"


def _base():
    return json.loads((EXAMPLES / "report_band_block.json").read_text(
        encoding="utf-8"))


def _causal_claim():
    return {
        "claim": "The gate caused the improvement",
        "claim_type": "causal",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
        "expected_effect": "positive",
    }


def _counterfactual_document(report, **overrides):
    document = {
        "system": report["system"],
        "benchmark": report["benchmark"],
        "metric": "attack_trace_block_rate",
        "unit": "trace",
        "n": 10439,
        "estimate_pp": 0.42,
        "design": {"treatment": "gate_on", "control": "gate_off"},
    }
    document.update(overrides)
    return document


def _attach_counterfactual(tmp_path, report, document):
    path = tmp_path / "counterfactual.json"
    path.write_text(json.dumps(document) + "\n", encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    report["design"]["attribution_source"] = "gate_side"
    report["evidence"] = {
        "attribution_coverage": 1.0,
        "counterfactual": {
            "source": "counterfactual.json",
            "sha256": digest,
            "scientific_values_preserved": True,
        },
    }


def test_two_mechanisms_under_one_protocol_are_a_mechanism_comparison():
    left = _base()
    right = copy.deepcopy(left)
    right["system"] = "hard_first"
    result = core.compare(left, right)
    assert result["comparison_type"] == "mechanism"
    assert result["licensed"] is True


def test_same_mechanism_only_semantics_is_design_sensitivity():
    left = _base()
    right = copy.deepcopy(left)
    right["design"]["enforcement_semantics"] = "log_and_allow"
    result = core.compare(left, right)
    assert result["comparison_type"] == "design_sensitivity"
    assert result["licensed"] is True


def test_different_coverage_same_asr_is_descriptive_only():
    left = _base()
    left["metrics"] = {"end_to_end_asr": 0.2}
    left["uncertainty"] = {
        "end_to_end_asr": {"unit": "cell", "method": "paired bootstrap",
                           "ci95": [0.15, 0.25]}}
    left["evidence"] = {"attribution_coverage": 0.2}
    right = copy.deepcopy(left)
    right["evidence"] = {"attribution_coverage": 0.9}
    result = core.compare(left, right)
    assert result["comparison_type"] == "descriptive"
    assert result["licensed"] is True


def test_unknown_review_semantics_cannot_support_a_point_block_rate():
    report = _base()
    report["design"]["enforcement_semantics"] = "unknown"
    assert validate_report(report) == []
    result = core.claims(report, [{
        "claim": "The gate blocks 7.51 percent of attacks",
        "claim_type": "point",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
    }])
    assert result["passed"] is False
    assert any("bound" in error for error in result["results"][0]["errors"])


def test_intervention_support_is_not_causal_attribution():
    report = _base()
    report["design"]["attribution_source"] = "gate_side"
    report["evidence"] = {
        "attribution_coverage": 0.7125,
        "concordant_intervention_flips": 6,
        "flips": 15,
    }
    result = core.claims(report, [{
        "claim": "The gate caused six of the fifteen security flips",
        "claim_type": "descriptive",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
    }])
    assert result["passed"] is False
    assert any("causal" in error for error in result["results"][0]["errors"])


def test_full_intervention_coverage_is_still_not_a_counterfactual():
    report = _base()
    report["design"]["attribution_source"] = "gate_side"
    report["evidence"] = {"attribution_coverage": 1.0}
    result = core.claims(report, [{
        "claim": "The gate caused the security improvement",
        "claim_type": "causal",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
    }])
    assert result["passed"] is False
    assert any("counterfactual" in error
               for error in result["results"][0]["errors"])


def test_non_significance_is_not_equivalence():
    report = _base()
    report["uncertainty"]["attack_trace_block_rate"]["ci95"] = [0.0702, 0.0801]
    result = core.claims(report, [{
        "claim": "Band split and hard first are equivalent",
        "claim_type": "descriptive",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
    }])
    assert result["passed"] is False
    assert any("equivalence" in error
               for error in result["results"][0]["errors"])


def test_equivalence_without_a_prespecified_margin_is_rejected():
    report = _base()
    result = core.claims(report, [{
        "claim": "The two rates are equivalent",
        "claim_type": "equivalence",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
    }])
    assert result["passed"] is False
    assert any("margin" in error for error in result["results"][0]["errors"])


def test_equivalence_interval_outside_the_margin_is_rejected():
    report = _base()
    report["evidence"] = {"equivalence_margin": 0.01}
    result = core.claims(report, [{
        "claim": "The two rates are equivalent",
        "claim_type": "equivalence",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
        "contrast": {
            "left": report["system"],
            "right": "hard_first",
            "paired": True,
            "difference_ci95": [-0.02, 0.02],
            "equivalence_margin": 0.01,
            "method": "paired bootstrap",
        },
    }])
    assert result["passed"] is False
    assert any("not contained" in error
               for error in result["results"][0]["errors"])


def test_discrete_reversal_claim_cannot_use_a_zero_gap_equality():
    report = _base()
    result = core.claims(report, [{
        "claim": "The minimum reversal distance is zero because the gap equals zero",
        "claim_type": "descriptive",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
    }])
    assert result["passed"] is False
    assert any("crossing" in error for error in result["results"][0]["errors"])


def test_different_benchmark_is_not_a_same_design_comparison():
    left = _base()
    right = copy.deepcopy(left)
    right["benchmark"] = "another_benchmark"
    result = core.compare(left, right)
    assert result["comparison_type"] == "not_comparable"
    assert result["licensed"] is False


def test_mechanism_plus_frame_change_is_not_a_population_comparison():
    left = _base()
    right = copy.deepcopy(left)
    right["system"] = "hard_first"
    right["design"]["sampling_frame"] = "prefix_400"
    result = core.compare(left, right)
    assert result["comparison_type"] == "not_comparable"
    assert result["licensed"] is False


def test_unknown_semantics_allows_only_bounded_comparison():
    left = _base()
    right = copy.deepcopy(left)
    left["design"]["enforcement_semantics"] = "unknown"
    right["design"]["enforcement_semantics"] = "unknown"
    point = core.compare(left, right)
    assert point["comparison_type"] == "interval_only"
    assert point["licensed"] is False
    left["bounds"] = {
        "attack_trace_block_rate": [0.03, 0.08],
        "benign_trace_block_rate": [0.30, 0.52],
    }
    right["bounds"] = {
        "attack_trace_block_rate": [0.03, 0.08],
        "benign_trace_block_rate": [0.30, 0.52],
    }
    bounded = core.compare(left, right)
    assert bounded["comparison_type"] == "interval_comparison"
    assert bounded["licensed"] is True


def test_clause_level_causal_detection_is_not_fooled_by_not_the_model():
    report = _base()
    result = core.claims(report, [{
        "claim": "The gate caused the improvement, not the model",
        "claim_type": "descriptive",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
    }])
    assert result["passed"] is False
    assert any("causal" in error for error in result["results"][0]["errors"])


def test_no_difference_is_detected_as_an_equivalence_claim():
    report = _base()
    result = core.claims(report, [{
        "claim": "There is no difference between the two rules",
        "claim_type": "descriptive",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
    }])
    assert result["passed"] is False
    assert any("equivalence" in error
               for error in result["results"][0]["errors"])


def test_prevents_is_detected_as_causal_wording():
    report = _base()
    result = core.claims(report, [{
        "claim": "The gate prevents attacks",
        "claim_type": "descriptive",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
    }])
    assert result["passed"] is False
    assert any("causal" in error for error in result["results"][0]["errors"])


def test_exactly_is_precise_even_when_the_word_range_appears():
    report = _base()
    report["design"]["enforcement_semantics"] = "unknown"
    result = core.claims(report, [{
        "claim": "The range is exactly 7.51 percent",
        "claim_type": "point",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
    }])
    assert result["passed"] is False
    assert any("point block rate" in error
               for error in result["results"][0]["errors"])


def test_a_boolean_counterfactual_is_not_evidence():
    report = _base()
    report["design"]["attribution_source"] = "gate_side"
    report["evidence"] = {"counterfactual": True,
                          "attribution_coverage": 1.0}
    result = core.claims(report, [_causal_claim()])
    assert result["passed"] is False
    assert any("object" in error for error in result["results"][0]["errors"])


def test_a_fabricated_counterfactual_hash_is_rejected(tmp_path):
    report = _base()
    report["design"]["attribution_source"] = "gate_side"
    report["evidence"] = {
        "counterfactual": {
            "source": "counterfactual.json",
            "sha256": "0" * 64,
            "scientific_values_preserved": True,
        },
        "attribution_coverage": 1.0,
    }
    (tmp_path / "counterfactual.json").write_text("{}", encoding="utf-8")
    result = core.claims(report, [_causal_claim()], root=tmp_path)
    assert result["passed"] is False
    assert any("hashes to" in error
               for error in result["results"][0]["errors"])


def test_missing_claim_type_is_rejected():
    report = _base()
    result = core.claims(report, [{
        "claim": "The band split blocks 7.51 percent of attack traces",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
    }])
    assert result["passed"] is False
    assert any("claim_type is required" in error
               for error in result["results"][0]["errors"])


def test_unknown_claim_type_is_rejected():
    report = _base()
    result = core.claims(report, [{
        "claim": "The band split blocks 7.51 percent of attack traces",
        "claim_type": "causalish",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
    }])
    assert result["passed"] is False
    assert any("claim_type must be one of" in error
               for error in result["results"][0]["errors"])


def test_interval_with_lower_bound_above_upper_is_rejected():
    report = _base()
    report["bounds"] = {"attack_trace_block_rate": [0.03, 0.08]}
    result = core.claims(report, [{
        "claim": "The rate lies between 8.0 and 3.0 percent",
        "claim_type": "interval",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "bounds": [0.08, 0.03],
    }])
    assert result["passed"] is False
    assert any("0 <= low <= high <= 1" in error
               for error in result["results"][0]["errors"])


def test_interval_outside_the_metric_range_is_rejected():
    report = _base()
    report["bounds"] = {"attack_trace_block_rate": [0.03, 0.08]}
    result = core.claims(report, [{
        "claim": "The rate lies between 7.0 and 120 percent",
        "claim_type": "interval",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "bounds": [0.07, 1.2],
    }])
    assert result["passed"] is False
    assert any("0 <= low <= high <= 1" in error
               for error in result["results"][0]["errors"])


def test_interval_claim_requires_report_bounds():
    report = _base()
    result = core.claims(report, [{
        "claim": "The rate lies between 3.0 and 7.6 percent",
        "claim_type": "interval",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "bounds": [0.03, 0.076],
    }])
    assert result["passed"] is False
    assert any("requires report.bounds" in error
               for error in result["results"][0]["errors"])


def test_different_units_block_a_direct_comparison():
    left = _base()
    right = copy.deepcopy(left)
    right["uncertainty"]["attack_trace_block_rate"]["unit"] = "cell"
    result = core.compare(left, right)
    assert result["comparison_type"] == "not_comparable"
    assert result["licensed"] is False
    assert any(item["field"] == "unit"
               for item in result["definition_mismatches"])


def test_different_denominators_block_a_direct_comparison():
    left = _base()
    left["uncertainty"]["attack_trace_block_rate"]["denominator"] = (
        "attack traces")
    right = copy.deepcopy(left)
    right["uncertainty"]["attack_trace_block_rate"]["denominator"] = (
        "paired cells")
    result = core.compare(left, right)
    assert result["comparison_type"] == "not_comparable"
    assert result["licensed"] is False
    assert any(item["field"] == "denominator"
               for item in result["definition_mismatches"])


def test_overlapping_partial_intervals_do_not_license_a_strict_ranking():
    left = _base()
    right = copy.deepcopy(left)
    for report in (left, right):
        report["design"]["enforcement_semantics"] = "unknown"
        report["bounds"] = {
            "attack_trace_block_rate": [0.03, 0.08],
            "benign_trace_block_rate": [0.30, 0.52],
        }
    result = core.compare(left, right)
    assert result["comparison_type"] == "interval_comparison"
    assert result["licensed"] is True
    assert result["strict_ranking_licensed"] is False
    assert all(item["intervals_overlap"]
               for item in result["difference_bounds"].values())


def test_disjoint_partial_intervals_license_a_strict_ranking():
    left = _base()
    right = copy.deepcopy(left)
    for report in (left, right):
        report["design"]["enforcement_semantics"] = "unknown"
    left["metrics"] = {
        "attack_trace_block_rate": 0.035,
        "benign_trace_block_rate": 0.32,
    }
    right["metrics"] = {
        "attack_trace_block_rate": 0.055,
        "benign_trace_block_rate": 0.42,
    }
    left["bounds"] = {
        "attack_trace_block_rate": [0.03, 0.04],
        "benign_trace_block_rate": [0.30, 0.35],
    }
    right["bounds"] = {
        "attack_trace_block_rate": [0.05, 0.06],
        "benign_trace_block_rate": [0.40, 0.45],
    }
    result = core.compare(left, right)
    assert result["comparison_type"] == "interval_comparison"
    assert result["strict_ranking_licensed"] is True
    for item in result["difference_bounds"].values():
        assert item["intervals_overlap"] is False
        assert item["strict_ranking"] is True


def test_a_correct_hash_over_unrelated_content_is_not_causal_evidence(
        tmp_path):
    report = _base()
    path = tmp_path / "counterfactual.json"
    path.write_text('{"note": "trust me, the gate caused it"}\n',
                    encoding="utf-8")
    report["design"]["attribution_source"] = "gate_side"
    report["evidence"] = {
        "attribution_coverage": 1.0,
        "counterfactual": {
            "source": "counterfactual.json",
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "scientific_values_preserved": True,
        },
    }
    result = core.claims(report, [_causal_claim()], root=tmp_path)
    assert result["passed"] is False
    assert any("missing required field" in error
               for error in result["results"][0]["errors"])


def test_counterfactual_evidence_from_another_mechanism_is_rejected(tmp_path):
    report = _base()
    document = _counterfactual_document(report, system="another_gate")
    _attach_counterfactual(tmp_path, report, document)
    result = core.claims(report, [_causal_claim()], root=tmp_path)
    assert result["passed"] is False
    assert any("different mechanism" in error
               for error in result["results"][0]["errors"])


def test_counterfactual_evidence_for_another_metric_is_rejected(tmp_path):
    report = _base()
    document = _counterfactual_document(
        report, metric="benign_trace_block_rate")
    _attach_counterfactual(tmp_path, report, document)
    result = core.claims(report, [_causal_claim()], root=tmp_path)
    assert result["passed"] is False
    assert any("different metric" in error
               for error in result["results"][0]["errors"])


def test_counterfactual_evidence_with_a_different_unit_is_rejected(tmp_path):
    report = _base()
    document = _counterfactual_document(report, unit="cell")
    _attach_counterfactual(tmp_path, report, document)
    result = core.claims(report, [_causal_claim()], root=tmp_path)
    assert result["passed"] is False
    assert any("uses unit" in error
               for error in result["results"][0]["errors"])


def test_counterfactual_evidence_without_treatment_and_control_is_rejected(
        tmp_path):
    report = _base()
    document = _counterfactual_document(
        report, design={"treatment": "gate_on"})
    _attach_counterfactual(tmp_path, report, document)
    result = core.claims(report, [_causal_claim()], root=tmp_path)
    assert result["passed"] is False
    assert any("treatment and a control" in error
               for error in result["results"][0]["errors"])


def test_matching_structured_evidence_licenses_a_causal_claim(tmp_path):
    report = _base()
    document = _counterfactual_document(report)
    _attach_counterfactual(tmp_path, report, document)
    result = core.claims(report, [_causal_claim()], root=tmp_path)
    assert result["passed"] is True, result["results"][0]["errors"]
    assert result["contract_valid"] is True
    assert result["causal_validity_established"] is False
    assert result["results"][0]["eligible_for_causal_assessment"] is True


def test_narrowed_interval_must_equal_the_report_bounds():
    report = _base()
    report["bounds"] = {"attack_trace_block_rate": [0.030846, 0.075103]}
    result = core.claims(report, [{
        "claim": "The rate is pinned at 7.51 percent",
        "claim_type": "interval",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "bounds": [0.0751, 0.0751],
    }])
    assert result["passed"] is False
    assert any("must equal report.bounds" in error
               for error in result["results"][0]["errors"])


def test_unknown_semantics_rejects_a_descriptive_block_rate():
    report = _base()
    report["design"]["enforcement_semantics"] = "unknown"
    result = core.claims(report, [{
        "claim": "The gate blocks attacks",
        "claim_type": "descriptive",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
    }])
    assert result["passed"] is False
    assert any("unknown REVIEW" in error
               for error in result["results"][0]["errors"])


def test_nan_claim_value_is_rejected():
    report = _base()
    result = core.claims(report, [{
        "claim": "The rate is 7.51 percent",
        "claim_type": "descriptive",
        "metric": "attack_trace_block_rate",
        "value": math.nan,
        "tolerance": 0.0001,
    }])
    assert result["passed"] is False
    assert any("finite number" in error
               for error in result["results"][0]["errors"])


def test_excessive_tolerance_is_rejected():
    report = _base()
    result = core.claims(report, [{
        "claim": "The rate is 7.51 percent",
        "claim_type": "descriptive",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 1.0,
    }])
    assert result["passed"] is False
    assert any("tolerance" in error
               for error in result["results"][0]["errors"])


def test_invalid_report_schema_is_rejected_by_claims():
    report = _base()
    del report["provenance"]
    result = core.claims(report, [{
        "claim": "The rate is 7.51 percent",
        "claim_type": "descriptive",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
    }])
    assert result["passed"] is False
    assert result["report_errors"]
    assert any("report schema is invalid" in error
               for error in result["results"][0]["errors"])


def test_single_group_interval_is_not_an_equivalence_contrast():
    report = _base()
    report["evidence"] = {"equivalence_margin": 0.01}
    result = core.claims(report, [{
        "claim": "The two rates are equivalent",
        "claim_type": "equivalence",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
    }])
    assert result["passed"] is False
    assert any("contrast" in error
               for error in result["results"][0]["errors"])


def test_equivalence_with_a_paired_contrast_passes():
    report = _base()
    report["evidence"] = {"equivalence_margin": 0.01}
    result = core.claims(report, [{
        "claim": "The two rates are equivalent",
        "claim_type": "equivalence",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
        "contrast": {
            "left": report["system"],
            "right": "hard_first",
            "paired": True,
            "difference_ci95": [-0.005, 0.005],
            "equivalence_margin": 0.01,
            "method": "paired bootstrap, 2000 draws",
        },
    }])
    assert result["passed"] is True, result["results"][0]["errors"]


def test_mechanism_plus_frame_with_disjoint_bounds_is_not_comparable():
    left = _base()
    right = copy.deepcopy(left)
    right["system"] = "hard_first"
    right["design"]["sampling_frame"] = "published_prefix"
    right["design"]["frame_size"] = 400
    for report, attack, benign in ((left, 0.035, 0.32), (right, 0.055, 0.42)):
        report["design"]["enforcement_semantics"] = "unknown"
        report["metrics"] = {
            "attack_trace_block_rate": attack,
            "benign_trace_block_rate": benign,
        }
        report["bounds"] = {
            "attack_trace_block_rate": [attack - 0.005, attack + 0.005],
            "benign_trace_block_rate": [benign - 0.02, benign + 0.02],
        }
    result = core.compare(left, right)
    assert result["comparison_type"] == "not_comparable"
    assert result["licensed"] is False
    assert result.get("strict_ranking_licensed") is not True


def test_mechanism_plus_attribution_change_is_not_comparable():
    left = _base()
    right = copy.deepcopy(left)
    right["system"] = "hard_first"
    right["design"]["attribution_source"] = "gate_side"
    result = core.compare(left, right)
    assert result["comparison_type"] == "not_comparable"
    assert result["licensed"] is False


def test_different_protocol_is_not_comparable():
    left = _base()
    left["protocol"] = "frozen-v1"
    right = copy.deepcopy(left)
    right["protocol"] = "frozen-v2"
    result = core.compare(left, right)
    assert result["comparison_type"] == "not_comparable"
    assert result["licensed"] is False


def test_mixed_benchmark_sensitivity_is_rejected():
    left = _base()
    right = copy.deepcopy(left)
    right["benchmark"] = "another_benchmark"
    result = core.sensitivity([left, right], "attack_trace_block_rate")
    assert result["comparable"] is False
    assert result["systems"] == {}
    assert "different benchmarks or protocols" in result["error"]


def test_mixed_protocol_sensitivity_is_rejected():
    left = _base()
    right = copy.deepcopy(left)
    right["protocol"] = "another_protocol"
    result = core.sensitivity([left, right], "attack_trace_block_rate")
    assert result["comparable"] is False
    assert result["systems"] == {}


def test_claim_protocol_mismatch_is_rejected():
    report = _base()
    report["protocol"] = "frozen-v1"
    result = core.claims(report, [{
        "claim": "The rate is 7.51 percent",
        "claim_type": "descriptive",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
        "protocol": "frozen-v2",
    }])
    assert result["passed"] is False
    assert any("protocol" in error
               for error in result["results"][0]["errors"])


def test_claim_denominator_mismatch_is_rejected():
    report = _base()
    report["uncertainty"]["attack_trace_block_rate"]["denominator"] = (
        "attack traces")
    result = core.claims(report, [{
        "claim": "The rate is 7.51 percent",
        "claim_type": "descriptive",
        "metric": "attack_trace_block_rate",
        "value": 0.0751,
        "tolerance": 0.0001,
        "denominator": "paired cells",
    }])
    assert result["passed"] is False
    assert any("denominator" in error
               for error in result["results"][0]["errors"])


def test_counterfactual_treatment_control_and_zero_coverage_are_rejected(
        tmp_path):
    report = _base()
    document = _counterfactual_document(
        report, design={"treatment": "same", "control": "same"})
    _attach_counterfactual(tmp_path, report, document)
    report["evidence"]["attribution_coverage"] = 0.0
    result = core.claims(report, [_causal_claim()], root=tmp_path)
    errors = result["results"][0]["errors"]
    assert result["passed"] is False
    assert any("different treatment and control" in error for error in errors)
    assert any("positive attribution_coverage" in error for error in errors)


def test_counterfactual_n_must_match_the_report_frame_size(tmp_path):
    report = _base()
    document = _counterfactual_document(report, n=100)
    _attach_counterfactual(tmp_path, report, document)
    result = core.claims(report, [_causal_claim()], root=tmp_path)
    assert result["passed"] is False
    assert any("frame_size" in error
               for error in result["results"][0]["errors"])


def test_counterfactual_expected_effect_must_match_the_estimate(tmp_path):
    report = _base()
    document = _counterfactual_document(report)
    _attach_counterfactual(tmp_path, report, document)
    claim = _causal_claim()
    claim["expected_effect"] = "negative"
    result = core.claims(report, [claim], root=tmp_path)
    assert result["passed"] is False
    assert any("expected_effect='negative'" in error
               for error in result["results"][0]["errors"])


def test_counterfactual_nan_estimate_is_rejected(tmp_path):
    report = _base()
    document = _counterfactual_document(report, estimate_pp=math.nan)
    _attach_counterfactual(tmp_path, report, document)
    result = core.claims(report, [_causal_claim()], root=tmp_path)
    assert result["passed"] is False
    assert any("finite estimate_pp" in error
               for error in result["results"][0]["errors"])


def test_non_object_claim_is_rejected():
    result = core.claims(_base(), ["not a claim object"])
    assert result["passed"] is False
    assert result["results"][0]["errors"] == [
        "a claim must be a JSON object"]
