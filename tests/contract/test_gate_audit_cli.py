"""Pin the Claim Auditor MVP behaviour."""

import json
from pathlib import Path

from tools.gate_audit import core
from tools.gate_audit.cli import main
from tools.gate_audit.schema import validate_report

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "tools" / "gate_audit" / "examples"


def _load(name):
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def test_valid_report_passes_and_missing_semantics_fails():
    report = _load("report_band_block.json")
    assert validate_report(report) == []
    broken = json.loads(json.dumps(report))
    del broken["design"]["enforcement_semantics"]
    assert any("enforcement_semantics" in error for error in validate_report(broken))


def test_identify_licenses_mechanism_but_not_attribution_for_outcome_only():
    result = core.identify(_load("report_band_block.json"))
    assert result["can_enter"]["mechanism"] is True
    assert result["can_enter"]["attribution"] is False
    gate_side = core.identify(_load("report_band_gate_side.json"))
    assert gate_side["can_enter"]["attribution"] is True


def test_compare_classifies_design_sensitivity_population_and_multi_coordinate():
    sensitivity = core.compare(
        _load("report_band_block.json"), _load("report_band_log.json"))
    assert sensitivity["comparison_type"] == "design_sensitivity"
    assert sensitivity["licensed"] is True
    population = core.compare(
        _load("report_band_block.json"), _load("report_band_prefix.json"))
    assert population["comparison_type"] == "population"
    assert population["licensed"] is True

    other = json.loads(json.dumps(_load("report_band_prefix.json")))
    other["design"]["aggregation_rule"] = "hard_first"
    multi = core.compare(_load("report_band_block.json"), other)
    assert multi["comparison_type"] == "not_comparable"
    assert multi["licensed"] is False


def test_sensitivity_reports_the_design_width():
    reports = [
        _load("report_band_block.json"),
        _load("report_band_prefix.json"),
    ]
    result = core.sensitivity(reports, "attack_trace_block_rate")
    assert result["systems"]["band_split"]["width_pp"] == 0.51
    assert result["max_single_system_width_pp"] == 0.51


def test_claims_reject_block_rate_as_asr_and_wrong_value():
    report = _load("report_band_block.json")
    claims = json.loads((EXAMPLES / "claims_bad.json").read_text(encoding="utf-8"))
    result = core.claims(report, claims)
    assert result["passed"] is False
    assert "not an attack success rate" in result["results"][0]["errors"][0]
    assert result["results"][1]["errors"]


def test_valid_claims_pass():
    report = _load("report_band_block.json")
    claims = json.loads((EXAMPLES / "claims_ok.json").read_text(encoding="utf-8"))
    assert core.claims(report, claims)["passed"] is True


def test_cli_validate_and_compare_exit_codes(capsys):
    assert main(["validate", str(EXAMPLES / "report_band_block.json")]) == 0
    capsys.readouterr()
    assert main(["compare", str(EXAMPLES / "report_band_block.json"),
                 str(EXAMPLES / "report_band_log.json"), "--format", "markdown"]) == 0
    output = capsys.readouterr().out
    assert "design_sensitivity" in output
