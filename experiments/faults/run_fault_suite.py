"""Evaluation fault suite (S02).

Twelve injected faults and eight negative controls exercise the Claim Auditor
on copies of the frozen example reports. The originals are hashed before and
after; the suite fails if any byte changes.

Faults
------
F01  missing enforcement semantics          validate
F02  missing metric uncertainty            validate
F03  illegal aggregation rule              validate
F04  metric above one                      validate
F05  metric below zero                     validate
F06  missing provenance source             validate
F07  malformed SHA-256 digest              validate
F08  block rate described as attack success claims
F09  claimed value outside tolerance       claims
F10  frame-only comparison across benchmarks compare
F11  two design coordinates differ         compare
F12  no shared metric                      compare

Controls
--------
N01  another rule                          validate
N02  another enforcement semantics         validate
N03  different interval values             validate
N04  all six metrics                       validate
N05  derived provenance with valid digest  validate
N06  ASR claim backed by end_to_end_asr    claims
N07  same-benchmark frame comparison       compare
N08  same-frame semantics comparison       compare

Outputs
-------
experiments/faults/results/fault_suite.json
experiments/faults/FAULT_SUITE.md

Run:
    python experiments/faults/run_fault_suite.py
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.gate_audit.core import claims, compare  # noqa: E402
from tools.gate_audit.schema import validate_report  # noqa: E402

EXAMPLES = ROOT / "tools" / "gate_audit" / "examples"
OUT = ROOT / "experiments" / "faults" / "results" / "fault_suite.json"
MD = ROOT / "experiments" / "faults" / "FAULT_SUITE.md"


def _load(name: str) -> Dict[str, Any]:
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def _copy(report: Dict[str, Any]) -> Dict[str, Any]:
    return copy.deepcopy(report)


def _digests() -> Dict[str, str]:
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(EXAMPLES.glob("*.json"))
    }


def build_faults() -> List[Dict[str, Any]]:
    base = _load("report_band_block.json")
    other = _load("report_band_prefix.json")
    other["benchmark"] = "agentdojo_public"
    two_coordinates = _load("report_band_prefix.json")
    two_coordinates["design"]["aggregation_rule"] = "hard_first"
    asr_only = _load("report_band_block.json")
    asr_only["metrics"] = {"end_to_end_asr": 0.12}
    asr_only["uncertainty"] = {
        "end_to_end_asr": {"method": "paired bootstrap", "unit": "task",
                           "ci95": [0.05, 0.19]}}

    cases = []

    report = _copy(base)
    del report["design"]["enforcement_semantics"]
    cases.append({
        "id": "F01", "kind": "validate",
        "description": "missing enforcement semantics",
        "report": report,
        "expected": "design.enforcement_semantics is required",
    })

    report = _copy(base)
    del report["uncertainty"]["attack_trace_block_rate"]
    cases.append({
        "id": "F02", "kind": "validate",
        "description": "missing metric uncertainty",
        "report": report,
        "expected": "uncertainty.attack_trace_block_rate is required",
    })

    report = _copy(base)
    report["design"]["aggregation_rule"] = "majority_vote"
    cases.append({
        "id": "F03", "kind": "validate",
        "description": "illegal aggregation rule",
        "report": report,
        "expected": "aggregation_rule must be one of",
    })

    report = _copy(base)
    report["metrics"]["attack_trace_block_rate"] = 7.51
    cases.append({
        "id": "F04", "kind": "validate",
        "description": "metric reported as a percentage above one",
        "report": report,
        "expected": "must lie in [0, 1]",
    })

    report = _copy(base)
    report["metrics"]["benign_trace_block_rate"] = -0.01
    cases.append({
        "id": "F05", "kind": "validate",
        "description": "negative metric",
        "report": report,
        "expected": "must lie in [0, 1]",
    })

    report = _copy(base)
    del report["provenance"]["source"]
    cases.append({
        "id": "F06", "kind": "validate",
        "description": "missing provenance source",
        "report": report,
        "expected": "provenance.source",
    })

    report = _copy(base)
    report["provenance"]["sha256"] = "abc123"
    cases.append({
        "id": "F07", "kind": "validate",
        "description": "malformed SHA-256 digest",
        "report": report,
        "expected": "provenance.sha256",
    })

    cases.append({
        "id": "F08", "kind": "claims",
        "description": "block rate described as attack success",
        "report": _copy(base),
        "claims": [{
            "claim": "The gate reaches 7.5 percent attack success",
            "claim_type": "descriptive",
            "metric": "attack_trace_block_rate",
            "value": 0.0751,
            "tolerance": 0.001,
        }],
        "expected": "not an attack success rate",
    })

    cases.append({
        "id": "F09", "kind": "claims",
        "description": "claimed value outside tolerance",
        "report": _copy(base),
        "claims": [{
            "claim": "Benign trace blocking is 40 percent",
            "claim_type": "descriptive",
            "metric": "benign_trace_block_rate",
            "value": 0.40,
            "tolerance": 0.001,
        }],
        "expected": "claimed 0.4 but the report has",
    })

    cases.append({
        "id": "F10", "kind": "compare",
        "description": "frame-only comparison across benchmarks",
        "left": _copy(base),
        "right": _copy(other),
        "expected_type": "not_comparable",
    })

    cases.append({
        "id": "F11", "kind": "compare",
        "description": "two design coordinates differ",
        "left": _copy(base),
        "right": _copy(two_coordinates),
        "expected_type": "not_comparable",
    })

    cases.append({
        "id": "F12", "kind": "compare",
        "description": "no shared metric",
        "left": _copy(base),
        "right": _copy(asr_only),
        "expected_type": "not_comparable",
    })

    return cases


def build_controls() -> List[Dict[str, Any]]:
    base = _load("report_band_block.json")
    log = _load("report_band_log.json")
    prefix = _load("report_band_prefix.json")

    hard = _copy(base)
    hard["design"]["aggregation_rule"] = "hard_first"

    wide = _copy(base)
    wide["uncertainty"]["attack_trace_block_rate"]["ci95"] = [0.06, 0.09]

    all_metrics = _copy(base)
    all_metrics["metrics"].update({
        "human_review_rate": 0.059,
        "benign_step_block_fpr": 0.01,
        "end_to_end_asr": 0.12,
        "benign_task_utility": 0.88,
    })
    all_metrics["uncertainty"].update({
        "human_review_rate": {"method": "bootstrap", "unit": "step",
                              "ci95": [0.035, 0.087]},
        "benign_step_block_fpr": {"method": "bootstrap", "unit": "step",
                                   "ci95": [0.005, 0.02]},
        "end_to_end_asr": {"method": "bootstrap", "unit": "task",
                            "ci95": [0.05, 0.19]},
        "benign_task_utility": {"method": "bootstrap", "unit": "task",
                                "ci95": [0.81, 0.95]},
    })

    derived = _copy(base)
    derived["provenance"]["derived"] = True

    return [
        {"id": "N01", "kind": "validate", "description": "another rule",
         "report": hard},
        {"id": "N02", "kind": "validate", "description": "another semantics",
         "report": _copy(log)},
        {"id": "N03", "kind": "validate", "description": "different interval values",
         "report": wide},
        {"id": "N04", "kind": "validate", "description": "all six metrics",
         "report": all_metrics},
        {"id": "N05", "kind": "validate", "description": "derived provenance",
         "report": derived},
        {"id": "N06", "kind": "claims", "description": "ASR claim backed by ASR",
         "report": _copy(all_metrics),
         "claims": [{
             "claim": "The gate reaches 12 percent attack success",
             "claim_type": "descriptive",
             "metric": "end_to_end_asr",
             "value": 0.12,
             "tolerance": 0.001,
         }]},
        {"id": "N07", "kind": "compare",
         "description": "same-benchmark frame comparison",
         "left": _copy(base), "right": _copy(prefix)},
        {"id": "N08", "kind": "compare",
         "description": "same-frame semantics comparison",
         "left": _copy(base), "right": _copy(log)},
    ]


def evaluate_fault(case: Dict[str, Any]) -> Dict[str, Any]:
    if case["kind"] == "validate":
        errors = validate_report(case["report"])
        detected = any(case["expected"] in error for error in errors)
        return {"detected": detected, "evidence": errors}
    if case["kind"] == "claims":
        result = claims(case["report"], case["claims"])
        errors = [error for item in result["results"] for error in item["errors"]]
        detected = (not result["passed"]) and any(
            case["expected"] in error for error in errors)
        return {"detected": detected, "evidence": errors}
    result = compare(case["left"], case["right"])
    detected = (result["comparison_type"] == case["expected_type"]
                and not result.get("licensed", False))
    return {"detected": detected,
            "evidence": [result["comparison_type"], result.get("note", "")]}


def evaluate_control(case: Dict[str, Any]) -> Dict[str, Any]:
    if case["kind"] == "validate":
        errors = validate_report(case["report"])
        return {"rejected": bool(errors), "evidence": errors}
    if case["kind"] == "claims":
        result = claims(case["report"], case["claims"])
        return {"rejected": not result["passed"], "evidence": result["results"]}
    result = compare(case["left"], case["right"])
    licensed = bool(result.get("licensed", result.get("comparable")))
    return {"rejected": not licensed,
            "evidence": [result["comparison_type"], result.get("note", "")]}


def main() -> int:
    before = _digests()
    faults = []
    for case in build_faults():
        result = evaluate_fault(case)
        faults.append({
            "id": case["id"],
            "kind": case["kind"],
            "description": case["description"],
            "detected": result["detected"],
            "evidence": result["evidence"],
        })
    controls = []
    for case in build_controls():
        result = evaluate_control(case)
        controls.append({
            "id": case["id"],
            "kind": case["kind"],
            "description": case["description"],
            "rejected": result["rejected"],
            "evidence": result["evidence"],
        })
    after = _digests()
    originals_unchanged = before == after
    if not originals_unchanged:
        raise SystemExit("the suite mutated an example report")

    result = {
        "experiment": "S02 evaluation fault suite",
        "faults": faults,
        "controls": controls,
        "summary": {
            "faults": len(faults),
            "detected": sum(1 for item in faults if item["detected"]),
            "controls": len(controls),
            "false_rejections": sum(1 for item in controls if item["rejected"]),
            "originals_unchanged": originals_unchanged,
        },
        "not_claimed": [
            "Synthetic faults validate the implementation, not real-world accuracy.",
            "The suite covers twelve fault classes and eight controls, not every "
            "possible reporting error.",
            "No original artifact is modified; every case works on a copy.",
        ],
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=1), encoding="utf-8")

    lines = [
        "# S02 — Evaluation fault suite",
        "",
        "Twelve injected faults and eight negative controls, run on copies of "
        "the frozen examples. The example files are hashed before and after.",
        "",
        "## Faults",
        "",
        "| id | kind | description | detected | evidence |",
        "|---|---|---|---|---|",
    ]
    for item in faults:
        evidence = "; ".join(str(value) for value in item["evidence"])
        lines.append(
            f"| {item['id']} | {item['kind']} | {item['description']} | "
            f"{item['detected']} | {evidence} |")
    lines += [
        "",
        "## Negative controls",
        "",
        "| id | kind | description | rejected | evidence |",
        "|---|---|---|---|---|",
    ]
    for item in controls:
        evidence = "; ".join(str(value) for value in item["evidence"])
        lines.append(
            f"| {item['id']} | {item['kind']} | {item['description']} | "
            f"{item['rejected']} | {evidence} |")
    lines += [
        "",
        f"Detected {result['summary']['detected']} of "
        f"{result['summary']['faults']} faults; "
        f"{result['summary']['false_rejections']} of "
        f"{result['summary']['controls']} controls were falsely rejected; "
        f"originals unchanged: {result['summary']['originals_unchanged']}.",
        "",
        "## What is not claimed",
        "",
        *[f"- {item}" for item in result["not_claimed"]],
        "",
        "Reproduce: `python experiments/faults/run_fault_suite.py`",
    ]
    MD.parent.mkdir(parents=True, exist_ok=True)
    MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT).as_posix()} and {MD.relative_to(ROOT).as_posix()}")
    print(result["summary"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
