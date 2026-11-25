"""Pin the S02 fault suite: detection, controls, and original bytes."""

import hashlib
import json
from pathlib import Path

from experiments.faults import run_fault_suite as suite

RESULT = (Path(__file__).resolve().parents[2]
          / "experiments" / "faults" / "results" / "fault_suite.json")


def test_all_twelve_faults_are_detected():
    faults = suite.build_faults()
    assert len(faults) == 12
    for case in faults:
        result = suite.evaluate_fault(case)
        assert result["detected"] is True, (case["id"], result["evidence"])


def test_all_negative_controls_pass():
    controls = suite.build_controls()
    assert len(controls) == 8
    for case in controls:
        result = suite.evaluate_control(case)
        assert result["rejected"] is False, (case["id"], result["evidence"])


def test_originals_are_not_mutated():
    before = suite._digests()
    for case in suite.build_faults():
        suite.evaluate_fault(case)
    for case in suite.build_controls():
        suite.evaluate_control(case)
    after = suite._digests()
    assert before == after


def test_recorded_summary_matches_the_suite():
    data = json.loads(RESULT.read_text(encoding="utf-8"))
    assert data["summary"] == {
        "faults": 12,
        "detected": 12,
        "controls": 8,
        "false_rejections": 0,
        "originals_unchanged": True,
    }
    assert {item["id"] for item in data["faults"]} == {
        f"F{index:02d}" for index in range(1, 13)}
    assert {item["id"] for item in data["controls"]} == {
        f"N{index:02d}" for index in range(1, 9)}


def test_suite_is_deterministic():
    first = [
        (case["id"], suite.evaluate_fault(case)["detected"])
        for case in suite.build_faults()
    ]
    second = [
        (case["id"], suite.evaluate_fault(case)["detected"])
        for case in suite.build_faults()
    ]
    assert first == second
    digest = hashlib.sha256(RESULT.read_bytes()).hexdigest()
    assert len(digest) == 64
