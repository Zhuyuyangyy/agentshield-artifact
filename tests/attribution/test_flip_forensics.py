"""Pin the E07/E08 flip matrix and attribution bounds."""

import json
from pathlib import Path

RESULT = (Path(__file__).resolve().parents[2]
          / "experiments" / "attribution" / "results" / "flip_forensics.json")


def _load():
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_fifteen_flips_and_class_counts():
    data = _load()
    assert len(data["flips"]) == 15
    assert data["classes"] == {
        "gate_consistent": 6, "zero_intervention": 3, "unrecorded": 6}
    assert all(row["a_security"] is True and row["b_security"] is False
               for row in data["flips"])
    assert data["coding_check"]["disagreements"] == []


def test_unrecorded_flips_are_one_user_task():
    data = _load()
    unrecorded = [row for row in data["flips"]
                  if row["class"] == "unrecorded"]
    assert {row["cell"].split("|")[0] for row in unrecorded} == {"user_task_28"}
    assert data["unrecorded_flip_tasks"] == ["user_task_28"]


def test_zero_intervention_cells_ran_the_gate():
    data = _load()
    zero = [row for row in data["flips"]
            if row["class"] == "zero_intervention"]
    assert len(zero) == 3
    assert all(row["blocked_calls"] == 0 and row["gate_calls"] > 0
               for row in zero)


def test_bounds_are_six_to_twelve():
    data = _load()
    bounds = data["bounds"]
    assert bounds["identified_lower"] == 6
    assert bounds["identified_upper"] == 12
    assert bounds["naive_upper"] == 15
    assert bounds["width_flips"] == 6
    assert bounds["cluster_conditional"]["values"] == [6, 12]


def test_source_is_provenance_not_a_measurement():
    data = _load()
    assert data["provenance"]["derived"] is True
    assert data["provenance"]["empty_snapshots"] == 2
    assert data["provenance"]["not_a_measurement"]
    assert data["coverage"]["paired_attack_cells"] == 80
    assert data["coverage"]["cells_with_attribution"] == 57
    assert data["unmapped_by_user_task"] == {
        "user_task_25": 7, "user_task_28": 8, "user_task_30": 8}
