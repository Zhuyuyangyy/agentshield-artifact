"""Regression pins for the clustered intervals quoted in the paper."""

import json
from pathlib import Path

RESULT = (Path(__file__).resolve().parents[2]
          / "experiments" / "statistics" / "results" / "clustered_bootstrap.json")


def _load():
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_band_and_hard_first_are_exactly_equal_on_attacks():
    data = _load()
    entry = data["contrasts"]["band_minus_hard|block"]["attack"]
    assert entry["point_pp"] == 0.0
    assert entry["cell_ci95"] == [0.0, 0.0]
    assert entry["user_cluster_ci95"] == [0.0, 0.0]
    assert entry["injection_cluster_ci95"] == [0.0, 0.0]
    assert entry["twoway_ci95"] == [0.0, 0.0]


def test_benign_difference_is_three_point_zero_nine_points():
    data = _load()
    entry = data["contrasts"]["band_minus_hard|block"]["benign"]
    assert entry["point_pp"] == 3.0928
    assert entry["cell_ci95"] == [0.0, 7.2165]
    assert entry["user_cluster_ci95"] == [0.0, 7.2165]


def test_global_cap_lead_does_not_survive_user_clustering():
    data = _load()
    entry = data["contrasts"]["band_minus_global|block"]["attack"]
    assert entry["point_pp"] == 0.1341
    assert entry["cell_ci95"] == [0.0671, 0.2107]
    assert entry["user_cluster_ci95"][0] == 0.0
    assert entry["twoway_ci95"][0] < 0.0
    assert entry["twoway_ci95"][1] > 0.0


def test_review_load_difference_is_under_one_point():
    data = _load()
    entry = data["contrasts"]["review_step_rate|block"]["benign"]
    assert entry["point_pp"] == 0.885
    assert entry["cell_ci95"][0] == 0.0
    assert entry["user_cluster_ci95"][0] == 0.0


def test_cluster_counts_are_recorded():
    data = _load()
    entry = data["contrasts"]["band_minus_hard|block"]["attack"]
    assert entry["n_traces"] == 10439
    assert entry["n_user_clusters"] == 97
    assert entry["n_injection_clusters"] == 35
