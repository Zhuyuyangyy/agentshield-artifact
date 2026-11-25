"""Pin the E04 joint design and sampling verdicts."""

import json
from pathlib import Path

RESULT = (Path(__file__).resolve().parents[2]
          / "experiments" / "sensitivity" / "results" / "joint.json")


def _load():
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_no_uniform_dominance_claim_is_licensed():
    data = _load()
    assert data["summary"]["strict_uniform_claims"] == 0
    assert data["summary"]["licensed_claims"] == []
    assert all(not item["uniform_dominance_licensed"]
               for item in data["contrasts"].values())


def test_band_hard_attack_is_a_set_identity():
    data = _load()
    item = data["contrasts"]["band_minus_hard|attack_trace_block_rate"]
    assert item["verdict"] == "set_identity"
    assert {config["point_pp"] for config in item["configurations"]} == {0.0}
    assert {tuple(config["cell_ci95"]) for config in item["configurations"]} == {
        (0.0, 0.0)}


def test_band_global_attack_is_census_cell_only():
    data = _load()
    item = data["contrasts"]["band_minus_global|attack_trace_block_rate"]
    assert item["verdict"] == "census_cell_only"
    census = {
        config["semantics"]: config for config in item["configurations"]
        if config["frame"] == "full"
    }
    assert census["block"]["point_pp"] == 0.1341
    assert census["block"]["cell_ci95"] == [0.0671, 0.2107]
    prefix = [
        config for config in item["configurations"]
        if config["frame"] == "prefix_400"
    ]
    assert {config["point_pp"] for config in prefix} == {0.0}
    clustered = item["clustered_census"]
    assert clustered["intervals"]["user_cluster_ci95"] == [0.0, 0.4178]
    assert clustered["intervals"]["twoway_ci95"] == [-0.121, 0.3892]
    assert clustered["all_exclude_zero"] is False


def test_benign_contrasts_are_below_resolution():
    data = _load()
    for key in ("band_minus_hard|benign_trace_block_rate",
                "band_minus_global|benign_trace_block_rate"):
        item = data["contrasts"][key]
        assert item["verdict"] == "not_resolvable"
        assert all(config["cell_ci95"][0] == 0
                   for config in item["configurations"])
    hard = data["contrasts"]["band_minus_hard|benign_trace_block_rate"]
    block = next(config for config in hard["configurations"]
                 if config["semantics"] == "block")
    assert block["point_pp"] == 3.0928
    assert block["cell_ci95"] == [0.0, 7.2165]


def test_study2_top_two_changes_sign():
    data = _load()
    item = data["study2_top_two"]
    assert item["verdict"] == "sign_change"
    assert item["design_envelope"]["min"]["difference_pp"] == -1.113
    assert item["design_envelope"]["max"]["difference_pp"] == 10.417
