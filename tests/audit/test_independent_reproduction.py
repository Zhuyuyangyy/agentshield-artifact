"""Pin the V01 internal recomputation and review artifacts."""

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RESULT = ROOT / "audit" / "independent_review" / "results" / "recompute.json"
SCRIPT = ROOT / "audit" / "independent_review" / "recompute.py"
REVIEW = ROOT / "audit" / "independent_review" / "ADVERSARIAL_REVIEW.md"


def _load():
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_all_independent_checks_match():
    data = _load()
    assert data["mode"] == "offline"
    assert data["status"] == "pass"
    assert data["blocked"]
    assert data["matches"]
    assert all(data["matches"].values())
    assert data["study1"]["attack"] == 10439
    assert data["study1"]["benign"] == 97
    assert data["study1"]["block_sets"]["symmetric_difference"] == 0
    assert data["study2"] is None
    assert data["reversal"]["minimum"]["distance_l1"] == 0.10713
    assert data["reversal"]["compositions"] == 1501380
    assert data["reversal"]["minimum"]["gap_pp"] > 0
    assert data["reversal"]["minimum_tie"]["distance_l1"] == 0.121979
    assert data["reversal"]["minimum_tie"]["gap_pp"] == 0
    assert data["reversal"]["minimum_strict"] == data["reversal"]["minimum"]
    assert data["power"]["observed_power"] == 0.081
    assert data["power"]["mde_pp"] == {"q_0.10": 8.97, "q_0.20": 12.95}
    assert data["flips"]["bound"] == [6, 12]


def test_recompute_does_not_import_the_analysis_modules():
    text = SCRIPT.read_text(encoding="utf-8")
    for forbidden in ("from benchmark", "import benchmark",
                      "from experiments", "import experiments",
                      "from tools", "import tools"):
        assert forbidden not in text


def test_adversarial_review_has_seven_sections():
    text = REVIEW.read_text(encoding="utf-8")
    headings = [line for line in text.splitlines() if line.startswith("## ")]
    assert len(headings) == 7
    assert "TODO" not in text


def _load_recompute():
    spec = importlib.util.spec_from_file_location(
        "recompute_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """A writable copy of the two inputs, with outputs redirected."""
    module = _load_recompute()
    outcomes = tmp_path / "outcomes.jsonl"
    shutil.copy2(module.OUTCOMES, outcomes)
    attribution = tmp_path / "attribution.json"
    shutil.copy2(module.ATTRIBUTION, attribution)
    reversal = tmp_path / "reversal_distance.json"
    shutil.copy2(module.REVERSAL_RESULT, reversal)
    registry = tmp_path / "CLAIM_REGISTRY.json"
    shutil.copy2(module.REGISTRY, registry)
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "OUTCOMES", outcomes)
    monkeypatch.setattr(module, "ATTRIBUTION", attribution)
    monkeypatch.setattr(module, "REVERSAL_RESULT", reversal)
    monkeypatch.setattr(module, "REGISTRY", registry)
    monkeypatch.setattr(module, "OUT", tmp_path / "recompute.json")
    monkeypatch.setattr(module, "MD", tmp_path / "REPORT.md")
    return module, outcomes


def test_recompute_tampered_counts_fail_the_gate(sandbox):
    module, outcomes = sandbox
    kept = []
    removed = False
    for line in outcomes.read_text(encoding="utf-8").splitlines():
        if not removed and json.loads(line)["label"] == "attack":
            removed = True
            continue
        kept.append(line)
    outcomes.write_text("\n".join(kept) + "\n", encoding="utf-8")
    assert module.main(["--mode", "offline"]) == 1
    result = json.loads(module.OUT.read_text(encoding="utf-8"))
    assert result["status"] == "fail"
    assert result["matches"]["S1-ATTACK"] is False


def test_recompute_missing_input_returns_blocked(sandbox, capsys):
    module, outcomes = sandbox
    outcomes.unlink()
    assert module.main(["--mode", "offline"]) == 2
    assert "BLOCKED" in capsys.readouterr().out
    result = json.loads(module.OUT.read_text(encoding="utf-8"))
    assert result["status"] == "BLOCKED"


def test_recompute_does_not_count_unexecuted_checks_as_passed(sandbox):
    module, _ = sandbox
    assert module.main(["--mode", "offline"]) == 0
    result = json.loads(module.OUT.read_text(encoding="utf-8"))
    assert result["status"] == "pass"
    assert len(result["matches"]) == 43
    assert "S2-CELLS" not in result["matches"]
    assert "S2-PREFIX-GAP" not in result["matches"]
    assert "S2-ASR-TOOL-FILTER" in result["not_executed"]
    assert any("Study 2" in item for item in result["blocked"])


def test_recompute_flips_one_trace_outside_the_prefix_and_fails(sandbox):
    module, outcomes = sandbox
    rows = [json.loads(line)
            for line in outcomes.read_text(encoding="utf-8").splitlines()]
    attack_index = 0
    changed = False
    for row in rows:
        if row["label"] != "attack":
            continue
        attack_index += 1
        if attack_index <= 400:
            continue
        if (row["blocked"]["band_split"]["block"]
                and row["blocked"]["hard_first"]["block"]):
            row["blocked"]["band_split"]["block"] = False
            row["blocked"]["hard_first"]["block"] = False
            changed = True
            break
    assert changed, "no attack trace outside the prefix had both block flags set"
    outcomes.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    assert module.main(["--mode", "offline"]) == 1
    result = json.loads(module.OUT.read_text(encoding="utf-8"))
    assert result["status"] == "fail"
    assert result["matches"]["S1-BLOCK-SET-BAND-SPLIT"] is False
    assert result["matches"]["S1-ATTACK-BAND-SPLIT-BLOCK"] is False


def test_recompute_missing_reversal_file_returns_blocked(sandbox, capsys):
    module, _ = sandbox
    module.REVERSAL_RESULT.unlink()
    assert module.main(["--mode", "offline"]) == 2
    assert "BLOCKED" in capsys.readouterr().out
    result = json.loads(module.OUT.read_text(encoding="utf-8"))
    assert result["status"] == "BLOCKED"
    assert any("reversal_distance.json" in item for item in result["blocked"])
