"""P2 authorization invariant matrix: the pre-registered invariants, re-derived.

Pre-registration:
``docs/superpowers/specs/2026-09-29-authorization-invariant-matrix.md`` (§6, §10).
Harness: ``benchmark/authorization_invariant_matrix.py``.

This file does not call the harness's invariant code. It re-derives the §6
invariants from the *committed* ``matrix.json`` with its own arithmetic, so a bug
in the harness cannot certify itself; where the harness also records a verdict,
the two are asserted to agree. Three checks the harness cannot make about itself
are added on top:

* **H1 pinned against the engine directly** for cells 3 and 4 (the
  authorized-structural class, the cells the paper's §7.5 claim is about): a fresh
  engine is driven here, and the score it records now must equal both the frozen
  ``matrix.json`` value and the independently re-derived ``band_split``.
* **Determinism**: a second in-process run of the harness reproduces every cell's
  policy scores, peaks and engine score exactly.
* **Hash discipline** (§7): the freeze hashes match the committed artifacts, and
  the recorded pre-registration / harness hashes match the committed files.

No ``agentdojo`` import anywhere -- it is absent on this host, and the harness is
required to run without it.
"""

from __future__ import annotations

import json
import sys
from functools import lru_cache
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
BENCHMARK = ROOT / "benchmark"
for _path in (str(BACKEND), str(BENCHMARK)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

RESULTS = ROOT / "benchmark/results/authorization_invariant_matrix"
PREREG = ROOT / "docs/superpowers/specs/2026-09-29-authorization-invariant-matrix.md"
HARNESS = ROOT / "benchmark/authorization_invariant_matrix.py"

BLOCK_THRESHOLD = 0.90
REVIEW_THRESHOLD = 0.60
POLICIES = ("no_authorization", "global_cap", "band_split")
TOL = 1e-9

# The 12 pre-registered cell identifiers (§3.2), as a set the artifact must match.
EXPECTED_CELL_IDS = {
    f"{auth}__{risk}__{actuation}"
    for auth in ("explicit", "delegated", "none")
    for risk in ("provenance_only", "hard_structural")
    for actuation in ("side_effect", "read_only")
}

# The authorized-structural class: the cells that carry both an authorization cap
# and a hard structural peak, i.e. the ones §7.5 is actually about.
H1_ENGINE_PIN_CELLS = (
    "explicit__hard_structural__side_effect",
    "explicit__hard_structural__read_only",
)


# ─── Loading the committed artifacts ─────────────────────────────────────────


@lru_cache(maxsize=1)
def _matrix() -> dict:
    return json.loads((RESULTS / "matrix.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _rows_by_id() -> dict:
    return {row["cell_id"]: row for row in _matrix()["cells"]}


def _lf_sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


# ─── Independent re-derivation (the harness's own functions are not called) ──


def _band_sets() -> tuple:
    """The engine's classification frozensets, read from the engine module."""
    from app.shield.risk_signals import (
        SUPPRESSIBLE_PROVENANCE_SIGNALS,
        SUPPRESSION_EVIDENCE_SIGNALS,
    )

    return (
        {s.value for s in SUPPRESSIBLE_PROVENANCE_SIGNALS},
        {s.value for s in SUPPRESSION_EVIDENCE_SIGNALS},
    )


def _peaks(row: dict) -> tuple:
    """``(hard_peak, suppressible_peak, cap)`` straight from the raw record."""
    suppressible_types, evidence_types = _band_sets()
    structural = row["structural"]
    hard = max(
        structural["local_risk"],
        structural["inherited_risk"],
        structural["path_risk"],
        structural["downstream_exposure"],
    )
    soft = 0.0
    caps = []
    for signal in row["signals"]:
        name = signal["signal_type"]
        if name in suppressible_types:
            soft = max(soft, signal["score"])
        elif name in evidence_types:
            if signal["caps_risk"] is not None:
                caps.append(signal["caps_risk"])
        else:
            # Unsuppressible, plus fail-closed for anything unclassified.
            hard = max(hard, signal["score"])
    return hard, soft, (min(caps) if caps else None)


def _floor(peak: float, intervention: float) -> float:
    if intervention > peak:
        peak = intervention
    return max(0.0, min(1.0, peak))


def _rederive_scores(row: dict) -> dict:
    hard, soft, cap = _peaks(row)
    intervention = row["structural"]["intervention_value"]
    soft_capped = soft if cap is None else min(soft, cap)
    peak = max(hard, soft)
    return {
        "no_authorization": _floor(peak, intervention),
        "global_cap": _floor(min(peak, cap) if cap is not None else peak, intervention),
        "band_split": _floor(max(hard, soft_capped), intervention),
    }


def _label(score: float) -> str:
    if score >= BLOCK_THRESHOLD:
        return "BLOCK"
    if score >= REVIEW_THRESHOLD:
        return "REVIEW"
    return "ALLOW"


# ─── §6 invariants 1 and 6 ───────────────────────────────────────────────────


def test_cell_count_and_policy_keys():
    """Invariant 1: 12 pre-registered cells, three policy scores each."""
    matrix = _matrix()
    rows = matrix["cells"]
    assert len(rows) == 12
    assert {row["cell_id"] for row in rows} == EXPECTED_CELL_IDS
    for row in rows:
        assert set(row["policy_scores"]) == set(POLICIES), row["cell_id"]
        assert set(row["policy_labels"]) == set(POLICIES), row["cell_id"]


def test_labels_derive_from_frozen_thresholds_and_cover_every_cell():
    """Invariant 6: labels come from the frozen thresholds, and each policy labels
    all 12 cells exactly once."""
    matrix = _matrix()
    for policy in POLICIES:
        counts = {"ALLOW": 0, "REVIEW": 0, "BLOCK": 0}
        for row in matrix["cells"]:
            score = row["policy_scores"][policy]
            expected = _label(score)
            assert row["policy_labels"][policy] == expected, (row["cell_id"], policy)
            counts[expected] += 1
        assert sum(counts.values()) == 12, policy
        assert matrix["checks"]["policy_label_counts"][policy] == counts, policy


# ─── H1 / invariant 2: the transcription cannot drift ────────────────────────


def test_h1_band_split_reproduces_the_engine_score():
    """H1: ``band_split`` equals the score the engine itself recorded."""
    matrix = _matrix()
    assert matrix["block_threshold"] == BLOCK_THRESHOLD
    assert matrix["review_threshold"] == REVIEW_THRESHOLD
    for row in matrix["cells"]:
        rederived = _rederive_scores(row)["band_split"]
        assert abs(rederived - row["engine_combined_risk"]) < TOL, row["cell_id"]
        assert abs(row["policy_scores"]["band_split"] - row["engine_combined_risk"]) < TOL
    assert matrix["H1_transcription_fidelity"]["holds"] is True


# ─── H2 / invariants 3, 4, 5: the algebra ────────────────────────────────────


def test_h2_policy_ordering():
    """H2: ``global_cap <= band_split <= no_authorization`` for all 12 cells."""
    matrix = _matrix()
    for row in matrix["cells"]:
        scores = row["policy_scores"]
        assert scores["global_cap"] <= scores["band_split"] <= scores["no_authorization"], (
            row["cell_id"],
            scores,
        )
    assert matrix["H2_policy_ordering"]["holds"] is True


def test_h3_bypass_iff():
    """H3: divergence between the pre-fix rule and the frozen rule is exactly the
    condition ``cap is present and hard_peak > cap``."""
    matrix = _matrix()
    observed, predicted = [], []
    for row in matrix["cells"]:
        hard, _soft, cap = _peaks(row)
        diverges = row["policy_scores"]["global_cap"] < row["policy_scores"]["band_split"]
        assert diverges == (cap is not None and hard > cap), row["cell_id"]
        assert row["peak_decomposition"]["order_divergence"] == diverges, row["cell_id"]
        if diverges:
            observed.append(row["cell_id"])
        if cap is not None and hard > cap:
            predicted.append(row["cell_id"])
    assert observed == predicted
    assert matrix["H3_bypass_condition"]["iff_holds"] is True
    assert matrix["H3_bypass_condition"]["observed_divergent_cells"] == observed
    assert matrix["H3_bypass_condition"]["bypass_cells"] == len(observed)
    # The pre-registration's judgement rule needs at least one bypass cell, and
    # only the authorized cells carry a cap, so the bypasses are exactly the
    # explicit x hard_structural ones plus the explicit provenance_only sink.
    assert set(observed) == {
        "explicit__provenance_only__side_effect",
        "explicit__hard_structural__side_effect",
        "explicit__hard_structural__read_only",
    }


def test_policies_only_differ_where_suppression_evidence_exists():
    """Invariant 5: no suppression evidence -> all three policies agree."""
    matrix = _matrix()
    for row in matrix["cells"]:
        has_cap = any(s["caps_risk"] is not None for s in row["signals"])
        assert row["peak_decomposition"]["has_suppression_evidence"] == has_cap, row["cell_id"]
        if not has_cap:
            assert len(set(row["policy_scores"].values())) == 1, row["cell_id"]
    assert matrix["checks"]["policies_equal_without_evidence"]["holds"] is True


# ─── H4, H5: the safety invariant ────────────────────────────────────────────


def test_h4_every_hard_structural_cell_stays_at_block():
    """H4: for every hard-structural cell, ``band_split >= 0.90`` under every
    authorization basis. A single cell below 0.90 falsifies the invariant."""
    matrix = _matrix()
    checked = 0
    for row in matrix["cells"]:
        if row["risk"] != "hard_structural":
            continue
        checked += 1
        assert row["policy_scores"]["band_split"] >= BLOCK_THRESHOLD, row["cell_id"]
        assert row["policy_labels"]["band_split"] == "BLOCK", row["cell_id"]
    assert checked == 6
    assert matrix["H4_hard_structural_blocked"]["holds"] is True


def test_h5_authorization_cannot_reach_the_hard_band():
    """H5: for every hard-structural cell the authorization cap changes nothing."""
    matrix = _matrix()
    for row in matrix["cells"]:
        if row["risk"] != "hard_structural":
            continue
        scores = row["policy_scores"]
        assert scores["band_split"] == scores["no_authorization"], row["cell_id"]
    assert matrix["H5_authorization_cannot_reach_hard_band"]["holds"] is True


# ─── H6, H7: the two boundaries recorded alongside the verdict ───────────────


def test_h6_delegated_boundary_is_silent_and_uncompared():
    """H6: where authorization is data-dependent, no authorization signal is
    emitted and therefore no policy can diverge inside the cell.

    Recorded as the boundary the invariant cannot cover, not as a success; it is
    deliberately not a comparison against the ``none`` cells (see prereg A1).
    """
    matrix = _matrix()
    delegated = 0
    for row in matrix["cells"]:
        fired = any(s["signal_type"] == "user_authorized_action" for s in row["signals"])
        if row["auth"] == "delegated":
            delegated += 1
            assert not fired, row["cell_id"]
            assert row["peak_decomposition"]["cap"] is None, row["cell_id"]
            assert len(set(row["policy_scores"].values())) == 1, row["cell_id"]
        if row["auth"] == "none":
            assert not fired, row["cell_id"]
    assert delegated == 4
    assert matrix["H6_delegated_data_dependent_boundary"]["holds"] is True


def test_h7_read_only_weight_does_not_excuse_a_privileged_tool():
    """H7: ``read_process_memory`` looks read-only but is privileged, so its
    untrusted-instruction signal must be at full weight (0.95), not tempered to
    the read-only weight (~0.285)."""
    matrix = _matrix()
    checked = 0
    for row in matrix["cells"]:
        if row["risk"] != "hard_structural" or row["actuation"] != "read_only":
            continue
        checked += 1
        scores = [
            s["score"] for s in row["signals"] if s["signal_type"] == "untrusted_instruction"
        ]
        assert scores, row["cell_id"]
        assert max(scores) >= BLOCK_THRESHOLD, (row["cell_id"], scores)
    assert checked == 3
    assert matrix["H7_read_only_precedence"]["holds"] is True


def test_verdict_is_supported_and_not_voided():
    verdict = _matrix()["verdict"]
    assert verdict["voided"] is False
    assert verdict["supported"] is True
    assert _matrix()["checks"]["violations"] == []


# ─── The engine pin H1: cells 3 and 4 driven again, now ──────────────────────


def _drive_engine_now(cell_id: str) -> tuple:
    """Drive the pre-registered scenario for ``cell_id`` on a fresh engine and
    return ``(combined_risk, decision, signals)`` from the governed call."""
    import authorization_invariant_matrix as harness

    scenario = {c["cell_id"]: c for c in harness.build_cells()}[cell_id]
    from app.shield.v3_engine import V3ShieldEngine

    engine = V3ShieldEngine(session_id=f"pytest_pin_{cell_id}", **harness.v0_4_1_flags())
    source = engine.process_tool_call(
        agent_id="p2_agent",
        tool_name=scenario["source"]["tool"],
        params=scenario["source"]["params"],
        user_intent=scenario["intent"],
        tool_output=scenario["source"]["output"],
        output_trust="untrusted",
    )
    governed = engine.process_tool_call(
        agent_id="p2_agent",
        tool_name=scenario["governed"]["tool"],
        params=scenario["governed"]["params"],
        parent_node_id=source.get("node_id"),
        user_intent=scenario["intent"],
        output_trust="untrusted",
    )
    state = engine._graph_risk_state
    assert state is not None
    return float(state.combined_risk), governed.get("decision"), state.signals


@pytest.mark.parametrize("cell_id", H1_ENGINE_PIN_CELLS)
def test_h1_pinned_against_the_engine_for_the_authorized_structural_cells(cell_id):
    """The artifact must be reproducible by the engine on this host, not just
    self-consistent: re-drive cells 3 and 4 and compare to the frozen record."""
    row = _rows_by_id()[cell_id]
    combined, decision, signals = _drive_engine_now(cell_id)

    assert abs(combined - row["engine_combined_risk"]) < TOL, (cell_id, combined)
    assert abs(_rederive_scores(row)["band_split"] - combined) < TOL, cell_id
    assert combined >= BLOCK_THRESHOLD, cell_id
    assert decision == "block", (cell_id, decision)

    # The cap must be carried by the engine's own live signal object, since
    # RiskSignal.to_dict drops caps_risk.
    caps = [
        s.caps_risk
        for s in signals
        if s.caps_risk is not None
    ]
    assert caps == [0.55], (cell_id, caps)
    assert min(caps) == _peaks(row)[2], cell_id


# ─── Determinism: a second in-process run reproduces every number ────────────


def test_second_in_process_run_reproduces_the_frozen_matrix():
    """§10: the harness is deterministic. Re-run it here and require the same
    policy scores, peaks, engine score and engine decision for all 12 cells."""
    import authorization_invariant_matrix as harness

    second = harness.evaluate(harness.build_cells())
    frozen = _rows_by_id()
    assert {row["cell_id"] for row in second["cells"]} == set(frozen)
    for row in second["cells"]:
        reference = frozen[row["cell_id"]]
        cell_id = row["cell_id"]
        assert row["policy_scores"] == reference["policy_scores"], cell_id
        assert row["peak_decomposition"] == reference["peak_decomposition"], cell_id
        assert row["engine_combined_risk"] == reference["engine_combined_risk"], cell_id
        assert row["engine_decision"] == reference["engine_decision"], cell_id
    assert second["verdict"] == _matrix()["verdict"]


# ─── §7 hash discipline ──────────────────────────────────────────────────────


def test_preregistration_and_harness_hashes_match_the_committed_files():
    """The pre-registration was committed before the harness ran, and the manifest
    the artifact carries must name the file actually in the tree."""
    matrix = _matrix()
    assert matrix["preregistration_sha256"] == _lf_sha256(PREREG)
    assert matrix["harness_sha256"] == _lf_sha256(HARNESS)


def test_freeze_hashes_match_the_committed_artifacts():
    freeze = json.loads((RESULTS / "freeze.json").read_text(encoding="utf-8"))
    assert freeze["manifest_sha256"] == _lf_sha256(RESULTS / "manifest.json")
    assert freeze["matrix_sha256"] == _lf_sha256(RESULTS / "matrix.json")


def test_manifest_records_engine_hashes_of_the_tree_it_measured():
    manifest = json.loads((RESULTS / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["cells"] == 12
    assert manifest["asr_measured"] is False
    assert manifest["utility_measured"] is False
    assert manifest["measured_over_traffic"] is False
    for path, digest in manifest["engine_source_sha256"].items():
        assert digest == _lf_sha256(ROOT / path), path
