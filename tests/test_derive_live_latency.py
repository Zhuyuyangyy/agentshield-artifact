"""Unit tests for the live-pair wall-clock derivation.

These test the derivation, not the experiment. ``derive()`` only reads frozen
per-cell artifacts, so the suite re-derives the real thing from the committed
sources and stays independent of any model or pipeline being reachable.

What is being pinned is the failure behaviour. The artifact exists to back a
sentence in the paper, so a derivation that reports PASS for a payload that no
longer reproduces that sentence is worse than no derivation: every mutation a
future edit could plausibly introduce gets its own negative case -- a dropped
cell, a nudged duration, a duplicated row, an invented paper number, and a
source file that moved after the artifact was written.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

_BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from benchmark.derive_live_latency import (  # noqa: E402
    ARM_A_LABEL,
    ARM_B_LABEL,
    DEFAULT_OUT,
    LIVE_DIR,
    aggregate_from_cells,
    check_invariants,
    derive,
    digest_set_sha256,
    failed_invariants,
    load_arm,
    median,
    verify_against_sources,
)
from benchmark.derive_live_latency import (  # noqa: E402
    ARM_A_PIPELINE,
    ARM_A_RUN,
)

_PAPER_MEDIAN_S = {ARM_A_LABEL: 63.9, ARM_B_LABEL: 73.3}
_PAPER_TOTAL_S = {ARM_A_LABEL: 13213, ARM_B_LABEL: 36948}


def _payload() -> dict:
    return derive()


def _failed_names(payload: dict) -> set:
    """Invariants that fail for *this* payload, evaluated now rather than read
    back from the list a previous derivation left inside it."""
    return {i["invariant"] for i in check_invariants(payload) if not i["passed"]}


def _by_arm(payload: dict, arm: str) -> list:
    return [c for c in payload["cells"] if c["arm"] == arm]


class TestDerivedPayload:
    def test_every_invariant_passes(self):
        assert failed_invariants(derive()) == []

    def test_committed_artifact_is_reproducible(self, tmp_path):
        """The artifact on disk is exactly what the frozen sources produce."""
        if not DEFAULT_OUT.is_file():
            pytest.skip("derived artifact not present")
        stored = json.loads(DEFAULT_OUT.read_text(encoding="utf-8"))
        fresh = derive()
        assert stored["provenance"]["source_digest_set_sha256"] == (
            fresh["provenance"]["source_digest_set_sha256"]
        )
        assert stored["cells"] == fresh["cells"]
        assert stored["aggregate"] == fresh["aggregate"]

    def test_committed_artifact_matches_sources(self):
        if not DEFAULT_OUT.is_file():
            pytest.skip("derived artifact not present")
        stored = json.loads(DEFAULT_OUT.read_text(encoding="utf-8"))
        assert verify_against_sources(stored) == []

    def test_eighty_paired_cells(self):
        payload = _payload()
        assert payload["pairing"]["paired_cells"] == 80
        assert len(payload["cells"]) == 160
        assert len(_by_arm(payload, ARM_A_LABEL)) == 80
        assert len(_by_arm(payload, ARM_B_LABEL)) == 80

    def test_paper_numbers_reproduce(self):
        payload = _payload()
        per_arm = payload["aggregate"]["per_arm"]
        assert round(per_arm[ARM_A_LABEL]["median_s"], 1) == _PAPER_MEDIAN_S[ARM_A_LABEL]
        assert round(per_arm[ARM_B_LABEL]["median_s"], 1) == _PAPER_MEDIAN_S[ARM_B_LABEL]
        assert round(per_arm[ARM_A_LABEL]["total_s"]) == _PAPER_TOTAL_S[ARM_A_LABEL]
        assert round(per_arm[ARM_B_LABEL]["total_s"]) == _PAPER_TOTAL_S[ARM_B_LABEL]
        assert round(payload["aggregate"]["median_ratio_b_over_a"], 2) == 1.15
        assert round(payload["aggregate"]["total_ratio_b_over_a"], 2) == 2.80
        assert per_arm[ARM_B_LABEL]["over_600s"] == 22


class TestProvenance:
    def test_declares_post_hoc_and_no_rerun(self):
        prov = _payload()["provenance"]
        assert prov["derived_post_hoc"] is True
        assert prov["experiment_rerun"] is False
        assert prov["model_calls"] == 0
        assert prov["filesystem_timestamps_used"] is False
        assert prov["duration_field"] == "duration"

    def test_source_digest_set_covers_every_cell(self):
        payload = _payload()
        prov = payload["provenance"]
        assert prov["source_file_count"] == len(payload["cells"]) == 160
        pairs = [(c["source_file"], c["source_sha256"]) for c in payload["cells"]]
        assert prov["source_digest_set_sha256"] == digest_set_sha256(pairs)

    def test_every_source_file_resolves_and_hashes_as_recorded(self):
        """Each row's digest must name a committed file that still hashes to it."""
        payload = _payload()
        for cell in payload["cells"]:
            path = _BACKEND_DIR / cell["source_file"]
            assert path.is_file(), cell["source_file"]
            observed = hashlib.sha256(
                path.read_bytes().replace(b"\r\n", b"\n")
            ).hexdigest()
            assert observed == cell["source_sha256"], cell["source_file"]


class TestMedianConvention:
    def test_odd_count(self):
        assert median([1.0, 2.0, 3.0]) == 2.0

    def test_even_count_interpolates(self):
        assert median([1.0, 2.0, 3.0, 4.0]) == 2.5

    def test_single_value(self):
        assert median([7.5]) == 7.5


class TestInvariantMutationsFail:
    """Each invariant must be able to fail, or none of them means anything."""

    def test_dropped_row_fails_the_pairing_coverage(self):
        """Losing one arm of one cell is not a full cell, and must not verify."""
        payload = _payload()
        payload["cells"] = payload["cells"][1:]
        names = _failed_names(payload)
        assert "every_paired_cell_has_one_row_per_arm" in names
        assert "aggregate_recomputation_matches_summary" in names

    def test_dropped_cell_fails_the_count(self):
        """Losing both rows of one cell drops the paired count below 80."""
        payload = _payload()
        victim = payload["cells"][0]
        payload["cells"] = [
            c for c in payload["cells"]
            if (c["user_task_id"], c["injection_task_id"])
            != (victim["user_task_id"], victim["injection_task_id"])
        ]
        assert "paired_cell_count" in _failed_names(payload)

    def test_nudged_duration_fails(self):
        payload = _payload()
        payload["cells"][0]["duration_s"] += 1.0
        names = _failed_names(payload)
        assert "aggregate_recomputation_matches_summary" in names
        assert "paper_total_s" in names

    def test_negative_duration_fails(self):
        payload = _payload()
        payload["cells"][0]["duration_s"] = -1.0
        assert "all_durations_non_negative" in _failed_names(payload)

    def test_duplicated_row_fails(self):
        payload = _payload()
        payload["cells"].append(dict(payload["cells"][0]))
        assert "no_duplicate_cells" in _failed_names(payload)

    def test_invented_paper_median_fails(self):
        payload = _payload()
        payload["paper_claims"]["median_s"][ARM_B_LABEL] = 70.2
        assert "paper_median_s" in _failed_names(payload)

    def test_invented_paper_ratio_fails(self):
        payload = _payload()
        payload["paper_claims"]["median_ratio"] = 1.50
        assert "paper_ratios" in _failed_names(payload)

    def test_invented_tail_count_fails(self):
        """Dropping the governed tail cells must break the 22-of-80 count."""
        payload = _payload()
        kept = [
            c for c in payload["cells"]
            if not (c["arm"] == ARM_B_LABEL and c["duration_s"] > 600.0)
        ]
        assert len(payload["cells"]) - len(kept) > 0
        payload["cells"] = kept
        assert f"governed_cells_over_600s" in _failed_names(payload)

    def test_pairing_claim_cannot_be_asserted_away(self):
        payload = _payload()
        payload["pairing"]["matches_index_jsonl_intersection"] = False
        assert "paired_cell_ids_match_index_jsonl_intersection" in _failed_names(payload)


class TestPayloadConstantsAreNotShared:
    """A payload handed out by the derivation must not alias module state."""

    def test_mutations_do_not_leak_into_the_constants(self):
        payload = _payload()
        payload["paper_claims"]["median_s"][ARM_B_LABEL] = 70.2
        assert derive()["paper_claims"]["median_s"][ARM_B_LABEL] == 73.3

    def test_a_second_derivation_is_unaffected(self):
        payload = _payload()
        payload["paper_claims"]["total_s"][ARM_A_LABEL] = 1
        again = derive()
        assert again["paper_claims"]["total_s"][ARM_A_LABEL] == 13213
        assert failed_invariants(again) == []


class TestVerifyAgainstSources:
    def test_row_drift_fails(self):
        payload = _payload()
        victim = payload["cells"][0]
        victim = dict(victim, duration_s=victim["duration_s"] + 5.0)
        payload["cells"] = [victim] + payload["cells"][1:]
        problems = verify_against_sources(payload)
        assert any("row drift" in p for p in problems)

    def test_mutated_cell_digest_fails(self):
        """A row whose digest no longer names its file must not verify."""
        payload = _payload()
        payload["cells"][0]["source_sha256"] = "0" * 64
        problems = verify_against_sources(payload)
        assert any("row drift" in p or "source digest set drift" in p
                   for p in problems)

    def test_tampered_digest_set_fails(self):
        """With every row intact, only the set-level check can catch this."""
        payload = _payload()
        payload["provenance"]["source_digest_set_sha256"] = "0" * 64
        problems = verify_against_sources(payload)
        assert any("source digest set drift" in p for p in problems)

    def test_clean_payload_reports_nothing(self):
        payload = _payload()
        assert verify_against_sources(payload) == []

    def test_payload_constants_still_match_after_earlier_mutations(self):
        assert derive()["paper_claims"]["median_s"] == _PAPER_MEDIAN_S
        assert derive()["paper_claims"]["total_s"] == _PAPER_TOTAL_S


class TestNoSourceIsWritten:
    def test_derive_leaves_every_source_file_untouched(self):
        """The derivation reads the frozen runs; it never restamps one."""
        sources = sorted(LIVE_DIR.rglob("*.json"))
        sources = [p for p in sources if p != DEFAULT_OUT]
        assert sources, "no source files found under the live results directory"
        before = {p: (p.stat().st_size, p.stat().st_mtime_ns) for p in sources}
        derive()
        after = {p: (p.stat().st_size, p.stat().st_mtime_ns) for p in sources}
        assert before == after


class TestRefusesToGuessADuration:
    def test_missing_duration_aborts(self, tmp_path, monkeypatch):
        """No recorded duration means no derived cell -- not an inferred one."""
        monkeypatch.setattr("benchmark.derive_live_latency.LIVE_DIR", tmp_path)
        workspace = tmp_path / "some-run" / "some-pipeline" / "workspace" / "user_task_0"
        workspace.mkdir(parents=True)
        cell = {
            "user_task_id": "user_task_0",
            "injection_task_id": "injection_task_0",
            "attack_type": "important_instructions",
            "utility": True,
        }
        (workspace / "injection_task_0.json").write_text(
            json.dumps(cell), encoding="utf-8"
        )
        with pytest.raises(SystemExit) as excinfo:
            load_arm(ARM_A_LABEL, "some-run", "some-pipeline")
        assert "refuses to guess" in str(excinfo.value)

    def test_non_numeric_duration_aborts(self, tmp_path, monkeypatch):
        monkeypatch.setattr("benchmark.derive_live_latency.LIVE_DIR", tmp_path)
        workspace = tmp_path / ARM_A_RUN / ARM_A_PIPELINE / "workspace"
        workspace.mkdir(parents=True)
        cell = {
            "user_task_id": "user_task_0",
            "injection_task_id": "injection_task_0",
            "attack_type": "important_instructions",
            "duration": "not a number",
        }
        (workspace / "injection_task_0.json").write_text(
            json.dumps(cell), encoding="utf-8"
        )
        with pytest.raises(SystemExit):
            load_arm(ARM_A_LABEL, ARM_A_RUN, ARM_A_PIPELINE)

    def test_missing_workspace_aborts(self, tmp_path, monkeypatch):
        monkeypatch.setattr("benchmark.derive_live_latency.LIVE_DIR", tmp_path)
        with pytest.raises(SystemExit) as excinfo:
            load_arm(ARM_A_LABEL, "absent-run", "absent-pipeline")
        assert "no frozen workspace" in str(excinfo.value)


class TestAggregateHelper:
    def test_recomputation_is_deterministic(self):
        payload = _payload()
        first = aggregate_from_cells(payload["cells"])
        second = aggregate_from_cells(payload["cells"])
        assert first == second == payload["aggregate"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
