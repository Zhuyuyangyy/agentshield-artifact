"""Post-hoc wall-clock derivation for the exploratory live pair.

Why a derivation rather than a measurement
------------------------------------------
The live pair reports a deployment cost in wall clock: median cell duration
63.9 s to 73.3 s, aggregate in-cell wall clock 13,213 s to 36,948 s, 22 of
the 80 governed cells beyond 600 s. Those two runs predate the harness's
per-cell ``latency_s`` column, so neither arm's shipped ``index.jsonl`` carries a
timing field and neither report aggregates one -- which is why the numbers had no
artifact behind them. They are re-derived here, once, from the one record the
runs did keep: the AgentDojo per-cell workspace artifact, which the run wrote at
execution time and which has carried an explicit ``duration`` since the first
live run.

What this script may and may not do
-----------------------------------
``python benchmark/derive_live_latency.py`` re-derives the artifact from the
frozen sources. It reads the two arms' per-cell workspace directories and the two
arms' ``index.jsonl`` (to fix which cells are paired), and it writes the one
output artifact. It stops there:

  * no model client is imported and no model is called,
  * no AgentDojo pipeline is built and no cell is re-run,
  * no source file is written, renamed or rewritten,
  * no filesystem timestamp is read -- not mtime, ctime or atime.

The duration reported is the value the run recorded in the artifact, so a cell
with no recorded duration fails the derivation instead of being filled in from
anything else. That is deliberate: an inferred duration would make the paper's
sentence unfalsifiable, and a claim that cannot be derived from a frozen record
is a claim that should not be made.

The paired cell set is not chosen here. It is the intersection of the two arms'
attack rows in their shipped ``index.jsonl`` -- the same 80 cells the paper's
other live numbers use -- and the derivation refuses to continue if the frozen
workspaces do not reproduce that set.

Output: ``benchmark/results/agentdojo_live/live_latency_derived.json``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]

LIVE_DIR = ROOT / "benchmark" / "results" / "agentdojo_live"

DEFAULT_OUT = LIVE_DIR / "live_latency_derived.json"

# The two arms of Section~\ref{sec:live}, each named by the run directory and by
# the pipeline directory inside it whose per-cell workspace holds the durations.
# Arm B's governed cells live in the v041 run's v0_4_1 pipeline directory; the
# v041 run also carries a no-governance pipeline, but only for its validity leg,
# so the ungoverned attack cells come from the earlier run.
ARM_A_RUN = "headroom-vllm-nemotron-120b"
ARM_A_PIPELINE = "agentshield-no_governance-vllm_parsed_nemotron_120b"
ARM_B_RUN = "headroom-vllm-nemotron-120b-v041"
ARM_B_PIPELINE = "agentshield-v0_4_1-vllm_parsed_nemotron_120b"

ARM_A_LABEL = "A_ungoverned"
ARM_B_LABEL = "B_governed"

#: (label, run directory, pipeline directory) -- the only directories read.
ARMS: Tuple[Tuple[str, str, str], ...] = (
    (ARM_A_LABEL, ARM_A_RUN, ARM_A_PIPELINE),
    (ARM_B_LABEL, ARM_B_RUN, ARM_B_PIPELINE),
)

#: The only attack the live pair ran, and the only cells the deployment-cost
#: sentence describes. Benign and validity cells are read and counted but never
#: paired: the sentence is about attack cells under both policies.
ATTACK_TYPE = "important_instructions"

#: In-cell wall clock beyond this is the long tail the sentence reports.
TAIL_THRESHOLD_S = 600.0

#: The paired intersection the paper quotes, and how many of its governed cells
#: sit past the threshold.
PAIRED_CELLS_EXPECTED = 80
GOVERNED_OVER_THRESHOLD_EXPECTED = 22

#: What the paper prints. Pinned here so the invariants are equalities rather
#: than descriptions: the aggregates recomputed from the frozen per-cell
#: durations must round to exactly these numbers, or the derivation fails. The
#: rounding rules are stated in the artifact for the same reason.
PAPER_MEDIAN_S = {ARM_A_LABEL: 63.9, ARM_B_LABEL: 73.3}
PAPER_TOTAL_S = {ARM_A_LABEL: 13213, ARM_B_LABEL: 36948}
PAPER_MEDIAN_RATIO = 1.15
PAPER_TOTAL_RATIO = 2.80

ROUNDING = {
    "total_s": "nearest whole second",
    "median_s": "one decimal place",
    "ratio": "two decimal places",
}


class CellRecord(NamedTuple):
    """One cell in one arm, with the file its duration came from."""

    user_task_id: str
    injection_task_id: str
    attack_type: str
    duration_s: float
    source_file: str
    source_sha256: str

    @property
    def key(self) -> Tuple[str, str, str]:
        """Cell identity: the same triple on both sides of the pairing."""
        return (self.user_task_id, self.injection_task_id, self.attack_type)


def sha256_lf(path: Path) -> str:
    """sha256 over LF-normalised content.

    The evidence inventory hashes what Git stores rather than what a
    ``core.autocrlf=true`` checkout leaves on disk, so a working copy with CRLF
    line endings does not invalidate every recorded digest. This artifact is
    indexed by that same inventory and follows the same convention.
    """
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def rel(path: Path) -> str:
    """Repository-relative POSIX path, so the artifact resolves anywhere.

    A path outside the repository is returned as an absolute POSIX path rather
    than rejected: the derivation can legitimately be pointed at a frozen
    evidence tree staged somewhere else, and refusing would only hide it.
    """
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def median(ordered: Sequence[float]) -> float:
    """Mean of the two central order statistics.

    Written out rather than called through ``statistics`` because the choice is
    load-bearing: the paper's 73.3 s is this convention, and a nearest-rank
    p50 on the same 80 cells would read 70.2 s. The artifact therefore records
    which median it computed instead of leaving a reviewer to discover it.
    """
    count = len(ordered)
    middle = count // 2
    if count % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def digest_set_sha256(pairs: Sequence[Tuple[str, str]]) -> str:
    """sha256 over the sorted ``<path>:<sha256>`` lines, one LF-terminated each.

    A single number standing for the whole source set, so one changed input
    moves one number rather than being found by re-reading 170 files by hand.
    """
    lines = "".join(f"{path}:{digest}\n" for path, digest in sorted(pairs))
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def index_attack_keys(index_path: Path) -> set:
    """Cell identity of every attack row in one arm's shipped index."""
    keys = set()
    for line in index_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("cell_kind") != "attack":
            continue
        keys.add((row["user_task_id"], row["injection_task_id"]))
    return keys


def load_arm(label: str, run: str, pipeline: str) -> Dict[Tuple[str, str, str], CellRecord]:
    """Read one arm's frozen per-cell workspace artifacts.

    Deliberately reads nothing but the ``duration`` field and the three identity
    fields: the trajectories beside it are the cell's content, which the
    derivation has no business restating.
    """
    workspace = LIVE_DIR / run / pipeline / "workspace"
    if not workspace.is_dir():
        raise SystemExit(f"{label}: no frozen workspace at {rel(workspace)}")

    records: Dict[Tuple[str, str, str], CellRecord] = {}
    files = 0
    for path in sorted(workspace.rglob("*.json")):
        files += 1
        payload = json.loads(path.read_text(encoding="utf-8"))
        duration = payload.get("duration")
        if not isinstance(duration, (int, float)) or isinstance(duration, bool):
            raise SystemExit(
                f"{label}: {rel(path)} records no numeric duration, so this "
                f"derivation refuses to guess one"
            )
        record = CellRecord(
            user_task_id=payload["user_task_id"],
            injection_task_id=payload["injection_task_id"],
            attack_type=payload["attack_type"],
            duration_s=float(duration),
            source_file=rel(path),
            source_sha256=sha256_lf(path),
        )
        if record.key in records:
            raise SystemExit(
                f"{label}: {record.key} appears twice "
                f"({records[record.key].source_file} and {record.source_file})"
            )
        records[record.key] = record

    if files != len(records):
        raise SystemExit(f"{label}: read {files} files but kept {len(records)} cells")
    return records


def attack_cells(records: Dict[Tuple[str, str, str], CellRecord]) -> Dict[Tuple[str, str], CellRecord]:
    """The arm's attack cells, keyed the way the paired comparison pairs them."""
    return {
        (record.user_task_id, record.injection_task_id): record
        for record in records.values()
        if record.attack_type == ATTACK_TYPE
    }


def aggregate(values: Sequence[float]) -> Dict[str, Any]:
    """The arm's contribution to the sentence, from its own cells only."""
    ordered = sorted(values)
    return {
        "n": len(ordered),
        "total_s": sum(ordered),
        "median_s": median(ordered),
        f"over_{int(TAIL_THRESHOLD_S)}s": sum(1 for v in ordered if v > TAIL_THRESHOLD_S),
    }


def aggregate_from_cells(cells: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Recompute the aggregates from an artifact's own per-cell rows.

    The same helper the derivation uses, so a recomputation is bit-for-bit the
    same arithmetic rather than a second implementation that has to agree.
    """
    per_arm = {}
    for label, _, _ in ARMS:
        per_arm[label] = aggregate([c["duration_s"] for c in cells if c["arm"] == label])
    a = per_arm[ARM_A_LABEL]
    b = per_arm[ARM_B_LABEL]
    return {
        "per_arm": per_arm,
        "median_ratio_b_over_a": b["median_s"] / a["median_s"],
        "total_ratio_b_over_a": b["total_s"] / a["total_s"],
    }


def check_invariants(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every invariant the artifact must satisfy, computed from the payload.

    Runs on a freshly derived payload and on one read back from disk, so the
    list written into the artifact is the list a later check re-evaluates.
    """
    cells = payload["cells"]
    pairing = payload["pairing"]
    stored = payload["aggregate"]
    recomputed = aggregate_from_cells(cells)
    b = recomputed["per_arm"][ARM_B_LABEL]
    claims = payload["paper_claims"]

    # Counted from the rows, not from the pairing report beside them: a payload
    # missing a row must not be able to keep reporting the pairing it came from.
    paired_ids = {(c["user_task_id"], c["injection_task_id"]) for c in cells}
    rows_per_cell: Dict[Tuple[str, str], int] = {}
    for cell in cells:
        key = (cell["user_task_id"], cell["injection_task_id"])
        rows_per_cell[key] = rows_per_cell.get(key, 0) + 1
    both_arms = sum(1 for key, count in rows_per_cell.items() if count == len(ARMS))

    def rounded(value: float, places: int) -> float:
        return round(value, places)

    def check(name: str, expected: Any, observed: Any) -> Dict[str, Any]:
        return {
            "invariant": name,
            "expected": expected,
            "observed": observed,
            "passed": expected == observed,
        }

    return [
        check("paired_cell_count",
              PAIRED_CELLS_EXPECTED, len(paired_ids)),
        check("paired_cell_ids_match_index_jsonl_intersection",
              True, pairing["matches_index_jsonl_intersection"]),
        check("every_paired_cell_has_one_row_per_arm",
              PAIRED_CELLS_EXPECTED, both_arms),
        check("no_duplicate_cells",
              len(cells), len({(c["user_task_id"], c["injection_task_id"],
                                c["arm"]) for c in cells})),
        check("all_durations_non_negative",
              0, sum(1 for c in cells if c["duration_s"] < 0)),
        check("aggregate_recomputation_matches_summary",
              stored, recomputed),
        check(f"governed_cells_over_{int(TAIL_THRESHOLD_S)}s",
              GOVERNED_OVER_THRESHOLD_EXPECTED, b[f"over_{int(TAIL_THRESHOLD_S)}s"]),
        check("paper_median_s",
              claims["median_s"],
              {label: rounded(recomputed["per_arm"][label]["median_s"], 1)
               for label, _, _ in ARMS}),
        check("paper_total_s",
              claims["total_s"],
              {label: round(recomputed["per_arm"][label]["total_s"])
               for label, _, _ in ARMS}),
        check("paper_ratios",
              {"median": claims["median_ratio"], "total": claims["total_ratio"]},
              {"median": rounded(recomputed["median_ratio_b_over_a"], 2),
               "total": rounded(recomputed["total_ratio_b_over_a"], 2)}),
    ]


def derive() -> Dict[str, Any]:
    """Assemble the artifact payload from the frozen sources. Writes nothing."""
    loaded = {}
    index_digests = {}
    for label, run, pipeline in ARMS:
        loaded[label] = load_arm(label, run, pipeline)
        index_path = LIVE_DIR / run / "index.jsonl"
        if not index_path.is_file():
            raise SystemExit(f"{label}: no shipped index at {rel(index_path)}")
        index_digests[label] = {
            "index_jsonl": rel(index_path),
            "index_jsonl_sha256": sha256_lf(index_path),
        }

    attacks = {label: attack_cells(records) for label, records in loaded.items()}
    key_a, key_b = set(attacks[ARM_A_LABEL]), set(attacks[ARM_B_LABEL])
    paired = sorted(key_a & key_b)

    index_a = index_attack_keys(LIVE_DIR / ARM_A_RUN / "index.jsonl")
    index_b = index_attack_keys(LIVE_DIR / ARM_B_RUN / "index.jsonl")
    index_paired = index_a & index_b

    cells: List[Dict[str, Any]] = []
    for key in paired:
        for label, _, _ in ARMS:
            record = attacks[label][key]
            cells.append({
                "user_task_id": record.user_task_id,
                "injection_task_id": record.injection_task_id,
                "attack_type": record.attack_type,
                "arm": label,
                "duration_s": record.duration_s,
                "source_file": record.source_file,
                "source_sha256": record.source_sha256,
            })

    source_pairs = [
        (c["source_file"], c["source_sha256"]) for c in cells
    ]
    script_path = ROOT / "benchmark" / "derive_live_latency.py"

    totals = aggregate_from_cells(cells)
    payload: Dict[str, Any] = {
        "experiment": "live_pair_deployment_cost_derivation",
        "description": (
            "Post-hoc wall-clock derivation for the exploratory live pair of "
            "Section sec:live. One row per cell per arm, carrying the duration "
            "the run itself recorded, and the aggregate the paper quotes."
        ),
        "provenance": {
            "derived_post_hoc": True,
            "experiment_rerun": False,
            "model_calls": 0,
            "derivation_script": rel(script_path),
            "derivation_script_sha256": sha256_lf(script_path),
            "duration_field": "duration",
            "timing_measurement": (
                "in-process wall clock, the difference of two time.monotonic() "
                "readings around the cell, written by the run harness into the "
                "per-cell workspace artifact"
            ),
            "filesystem_timestamps_used": False,
            "hash_encoding": (
                "sha256 over LF-normalised content, the convention "
                "benchmark/results/EVIDENCE_MANIFEST.json documents"
            ),
            "source_file_count": len(source_pairs),
            "source_digest_set_sha256": digest_set_sha256(source_pairs),
            "source_digest_recipe": (
                "sha256 over the UTF-8 bytes of the '<repo-relative path>:"
                "<lf-normalised sha256>' lines, sorted by path and each "
                "terminated by one LF; the per-cell source_sha256 values are "
                "that same set"
            ),
            "source_runs": [
                {
                    "arm": label,
                    "run_dir": run,
                    "pipeline": pipeline,
                    "workspace": rel(LIVE_DIR / run / pipeline / "workspace"),
                    "attack_cells_in_arm": len(attacks[label]),
                    "attack_cells_paired": len(paired),
                    **index_digests[label],
                }
                for label, run, pipeline in ARMS
            ],
        },
        "pairing": {
            "rule": (
                "cells present in both arms' attack sets, keyed by "
                "(user_task_id, injection_task_id, attack_type); the same key "
                "the arms' index.jsonl rows carry"
            ),
            "attack_type": ATTACK_TYPE,
            "arm_a_attack_cells": len(key_a),
            "arm_b_attack_cells": len(key_b),
            "paired_cells": len(paired),
            "unpaired_in_arm_a": len(key_a - key_b),
            "unpaired_in_arm_b": len(key_b - key_a),
            "reference_cell_set": (
                "the intersection of the two arms' attack rows in their shipped "
                "index.jsonl, which is the set the paper's other live numbers "
                "are computed on"
            ),
            "matches_index_jsonl_intersection": set(paired) == index_paired,
        },
        "cells": cells,
        "aggregate": {
            "per_arm": totals["per_arm"],
            "median_ratio_b_over_a": totals["median_ratio_b_over_a"],
            "total_ratio_b_over_a": totals["total_ratio_b_over_a"],
        },
        "paper_claims": {
            # Copied, not shared: a caller mutating a derived payload must not
            # rewrite the constants the next derivation checks itself against.
            "median_s": dict(PAPER_MEDIAN_S),
            "total_s": dict(PAPER_TOTAL_S),
            "median_ratio": PAPER_MEDIAN_RATIO,
            "total_ratio": PAPER_TOTAL_RATIO,
            "rounding": dict(ROUNDING),
            "sentence": (
                "median cell wall time increased from 63.9 s to 73.3 s (1.15x), "
                "while aggregate wall time increased from 13,213 s to 36,948 s "
                "(2.80x), with 22/80 governed cells exceeding 600 s"
            ),
        },
    }

    payload["invariants"] = check_invariants(payload)
    return payload


def failed_invariants(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [i for i in payload["invariants"] if not i["passed"]]


def verify_against_sources(payload: Dict[str, Any]) -> List[str]:
    """Re-read the frozen sources and check the artifact against them.

    Re-derives and compares cell by cell -- identity, duration, source path and
    source digest -- so a source file edited after the artifact was written
    fails here rather than passing because the artifact still mentions it.
    """
    problems: List[str] = []
    current = derive()
    if failed_invariants(current):
        problems.append(
            "the frozen sources no longer satisfy the derivation's invariants"
        )
    for check in failed_invariants(current):
        problems.append(
            f"invariant {check['invariant']}: expected {check['expected']!r}, "
            f"observed {check['observed']!r}"
        )

    stored = {
        (c["user_task_id"], c["injection_task_id"], c["arm"]): c
        for c in payload["cells"]
    }
    fresh = {
        (c["user_task_id"], c["injection_task_id"], c["arm"]): c
        for c in current["cells"]
    }
    if set(stored) != set(fresh):
        only_stored = sorted(set(stored) - set(fresh))[:3]
        only_fresh = sorted(set(fresh) - set(stored))[:3]
        problems.append(
            f"cell set drift: {len(stored)} recorded, {len(fresh)} in the "
            f"sources, e.g. recorded-only {only_stored}, "
            f"sources-only {only_fresh}"
        )
    for key in sorted(set(stored) & set(fresh)):
        if stored[key] != fresh[key]:
            problems.append(f"row drift for {key}: {stored[key]} != {fresh[key]}")
    if payload["provenance"]["source_digest_set_sha256"] != (
            current["provenance"]["source_digest_set_sha256"]):
        problems.append("source digest set drift: the frozen inputs moved")
    if payload["provenance"]["derivation_script_sha256"] != (
            current["provenance"]["derivation_script_sha256"]):
        problems.append(
            "derivation script drift: the artifact was produced by a different "
            "version of the script"
        )
    return problems


def write_artifact(payload: Dict[str, Any], out: Path) -> None:
    """Write the artifact, never any of the sources it was derived from."""
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, indent=2,
                                sort_keys=False) + "\n")


def report(payload: Dict[str, Any]) -> str:
    """The human-readable summary printed after deriving or verifying."""
    prov = payload["provenance"]
    pairing = payload["pairing"]
    agg = payload["aggregate"]
    claims = payload["paper_claims"]
    a = agg["per_arm"][ARM_A_LABEL]
    b = agg["per_arm"][ARM_B_LABEL]
    lines = [
        "live-pair deployment cost, derived from frozen per-cell records",
        f"  paired cells        {pairing['paired_cells']} "
        f"(A has {pairing['arm_a_attack_cells']}, B has "
        f"{pairing['arm_b_attack_cells']} attack cells; "
        f"{pairing['unpaired_in_arm_a']} of A's are outside the intersection)",
        f"  A total             {a['total_s']:.1f} s -> paper "
        f"{claims['total_s'][ARM_A_LABEL]} s",
        f"  B total             {b['total_s']:.1f} s -> paper "
        f"{claims['total_s'][ARM_B_LABEL]} s",
        f"  A median            {a['median_s']:.4f} s -> paper "
        f"{claims['median_s'][ARM_A_LABEL]} s",
        f"  B median            {b['median_s']:.4f} s -> paper "
        f"{claims['median_s'][ARM_B_LABEL]} s",
        f"  median ratio        {agg['median_ratio_b_over_a']:.4f}x -> paper "
        f"{claims['median_ratio']}x",
        f"  total ratio         {agg['total_ratio_b_over_a']:.4f}x -> paper "
        f"{claims['total_ratio']}x",
        f"  B over 600 s        {b['over_600s']} of {b['n']}",
        f"  source files        {prov['source_file_count']} "
        f"(digest set {prov['source_digest_set_sha256'][:16]}...)",
        f"  derived post hoc    {prov['derived_post_hoc']} "
        f"(experiment rerun: {prov['experiment_rerun']}, model calls: "
        f"{prov['model_calls']}, filesystem timestamps: "
        f"{prov['filesystem_timestamps_used']})",
    ]
    for check in payload["invariants"]:
        mark = "ok  " if check["passed"] else "FAIL"
        lines.append(f"  {mark} {check['invariant']}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--out", type=str, default=str(DEFAULT_OUT.relative_to(ROOT)),
        help="artifact to write (default: %(default)s)",
    )
    parser.add_argument(
        "--verify", action="store_true",
        help="check the artifact at --out against the frozen sources and write "
             "nothing",
    )
    args = parser.parse_args(argv)
    out = ROOT / args.out

    if args.verify:
        if not out.is_file():
            print(f"FAIL: no artifact at {rel(out)}")
            return 2
        payload = json.loads(out.read_text(encoding="utf-8"))
        problems: List[str] = []
        for check in failed_invariants(payload):
            problems.append(
                f"invariant {check['invariant']}: expected "
                f"{check['expected']!r}, observed {check['observed']!r}"
            )
        problems += verify_against_sources(payload)
        print(report(payload))
        if problems:
            print()
            for problem in problems:
                print(f"   HARD  {problem}")
            print(f"\nFAIL: {len(problems)} problem(s)")
            return 1
        print("\nPASS: the artifact still matches the frozen per-cell records")
        return 0

    payload = derive()
    broken = failed_invariants(payload)
    if broken:
        print(report(payload))
        print()
        for check in broken:
            print(f"   HARD  invariant {check['invariant']}: expected "
                  f"{check['expected']!r}, observed {check['observed']!r}")
        print("\nFAIL: refusing to write an artifact that breaks an invariant")
        return 1

    write_artifact(payload, out)
    print(report(payload))
    print(f"\nWritten to {rel(out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
