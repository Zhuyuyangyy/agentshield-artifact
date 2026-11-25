"""Flip forensics and attribution bounds (E07/E08).

The frozen attribution file records 80 paired attack cells of the live
evaluation. Fifteen flip from attack success in the ungoverned arm to failure
in the governed arm. For every flip this script records the gate-side evidence
and classifies it:

  gate_consistent     a record with blocked_calls > 0
  zero_intervention   a record with blocked_calls == 0
  unrecorded          no gate-side record (all fields null)

The attribution bound follows from one stated assumption: a flip whose record
shows zero blocked calls cannot have been caused by gate blocking. With no
assumption about the unrecorded cells, the number of gate-attributable flips
lies in [gate_consistent, gate_consistent + unrecorded] = [6, 12]. The naive
upper bound of 15 is reported and rejected because it attributes the three
zero-intervention flips to the gate.

A secondary, conditional bound uses the fact that all six unrecorded flips are
in one user task: if the gate's behaviour is homogeneous within that task, the
unrecorded group is either all gate-consistent or all zero-intervention, so the
attainable counts are {6, 12} rather than the full interval. The assumption is
reported, not used for the primary bound.

The source is a post-hoc fusion. `derived` is true and the file says it is not a
measurement; the bounds are bounds on records, not on a fresh causal estimate.

Outputs
-------
experiments/attribution/results/flip_forensics.json
experiments/attribution/FLIP_FORENSICS.md

Run:
    python experiments/attribution/flip_forensics.py
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "benchmark" / "results" / "agentdojo_live"
          / "headroom-vllm-nemotron-120b-v041" / "attribution.json")
OUT = ROOT / "experiments" / "attribution" / "results" / "flip_forensics.json"
MD = ROOT / "experiments" / "attribution" / "FLIP_FORENSICS.md"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _classify(cell: dict) -> str:
    blocked = cell.get("blocked_calls")
    if blocked is None:
        return "unrecorded"
    if blocked == 0:
        return "zero_intervention"
    return "gate_consistent"


def _classify_independently(cell: dict) -> str:
    """Second coder: key off record presence, not the blocked count alone."""
    if cell.get("gate_calls") is None or cell.get("iterations") is None:
        return "unrecorded"
    if cell.get("blocked_calls") == 0:
        return "zero_intervention"
    return "gate_consistent"


def main() -> int:
    data = json.loads(SOURCE.read_text(encoding="utf-8"))
    cells = data["cells"]
    flips = [cell for cell in cells
             if cell.get("a_security") and not cell.get("b_security")]
    if len(cells) != 80 or len(flips) != 15:
        raise SystemExit(
            f"expected 80 cells and 15 flips, got {len(cells)} and {len(flips)}")

    rows = []
    disagreements = []
    for cell in sorted(
            flips, key=lambda item: (item["user_task_id"], item["injection_task_id"])):
        class_name = _classify(cell)
        second = _classify_independently(cell)
        if second != class_name:
            disagreements.append({
                "cell": f"{cell['user_task_id']}|{cell['injection_task_id']}",
                "coder_a": class_name,
                "coder_b": second,
            })
        blocked = cell.get("blocked_calls")
        gate_calls = cell.get("gate_calls")
        if class_name == "gate_consistent":
            evidence = f"blocked {blocked} of {gate_calls} gate calls"
        elif class_name == "zero_intervention":
            evidence = f"gate ran {gate_calls} call(s) and blocked none"
        else:
            evidence = "no gate-side record"
        rows.append({
            "cell": f"{cell['user_task_id']}|{cell['injection_task_id']}",
            "user_task_id": cell["user_task_id"],
            "injection_task_id": cell["injection_task_id"],
            "cell_run_id": cell.get("cell_run_id"),
            "a_security": cell["a_security"],
            "b_security": cell["b_security"],
            "blocked_calls": blocked,
            "gate_calls": gate_calls,
            "iterations": cell.get("iterations"),
            "class": class_name,
            "evidence": evidence,
        })

    classes = Counter(row["class"] for row in rows)
    gate_consistent = classes["gate_consistent"]
    zero_intervention = classes["zero_intervention"]
    unrecorded = classes["unrecorded"]

    unmapped_by_task = Counter(
        cell.split("|")[0] for cell in data["coverage"]["unmapped_cells"])
    unrecorded_flips = [row for row in rows if row["class"] == "unrecorded"]
    unrecorded_flip_tasks = sorted({row["cell"].split("|")[0]
                                    for row in unrecorded_flips})

    lower = gate_consistent
    upper = gate_consistent + unrecorded
    cluster_conditional = {
        "values": [gate_consistent, gate_consistent + unrecorded],
        "assumption": (
            "The gate behaves homogeneously within the user task that holds "
            "all unrecorded flips, so its six missing records are either all "
            "gate-consistent or all zero-intervention."),
        "status": "conditional; not used for the primary bound",
    }

    result = {
        "experiment": "E07/E08 flip forensics and attribution bounds",
        "source": {
            "path": "benchmark/results/agentdojo_live/"
                    "headroom-vllm-nemotron-120b-v041/attribution.json",
            "sha256": _sha256(SOURCE),
        },
        "provenance": {
            "derived": bool(data.get("derived")),
            "not_a_measurement": data.get("not_a_measurement"),
            "snapshots": len(data.get("source_snapshots", [])),
            "empty_snapshots": sum(
                1 for item in data.get("source_snapshots", [])
                if item.get("size") == 0),
            "join_key": data.get("join_key"),
        },
        "coverage": data["coverage"],
        "flips": rows,
        "classes": {
            "gate_consistent": gate_consistent,
            "zero_intervention": zero_intervention,
            "unrecorded": unrecorded,
        },
        "unmapped_by_user_task": dict(sorted(unmapped_by_task.items())),
        "unrecorded_flip_tasks": unrecorded_flip_tasks,
        "coding_check": {
            "coders": 2,
            "coder_a": "blocked_calls == 0 / > 0 / Missing",
            "coder_b": "record presence via gate_calls and iterations, then blocked count",
            "disagreements": disagreements,
        },
        "bounds": {
            "identified_lower": lower,
            "identified_upper": upper,
            "naive_upper": len(rows),
            "width_flips": upper - lower,
            "width_fraction": round((upper - lower) / len(rows), 4),
            "assumptions": [
                "A flip with a zero-intervention record is not caused by gate blocking.",
                "No assumption is made about the six unrecorded cells; they may "
                "have blocked or not.",
                "The 80 paired cells are the complete paired set for this run.",
            ],
            "cluster_conditional": cluster_conditional,
            "rejected": {
                "upper": len(rows),
                "reason": "It attributes the three zero-intervention flips to "
                          "the gate, contradicting their records.",
            },
        },
        "not_claimed": [
            "The bounds are on records, not on a fresh causal measurement.",
            "The six gate-consistent flips are post-hoc provenance, not a "
            "controlled intervention.",
            "No claim that the unrecorded cells are missing at random.",
            "No claim about cells outside this 80-cell paired run.",
        ],
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=1), encoding="utf-8")

    lines = [
        "# E07/E08 — Flip forensics and attribution bounds",
        "",
        "Source: the post-hoc fused attribution for the 80-cell paired live run.",
        f"`derived = {result['provenance']['derived']}`; the file states it is "
        "not a measurement. No model calls.",
        "",
        "## Fifteen flips",
        "",
        "| cell | A/B | blocked | gate calls | class | evidence |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['cell']} | T/F | "
            f"{'--' if row['blocked_calls'] is None else row['blocked_calls']} | "
            f"{'--' if row['gate_calls'] is None else row['gate_calls']} | "
            f"{row['class']} | {row['evidence']} |")
    lines += [
        "",
        f"Classes: {gate_consistent} gate-consistent, {zero_intervention} "
        f"zero-intervention, {unrecorded} unrecorded.",
        f"Unrecorded cells by user task: "
        f"{', '.join(f'{task} ({count})' for task, count in sorted(unmapped_by_task.items()))}. "
        f"All unrecorded flips are in {', '.join(unrecorded_flip_tasks)}.",
        "",
        "## Bound",
        "",
        "Assumption: a flip with a zero-intervention record cannot have been "
        "caused by gate blocking. With no assumption about the unrecorded "
        "cells, the number of gate-attributable flips lies in "
        f"**[{lower}, {upper}]** of {len(rows)}; the naive upper bound of "
        f"{len(rows)} is rejected because it counts the three zero-intervention "
        "flips as gate effects.",
        "",
        f"The width is {upper - lower} flips "
        f"({100 * (upper - lower) / len(rows):.0f} percent of the fifteen). "
        f"Under within-task homogeneity in {unrecorded_flip_tasks[0]}, the "
        f"attainable counts are only {cluster_conditional['values'][0]} or "
        f"{cluster_conditional['values'][1]}, not every integer in between; "
        "that assumption is reported but not used for the primary bound.",
        "",
        "## Coverage",
        "",
        f"{data['coverage']['cells_with_attribution']} of "
        f"{data['coverage']['paired_attack_cells']} paired attack cells have a "
        f"gate-side record; {data['coverage']['cells_without_attribution']} do "
        "not. The missing cells are not missing at random with respect to user "
        "task: they cluster in three tasks.",
        "",
        "## What is not claimed",
        "",
        *[f"- {item}" for item in result["not_claimed"]],
        "",
        "Reproduce: `python experiments/attribution/flip_forensics.py`",
    ]
    MD.parent.mkdir(parents=True, exist_ok=True)
    MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT).as_posix()} and {MD.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
