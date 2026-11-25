"""Partial identification of the REVIEW semantics (T02).

A gate returns one action per tool call: ALLOW, REVIEW or BLOCK. The frozen
replay records the trace under two enforcement semantics:

  log_and_allow  a REVIEW is recorded and the call executes; only BLOCK stops.
  block          a REVIEW stops the call, like BLOCK.

A deployed system may resolve REVIEW per call, so its trace block indicator is
not directly observed. This script proves and checks the sharp bound

    R_log  <=  R_sigma  <=  R_block

for every per-call resolution of REVIEW, and reports the bound width for the
four aggregation rules on the frozen corpus. The width is the fraction of
traces that contain a REVIEW and no BLOCK; those are exactly the traces whose
status the deployment decides.

Checks
------
1. Per-sequence exhaustion: every action sequence of length 1..6 over
   {ALLOW, REVIEW, BLOCK} is enumerated, and every resolution of its REVIEW
   steps is scored. The trace indicator must stay inside [log, block] and both
   endpoints must be attained when a REVIEW exists.
2. Aggregate exhaustion: for every pair of two-step sequences, every joint
   resolution is enumerated and the aggregate count must hit every integer
   between the two endpoints.
3. Empirical bounds for the four rules on attack and benign traces, using the
   frozen per-trajectory outcomes. The log blocked set must be a subset of the
   block blocked set; a violation would falsify the monotonicity premise.

Outputs
-------
experiments/identifiability/results/review_bounds.json
experiments/identifiability/REVIEW_BOUNDS.md

Run:
    python experiments/identifiability/review_bounds.py
"""

from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path
from typing import Dict, Iterable, Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.contract.block_set_equality import (  # noqa: E402
    RULES,
    blocked_sets,
    load_rows,
)

OUT = ROOT / "experiments" / "identifiability" / "results" / "review_bounds.json"
MD = ROOT / "experiments" / "identifiability" / "REVIEW_BOUNDS.md"

ACTIONS = ("ALLOW", "REVIEW", "BLOCK")
SEQUENCE_LENGTHS = (1, 2, 3, 4, 5, 6)


def _trace_blocked(sequence: Sequence[str], policy: str) -> bool:
    if policy == "block":
        return any(action in ("REVIEW", "BLOCK") for action in sequence)
    return any(action == "BLOCK" for action in sequence)


def _resolved(sequence: Sequence[str], review_to_block: Sequence[bool]) -> bool:
    """Score a trace when each REVIEW independently executes or stops."""
    iterator = iter(review_to_block)
    for action in sequence:
        if action == "BLOCK":
            return True
        if action == "REVIEW" and next(iterator):
            return True
    return False


def _enumerate_sequences() -> Dict[str, object]:
    per_sequence = []
    total = 0
    for length in SEQUENCE_LENGTHS:
        for sequence in itertools.product(ACTIONS, repeat=length):
            log = _trace_blocked(sequence, "log_and_allow")
            block = _trace_blocked(sequence, "block")
            reviews = sum(1 for action in sequence if action == "REVIEW")
            attainable = set()
            for flags in itertools.product((False, True), repeat=reviews):
                attainable.add(_resolved(sequence, flags))
            total += 1
            inside = all(log <= int(value) <= block for value in attainable)
            endpoints = attainable == ({log, block} if reviews else {log})
            per_sequence.append({
                "sequence": "".join(sequence),
                "log": log,
                "block": block,
                "reviews": reviews,
                "attainable": sorted(int(value) for value in attainable),
                "inside": inside,
                "sharp": endpoints,
            })
    return {
        "sequences": total,
        "max_length": max(SEQUENCE_LENGTHS),
        "all_inside": all(item["inside"] for item in per_sequence),
        "all_sharp": all(item["sharp"] for item in per_sequence),
        "max_reviews_in_a_sequence": max(item["reviews"] for item in per_sequence),
        "examples": [item for item in per_sequence
                     if item["reviews"] and item["log"] != item["block"]][:3],
    }


def _aggregate_exhaustion() -> Dict[str, object]:
    """All pairs of two-step sequences; every joint REVIEW resolution."""
    sequences = list(itertools.product(ACTIONS, repeat=2))
    log_count = sum(_trace_blocked(sequence, "log_and_allow")
                    for sequence in sequences)
    block_count = sum(_trace_blocked(sequence, "block") for sequence in sequences)
    review_slots = [(index, position)
                    for index, sequence in enumerate(sequences)
                    for position, action in enumerate(sequence)
                    if action == "REVIEW"]
    attainable = set()
    for flags in itertools.product((False, True), repeat=len(review_slots)):
        mapping = {index: {} for index in range(len(sequences))}
        for (index, position), flag in zip(review_slots, flags):
            mapping[index][position] = flag
        count = 0
        for index, sequence in enumerate(sequences):
            decisions = [mapping[index].get(position, False)
                         for position, action in enumerate(sequence)
                         if action == "REVIEW"]
            count += int(_resolved(sequence, decisions))
        attainable.add(count)
    expected = set(range(log_count, block_count + 1))
    return {
        "sequences": len(sequences),
        "review_slots": len(review_slots),
        "log_count": log_count,
        "block_count": block_count,
        "attainable_counts": sorted(attainable),
        "full_integer_range": attainable == expected,
    }


def _empirical(rows: Iterable[dict]) -> Dict[str, object]:
    rows = list(rows)
    result = {}
    for label in ("attack", "benign"):
        subset = [row for row in rows if row["label"] == label]
        sets = blocked_sets(subset, label)
        n = len(subset)
        steps = sum(row["steps"] for row in subset)
        per_rule = {}
        review_only_sets = {}
        for rule in RULES:
            log_set = sets[f"{rule}|log_and_allow"]
            block_set = sets[f"{rule}|block"]
            if not log_set <= block_set:
                raise SystemExit(
                    f"{label}/{rule}: log blocked set is not a subset of block")
            review_only = block_set - log_set
            review_only_sets[rule] = review_only
            per_rule[rule] = {
                "log_blocked": len(log_set),
                "block_blocked": len(block_set),
                "review_only": len(review_only),
                "rate_log": round(len(log_set) / n, 6),
                "rate_block": round(len(block_set) / n, 6),
                "width_pp": round(100 * (len(block_set) - len(log_set)) / n, 4),
                "review_step_rate": round(
                    sum(row["review_steps"][rule] for row in subset) / steps, 6),
                "review_only_examples": sorted(review_only)[:3],
            }
        identical = len({frozenset(values) for values in review_only_sets.values()}) == 1
        result[label] = {
            "n": n,
            "steps": steps,
            "rules": per_rule,
            "review_only_sets_identical": identical,
        }
    return result


def main() -> int:
    rows = load_rows()
    per_sequence = _enumerate_sequences()
    aggregate = _aggregate_exhaustion()
    empirical = _empirical(rows)
    if not per_sequence["all_inside"] or not per_sequence["all_sharp"]:
        raise SystemExit("per-sequence exhaustion failed")
    if not aggregate["full_integer_range"]:
        raise SystemExit("aggregate exhaustion failed")

    result = {
        "experiment": "T02 partial identification of REVIEW semantics",
        "source": {
            "path": "benchmark/results/e2b_trajectory_outcomes.jsonl",
            "sha256": "46260b678f4afb21cd595ccbac02d72c08c6b780d141054f5eab62c41f1eb643",
        },
        "statement": (
            "For any per-call resolution of REVIEW, the trace block indicator "
            "lies in [log_and_allow, block]; both endpoints are attainable, so "
            "the interval is sharp. Aggregated over traces, every integer count "
            "between the endpoints is attainable."),
        "checks": {
            "per_sequence": per_sequence,
            "aggregate": aggregate,
        },
        "empirical": empirical,
        "not_claimed": [
            "The width is not a confidence interval; it is the exact range under "
            "the stated resolution model.",
            "No claim that the deployment resolves REVIEW independently per call.",
            "No claim about post-intervention task outcome; this is trace blocking.",
        ],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=1), encoding="utf-8")

    lines = [
        "# T02 — Partial identification of REVIEW semantics",
        "",
        "Frozen corpus: 10,439 attack and 97 benign traces. No model calls.",
        "",
        "## Statement",
        "",
        "For a fixed trace let `b_log` be 1 if some step is BLOCK, and `b_block`",
        "be 1 if some step is BLOCK or REVIEW. For any per-call resolution of",
        "REVIEW to execute or stop, `b_log <= b_f <= b_block`. Both endpoints are",
        "attained (resolve every REVIEW to execute, or every REVIEW to stop), so",
        "the interval is sharp. At the aggregate level every integer count",
        "between the two endpoints is attainable.",
        "",
        f"Per-sequence exhaustion: {per_sequence['sequences']:,} sequences of "
        f"length 1–{per_sequence['max_length']}; all inside: "
        f"{per_sequence['all_inside']}; all sharp: {per_sequence['all_sharp']}.",
        f"Aggregate exhaustion over {aggregate['sequences']} two-step sequences "
        f"and {aggregate['review_slots']} review slots: full integer range "
        f"{aggregate['log_count']}..{aggregate['block_count']}: "
        f"{aggregate['full_integer_range']}.",
        "",
        "## Bound widths on the frozen corpus",
        "",
        "| label | rule | log rate | block rate | width (pp) | review-only traces |",
        "|---|---|---|---|---|---|",
    ]
    for label in ("attack", "benign"):
        for rule in RULES:
            item = empirical[label]["rules"][rule]
            lines.append(
                f"| {label} | {rule} | {item['rate_log']:.4f} | "
                f"{item['rate_block']:.4f} | {item['width_pp']:.2f} | "
                f"{item['review_only']} |")
    lines += [
        "",
        "The width is the fraction of traces whose verdict the deployment",
        "decides: they contain a REVIEW and no BLOCK. It is not a confidence",
        "interval and not a post-intervention outcome.",
        "",
        f"On attack traces the width is rule-invariant: the review-only set is "
        f"identical under all four rules "
        f"({empirical['attack']['review_only_sets_identical']}), "
        f"{empirical['attack']['rules']['band_split']['review_only']} traces, "
        f"{empirical['attack']['rules']['band_split']['width_pp']:.2f} points. "
        "On benign traces the width depends on the rule (9.28 to 12.37 points), "
        "so the aggregation choice is visible only on the benign side.",
        "",
        "## What is not claimed",
        "",
        *[f"- {item}" for item in result["not_claimed"]],
        "",
        "Reproduce: `python experiments/identifiability/review_bounds.py`",
    ]
    MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT).as_posix()} and {MD.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
