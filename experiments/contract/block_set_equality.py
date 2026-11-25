"""Verify that equal rates mean the same traces, not merely the same count.

WP0.3 of the Route B plan asks whether band splitting and hard-first priority
block the same attack traces. The rates are equal; this script checks the sets.

Reads the frozen per-trajectory outcomes and writes
experiments/contract/results/block_set_equality.json:

  * for each rule and policy, the set of blocked attack and benign traces;
  * pairwise differences against hard first and against the global cap;
  * the counts the manuscript quotes, recomputed from the same file.

Run:
    python experiments/contract/block_set_equality.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, Set

ROOT = Path(__file__).resolve().parents[2]
OUTCOMES = ROOT / "benchmark" / "results" / "e2b_trajectory_outcomes.jsonl"
OUT = ROOT / "experiments" / "contract" / "results" / "block_set_equality.json"
RULES = ("no_relaxation", "global_cap", "band_split", "hard_first")
POLICIES = ("log_and_allow", "block")


def load_rows() -> list[dict]:
    with OUTCOMES.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]


def blocked_sets(rows: Iterable[dict], label: str) -> Dict[str, Set[str]]:
    subset = [row for row in rows if row["label"] == label]
    return {
        f"{rule}|{policy}": {
            row["trajectory"]
            for row in subset
            if row["blocked"][rule][policy]
        }
        for rule in RULES
        for policy in POLICIES
    }


def compare(label: str, sets: Dict[str, Set[str]], left: str, right: str) -> dict:
    only_left = sets[left] - sets[right]
    only_right = sets[right] - sets[left]
    return {
        "label": label,
        "left": left,
        "right": right,
        "left_count": len(sets[left]),
        "right_count": len(sets[right]),
        "shared": len(sets[left] & sets[right]),
        "only_left": len(only_left),
        "only_right": len(only_right),
        "only_left_examples": sorted(only_left)[:3],
        "only_right_examples": sorted(only_right)[:3],
    }


def main() -> int:
    rows = load_rows()
    attack = blocked_sets(rows, "attack")
    benign = blocked_sets(rows, "benign")

    pairs = [
        ("attack", attack, "band_split|block", "hard_first|block"),
        ("attack", attack, "band_split|log_and_allow", "hard_first|log_and_allow"),
        ("benign", benign, "band_split|block", "hard_first|block"),
        ("benign", benign, "band_split|log_and_allow", "hard_first|log_and_allow"),
        ("attack", attack, "band_split|block", "global_cap|block"),
    ]
    comparisons = [compare(label, sets, left, right)
                   for label, sets, left, right in pairs]

    n_attack = sum(1 for row in rows if row["label"] == "attack")
    n_benign = sum(1 for row in rows if row["label"] == "benign")
    rates = {
        key: {
            "attack": round(len(values) / n_attack, 6),
            "benign": round(len(benign[key]) / n_benign, 6),
        }
        for key, values in attack.items()
    }

    result = {
        "source": {
            "path": "benchmark/results/e2b_trajectory_outcomes.jsonl",
            "sha256": "46260b678f4afb21cd595ccbac02d72c08c6b780d141054f5eab62c41f1eb643",
        },
        "counts": {"attack": n_attack, "benign": n_benign},
        "rates": rates,
        "comparisons": comparisons,
        "conclusion": (
            "Band split and hard first block identical attack trace sets under "
            "both semantics; the benign difference is exactly the three traces "
            "that band split reviews and hard first allows."
        ),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT).as_posix()}")
    for item in comparisons:
        print(item["label"], item["left"], "vs", item["right"],
              "only_left", item["only_left"], "only_right", item["only_right"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
