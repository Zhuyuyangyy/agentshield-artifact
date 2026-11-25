"""Clustered uncertainty for the paired contrasts of Study 1 (EXP-01).

The frozen replay gives one decision per trace under four rules, so every
contrast is paired at the trace level. The cell-level bootstrap treats traces
as independent, which is optimistic: traces share user tasks and injection
tasks. This script reports four intervals for the same point estimate:

  cell          resample traces with replacement
  user          resample suite|user_task clusters
  injection     resample suite|injection_task clusters (attack only)
  two-way       Cameron-Gelbach-Miller sandwich, user + injection - intersection

It also reports the benign review-step-rate contrast, where the resampling unit
carries a step weight.

Reads benchmark/results/e2b_trajectory_outcomes.jsonl (frozen; no model calls).
Writes experiments/statistics/results/clustered_bootstrap.json.

Run:
    python experiments/statistics/clustered_bootstrap.py
"""

from __future__ import annotations

import json
import math
import random
from collections import defaultdict
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[2]
OUTCOMES = ROOT / "benchmark" / "results" / "e2b_trajectory_outcomes.jsonl"
OUT = ROOT / "experiments" / "statistics" / "results" / "clustered_bootstrap.json"

B = 2000
SEEDS = {"cell": 20261123, "user": 20261124, "injection": 20261125}
Z95 = 1.959963984540054


def load_rows() -> List[dict]:
    with OUTCOMES.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]


def split(row: dict) -> Tuple[str, str, str]:
    parts = row["trajectory"].split("|")
    return parts[0], parts[1], parts[2]


def user_key(row: dict) -> str:
    suite, user, _ = split(row)
    return f"{suite}|{user}"


def injection_key(row: dict) -> str:
    suite, _, injection = split(row)
    return f"{suite}|{injection}"


def _percentile(values: Sequence[float], pct: float) -> float:
    ordered = sorted(values)
    index = (len(ordered) - 1) * pct
    low = math.floor(index)
    high = math.ceil(index)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (index - low)


def _ci(values: Sequence[float]) -> List[float]:
    return [round(_percentile(values, 0.025), 4),
            round(_percentile(values, 0.975), 4)]


def _units(rows: Iterable[dict], value_fn: Callable[[dict], float],
           weight_fn: Callable[[dict], float]) -> List[Tuple[float, float]]:
    return [(value_fn(row), weight_fn(row)) for row in rows]


def _clusters(rows: Iterable[dict], key_fn: Callable[[dict], str],
              value_fn: Callable[[dict], float],
              weight_fn: Callable[[dict], float]) -> List[Tuple[float, float]]:
    buckets: Dict[str, List[float]] = defaultdict(lambda: [0.0, 0.0])
    for row in rows:
        bucket = buckets[key_fn(row)]
        bucket[0] += value_fn(row)
        bucket[1] += weight_fn(row)
    return [(value, weight) for value, weight in buckets.values()]


def _ratio(units: Sequence[Tuple[float, float]]) -> float:
    weight = sum(w for _, w in units)
    return 100.0 * sum(v for v, _ in units) / weight if weight else 0.0


def _bootstrap(units: Sequence[Tuple[float, float]], seed: int) -> List[float]:
    rng = random.Random(seed)
    n = len(units)
    return [_ratio([units[rng.randrange(n)] for _ in range(n)])
            for _ in range(B)]


def _bootstrap_clusters(units: Sequence[Tuple[float, float]],
                        seed: int) -> List[float]:
    rng = random.Random(seed)
    n = len(units)
    return [_ratio([units[rng.randrange(n)] for _ in range(n)])
            for _ in range(B)]


def _cgm(rows: Sequence[dict], value_fn: Callable[[dict], float],
         key_fn: Callable[[dict], str]) -> float:
    """Cluster-robust variance of a mean difference (CGM one-way)."""
    values = [value_fn(row) for row in rows]
    n = len(values)
    mean = sum(values) / n
    scores: Dict[str, float] = defaultdict(float)
    for row, value in zip(rows, values):
        scores[key_fn(row)] += value - mean
    groups = len(scores)
    if groups < 2:
        return 0.0
    variance = (groups / (groups - 1)) * sum(s * s for s in scores.values()) / n ** 2
    return variance


def _cgm_two_way(rows: Sequence[dict], value_fn: Callable[[dict], float]) -> float:
    variance = _cgm(rows, value_fn, user_key) + _cgm(rows, value_fn, injection_key)
    intersection = _cgm(rows, value_fn, lambda row: row["trajectory"])
    return max(0.0, variance - intersection)


def _block_value(rule_a: str, rule_b: str, policy: str) -> Callable[[dict], float]:
    def value(row: dict) -> float:
        left = 1.0 if row["blocked"][rule_a][policy] else 0.0
        right = 1.0 if row["blocked"][rule_b][policy] else 0.0
        return left - right
    return value


def _review_value(rule_a: str, rule_b: str) -> Callable[[dict], float]:
    def value(row: dict) -> float:
        return float(row["review_steps"][rule_a] - row["review_steps"][rule_b])
    return value


def _one_contrast(rows: Sequence[dict], value_fn: Callable[[dict], float],
                  weight_fn: Callable[[dict], float],
                  clusters: Sequence[str]) -> dict:
    cell_units = _units(rows, value_fn, weight_fn)
    point = _ratio(cell_units)
    result = {
        "n_traces": len(rows),
        "n_user_clusters": len({user_key(row) for row in rows}),
        "n_injection_clusters": len({injection_key(row) for row in rows}),
        "point_pp": round(point, 4),
        "cell_ci95": _ci(_bootstrap(cell_units, SEEDS["cell"])),
    }
    user_units = _clusters(rows, user_key, value_fn, weight_fn)
    result["user_cluster_ci95"] = _ci(
        _bootstrap_clusters(user_units, SEEDS["user"]))
    if "injection" in clusters:
        injection_units = _clusters(rows, injection_key, value_fn, weight_fn)
        result["injection_cluster_ci95"] = _ci(
            _bootstrap_clusters(injection_units, SEEDS["injection"]))
        variance = _cgm_two_way(rows, value_fn)
        half = Z95 * math.sqrt(variance) * 100.0
        result["twoway_ci95"] = [round(point - half, 4), round(point + half, 4)]
    return result


def main() -> int:
    rows = load_rows()
    attack = [row for row in rows if row["label"] == "attack"]
    benign = [row for row in rows if row["label"] == "benign"]

    contrasts = {}
    for name, rule_a, rule_b, policy in [
        ("band_minus_hard|block", "band_split", "hard_first", "block"),
        ("band_minus_global|block", "band_split", "global_cap", "block"),
        ("band_minus_hard|log_and_allow", "band_split", "hard_first",
         "log_and_allow"),
    ]:
        value = _block_value(rule_a, rule_b, policy)
        contrasts[name] = {
            "attack": _one_contrast(attack, value, lambda row: 1.0,
                                     ("injection",)),
            "benign": _one_contrast(benign, value, lambda row: 1.0, ()),
        }

    review_value = _review_value("band_split", "hard_first")
    contrasts["review_step_rate|block"] = {
        "benign": _one_contrast(
            benign, review_value, lambda row: float(row["steps"]), ())
    }

    result = {
        "experiment": "EXP-01 clustered uncertainty",
        "method": {
            "cell": "paired trace bootstrap",
            "user": "bootstrap over suite|user_task clusters",
            "injection": "bootstrap over suite|injection_task clusters",
            "two_way": "Cameron-Gelbach-Miller sandwich",
            "bootstrap_draws": B,
            "seeds": SEEDS,
            "interval": "percentile 2.5-97.5 for bootstrap; normal 95% for two-way",
        },
        "source": {
            "path": "benchmark/results/e2b_trajectory_outcomes.jsonl",
            "sha256": "46260b678f4afb21cd595ccbac02d72c08c6b780d141054f5eab62c41f1eb643",
        },
        "contrasts": contrasts,
        "notes": [
            "Attack unit is a trace; benign review contrast is step-weighted.",
            "Benign traces have no injection task, so injection clustering is omitted.",
            "All contrasts preserve the A/B pairing because every trace carries both rules.",
        ],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT).as_posix()}")
    for name, groups in contrasts.items():
        for label, values in groups.items():
            print(f"{name:38s} {label:7s} {values['point_pp']:+.3f} pp  "
                  f"cell {values['cell_ci95']}  user {values['user_cluster_ci95']}"
                  + (f"  inj {values['injection_cluster_ci95']}"
                     if "injection_cluster_ci95" in values else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
