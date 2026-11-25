"""P2-B: recompute the governance metrics under three sampling frames.

Input is the per-trajectory outcome file written by
``benchmark/e2b_review_policy_replay.py``. That file is bulk (about 4.8 MB) and
is not shipped; it is regenerated in about twenty seconds from the frozen dump.
What ships is this analysis: the sampling-frame comparison, the bootstrap
intervals and the rule rankings.

Frames
------
full            all 10,439 attack and 97 benign trajectories
published_prefix the first 400 attack trajectories (the frame the frozen Pareto
                ladder used) plus all benign trajectories
random_400      1,000 seeded draws of 400 attack trajectories, benign fixed

Metrics per rule and policy
---------------------------
attack_trace_block_rate   share of attack trajectories with at least one block
                          (or one review, when the policy blocks reviews)
benign_trace_block_rate   same over benign trajectories
benign_review_step_rate   review steps / benign steps

The bootstrap resamples trajectories, not steps, because the unit of analysis
is the trajectory. It is seeded, and the seed and numpy version are recorded.

Usage
-----
    python benchmark/e2b_review_policy_replay.py   # writes the outcomes file
    python benchmark/measurement_reanalysis.py
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
OUTCOMES = ROOT / "benchmark" / "results" / "e2b_trajectory_outcomes.jsonl"
OUT = ROOT / "benchmark" / "results" / "measurement_reanalysis.json"

RULES = ("no_relaxation", "global_cap", "band_split", "hard_first")
POLICIES = ("log_and_allow", "block")
ATTACK_SUBSET = 400
N_RANDOM = 1000
N_BOOT = 2000
SEED = 20261123


def _load() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    attack: List[Dict[str, Any]] = []
    benign: List[Dict[str, Any]] = []
    for line in OUTCOMES.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        (attack if row["label"] == "attack" else benign).append(row)
    attack.sort(key=lambda row: row["index"])
    benign.sort(key=lambda row: row["index"])
    return attack, benign


def _arrays(rows: List[Dict[str, Any]], rule: str, policy: str):
    blocked = np.array([row["blocked"][rule][policy] for row in rows], dtype=bool)
    return blocked


def _benign_arrays(rows: List[Dict[str, Any]], rule: str):
    steps = np.array([row["steps"] for row in rows], dtype=np.float64)
    reviews = np.array([row["review_steps"][rule] for row in rows], dtype=np.float64)
    return steps, reviews


def _frame_metrics(
    attack: List[Dict[str, Any]],
    benign: List[Dict[str, Any]],
    bootstrap: bool,
    rng: np.random.Generator,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    n_a, n_b = len(attack), len(benign)
    if n_a == 0 or n_b == 0:
        return out
    attack_arrays = {
        (rule, policy): _arrays(attack, rule, policy)
        for rule in RULES for policy in POLICIES
    }
    benign_blocked = {
        (rule, policy): _arrays(benign, rule, policy)
        for rule in RULES for policy in POLICIES
    }
    benign_steps = {
        rule: _benign_arrays(benign, rule) for rule in RULES
    }

    boot_a = {key: [] for key in attack_arrays}
    boot_b = {key: [] for key in benign_blocked}
    boot_review = {rule: [] for rule in RULES}
    if bootstrap:
        for _ in range(N_BOOT):
            ia = rng.integers(0, n_a, n_a)
            ib = rng.integers(0, n_b, n_b)
            for key, arr in attack_arrays.items():
                boot_a[key].append(float(arr[ia].mean()))
            for key, arr in benign_blocked.items():
                boot_b[key].append(float(arr[ib].mean()))
            for rule in RULES:
                steps, reviews = benign_steps[rule]
                boot_review[rule].append(
                    float(reviews[ib].sum() / steps[ib].sum())
                    if steps[ib].sum() else 0.0)

    def _ci(values: List[float]) -> List[float]:
        if not values:
            return []
        return [round(float(np.percentile(values, 2.5)), 5),
                round(float(np.percentile(values, 97.5)), 5)]

    for rule in RULES:
        for policy in POLICIES:
            key = (rule, policy)
            steps, reviews = benign_steps[rule]
            out[f"{rule}|{policy}"] = {
                "attack_trace_block_rate": round(float(attack_arrays[key].mean()), 5),
                "attack_trace_block_rate_ci95": _ci(boot_a[key]),
                "benign_trace_block_rate": round(float(benign_blocked[key].mean()), 5),
                "benign_trace_block_rate_ci95": _ci(boot_b[key]),
                "benign_review_step_rate": round(
                    float(reviews.sum() / steps.sum()), 5) if steps.sum() else 0.0,
                "benign_review_step_rate_ci95": _ci(boot_review[rule]),
            }
    return out


def _contrasts(
    attack: List[Dict[str, Any]],
    benign: List[Dict[str, Any]],
    rng: np.random.Generator,
) -> Dict[str, Any]:
    """Paired bootstrap for the differences between two rules.

    The two rules see the same trajectories, so the difference must be
    resampled jointly; comparing marginal intervals would overstate the
    uncertainty of the contrast.
    """
    out: Dict[str, Any] = {}
    n_a, n_b = len(attack), len(benign)
    for policy in POLICIES:
        for left, right in (("band_split", "hard_first"),
                            ("band_split", "global_cap")):
            a_left = _arrays(attack, left, policy)
            a_right = _arrays(attack, right, policy)
            b_left = _arrays(benign, left, policy)
            b_right = _arrays(benign, right, policy)
            steps, rev_left = _benign_arrays(benign, left)
            _, rev_right = _benign_arrays(benign, right)
            diffs_attack: List[float] = []
            diffs_benign: List[float] = []
            diffs_review: List[float] = []
            for _ in range(N_BOOT):
                ia = rng.integers(0, n_a, n_a)
                ib = rng.integers(0, n_b, n_b)
                diffs_attack.append(
                    float(a_left[ia].mean() - a_right[ia].mean()))
                diffs_benign.append(
                    float(b_left[ib].mean() - b_right[ib].mean()))
                denom = steps[ib].sum()
                diffs_review.append(
                    float((rev_left[ib].sum() - rev_right[ib].sum()) / denom)
                    if denom else 0.0)

            def _interval(values: List[float]) -> List[float]:
                return [round(float(np.percentile(values, 2.5)), 5),
                        round(float(np.percentile(values, 97.5)), 5)]

            out[f"{left}_minus_{right}|{policy}"] = {
                "attack_trace_block_rate_delta": round(
                    float(a_left.mean() - a_right.mean()), 5),
                "attack_trace_block_rate_delta_ci95": _interval(diffs_attack),
                "benign_trace_block_rate_delta": round(
                    float(b_left.mean() - b_right.mean()), 5),
                "benign_trace_block_rate_delta_ci95": _interval(diffs_benign),
                "benign_review_step_rate_delta": round(
                    float(rev_left.sum() / steps.sum()
                          - rev_right.sum() / steps.sum()), 5)
                if steps.sum() else 0.0,
                "benign_review_step_rate_delta_ci95": _interval(diffs_review),
            }
    return out


def _rankings(metrics: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for policy in POLICIES:
        attack_order = sorted(
            RULES,
            key=lambda rule: (-metrics[f"{rule}|{policy}"]["attack_trace_block_rate"],
                              metrics[f"{rule}|{policy}"]["benign_trace_block_rate"],
                              rule),
        )
        benign_order = sorted(
            RULES,
            key=lambda rule: (metrics[f"{rule}|{policy}"]["benign_trace_block_rate"],
                              -metrics[f"{rule}|{policy}"]["attack_trace_block_rate"],
                              rule),
        )
        out[policy] = {
            "by_attack_block_desc": attack_order,
            "by_benign_block_asc": benign_order,
        }
    return out


def main() -> int:
    attack, benign = _load()
    rng = np.random.default_rng(SEED)

    full = _frame_metrics(attack, benign, bootstrap=True, rng=rng)
    prefix_attack = [row for row in attack if row["index"] < ATTACK_SUBSET]
    prefix = _frame_metrics(prefix_attack, benign, bootstrap=True, rng=rng)
    contrasts_rng = np.random.default_rng(SEED + 1)
    contrasts = {
        "full": _contrasts(attack, benign, contrasts_rng),
        "published_prefix": _contrasts(prefix_attack, benign, contrasts_rng),
    }

    random_rates: Dict[str, List[float]] = {
        f"{rule}|{policy}": [] for rule in RULES for policy in POLICIES
    }
    n_a = len(attack)
    for _ in range(N_RANDOM):
        idx = rng.choice(n_a, size=ATTACK_SUBSET, replace=False)
        sample = [attack[i] for i in idx]
        for rule in RULES:
            for policy in POLICIES:
                arr = _arrays(sample, rule, policy)
                random_rates[f"{rule}|{policy}"].append(float(arr.mean()))

    random_summary: Dict[str, Any] = {}
    for key, values in random_rates.items():
        prefix_value = prefix[key]["attack_trace_block_rate"]
        arr = np.array(values)
        random_summary[key] = {
            "min": round(float(arr.min()), 5),
            "p2_5": round(float(np.percentile(arr, 2.5)), 5),
            "median": round(float(np.median(arr)), 5),
            "p97_5": round(float(np.percentile(arr, 97.5)), 5),
            "max": round(float(arr.max()), 5),
            "prefix_value": prefix_value,
            "prefix_percentile_rank": round(
                float((arr <= prefix_value).mean()), 5),
        }

    payload = {
        "experiment": "measurement_reanalysis",
        "tier": "offline_sampling_and_semantics",
        "source": OUTCOMES.relative_to(ROOT).as_posix(),
        "source_sha256": hashlib.sha256(
            OUTCOMES.read_bytes().replace(b"\r\n", b"\n")).hexdigest(),
        "source_rows": {
            "attack": len(attack),
            "benign": len(benign),
            "total": len(attack) + len(benign),
        },
        "parameters": {
            "attack_subset": ATTACK_SUBSET,
            "random_subsets": N_RANDOM,
            "bootstrap_draws": N_BOOT,
            "seed": SEED,
        },
        "frames": {
            "full": full,
            "published_prefix": prefix,
        },
        "random_400": random_summary,
        "contrasts": contrasts,
        "rankings": {
            "full": _rankings(full),
            "published_prefix": _rankings(prefix),
        },
        "environment": {
            "python": platform.python_version(),
            "numpy": np.__version__,
        },
        "not_measured": [
            "task success after a block",
            "utility under governance",
            "end-to-end ASR",
        ],
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                   encoding="utf-8", newline="\n")

    print(f"wrote {OUT.relative_to(ROOT)}")
    print(f"  rows: {len(attack)} attack, {len(benign)} benign")
    for policy in POLICIES:
        print(f"  policy={policy}: full / prefix / random400 median")
        for rule in RULES:
            key = f"{rule}|{policy}"
            print(f"    {rule:14s} atk "
                  f"{full[key]['attack_trace_block_rate']:.4f} / "
                  f"{prefix[key]['attack_trace_block_rate']:.4f} / "
                  f"{random_summary[key]['median']:.4f}   "
                  f"ben {full[key]['benign_trace_block_rate']:.4f} / "
                  f"{prefix[key]['benign_trace_block_rate']:.4f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
