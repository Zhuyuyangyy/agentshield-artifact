"""P2-C: external validity audit on the public AgentDojo run artifact.

This script performs no model calls. It reads the per-task JSON files that the
AgentDojo authors published under `runs/`, recomputes the aggregates in their
own results table, and then applies the four design parameters of the metric
contract (sampling frame, enforcement semantics, aggregation rule, attribution
source) to see which of them the independent artifact can even express.

What it can answer
------------------
RQ1 (sampling frame). Yes. The artifact stores one file per
(suite, user task, injection task, attack) cell, so a fixed subset can be
compared against the full population on the same cells and with the same arms.

RQ2 (enforcement semantics / risk aggregation). No. The artifact records only
the final `utility` and `security` booleans plus the message trace; there is no
per-step gate decision, no REVIEW state and no risk score. Any number produced
here would be a different construct.

RQ3 (gate attribution). No. There is no gate-side record to attribute a flip
to. The field inventory is reported so the absence is explicit rather than
assumed.

Privacy
-------
Only the scalar and provenance fields are read into the output. Message text
and the `injections` payloads are never copied into the result file; only
counts are written.

Usage
-----
    git clone --depth 1 --filter=blob:none --sparse \
        <agentdojo-repo> .tmp/agentdojo
    cd .tmp/agentdojo
    git sparse-checkout set \
        runs/gpt-4o-2024-05-13 \
        runs/gpt-4o-2024-05-13-tool_filter \
        runs/gpt-4o-2024-05-13-spotlighting_with_delimiting \
        runs/gpt-4o-2024-05-13-transformers_pi_detector \
        runs/gpt-4o-2024-05-13-repeat_user_prompt \
        runs/Meta-SecAlign-70B
    cd -

    python benchmark/external_validity_agentdojo.py \
        --artifact-commit <sha> --out benchmark/results/external_validity_agentdojo.json
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]

RUNS_DEFAULT = ROOT / ".tmp" / "agentdojo" / "runs"
OUT_DEFAULT = ROOT / "benchmark" / "results" / "external_validity_agentdojo.json"

# The five arms that share one task grid: the undefended gpt-4o run and the four
# official defenses. Each defence was run on `important_instructions` only.
ARMS = (
    "gpt-4o-2024-05-13",
    "gpt-4o-2024-05-13-tool_filter",
    "gpt-4o-2024-05-13-spotlighting_with_delimiting",
    "gpt-4o-2024-05-13-transformers_pi_detector",
    "gpt-4o-2024-05-13-repeat_user_prompt",
)
SHORT = {
    "gpt-4o-2024-05-13": "none",
    "gpt-4o-2024-05-13-tool_filter": "tool_filter",
    "gpt-4o-2024-05-13-spotlighting_with_delimiting": "spotlighting",
    "gpt-4o-2024-05-13-transformers_pi_detector": "pi_detector",
    "gpt-4o-2024-05-13-repeat_user_prompt": "repeat_user_prompt",
}
FOCUS_ATTACK = "important_instructions"
SECOND_RUN = "Meta-SecAlign-70B"

# `docs/results-table.html` at the same commit, fetched 2026-11-23. The
# published percentages are the numbers the audit is checking against; the
# SHA-256 pins the file they were read from.
PUBLISHED_TABLE = {
    "url": "<published-results-table>",
    "sha256": "bdd665fd32069666d3d89e2f54a9b6c12a38798f0e3824b5fe5b6488021d0925",
    "clean_utility_pct": {
        "none": 69.07,
        "tool_filter": 72.16,
        "spotlighting": 72.16,
        "pi_detector": 41.24,
        "repeat_user_prompt": 84.54,
    },
    "under_attack": {
        # (arm, attack) -> (utility under attack %, targeted ASR %)
        ("none", "important_instructions"): (50.08, 47.69),
        ("none", "ignore_previous"): (66.77, 5.41),
        ("none", "direct"): (67.25, 3.66),
        ("none", "injecagent"): (68.52, 5.72),
        ("none", "tool_knowledge"): (57.71, 34.50),
        ("tool_filter", "important_instructions"): (56.28, 6.84),
        ("spotlighting", "important_instructions"): (55.64, 41.65),
        ("pi_detector", "important_instructions"): (21.14, 7.95),
        ("repeat_user_prompt", "important_instructions"): (67.25, 27.82),
    },
}

CANDIDATE_DECISION_FIELDS = (
    "decision",
    "action",
    "gate",
    "review",
    "blocked",
    "intervention",
    "risk_score",
    "verdict",
)


def _pct(value: float) -> float:
    return round(100.0 * value, 3)


def _official(value: float) -> str:
    """Format exactly like `util_scripts/create_results_table.py`."""
    return f"{100.0 * value:.2f}"


def _matches(value: float, published_pct: float) -> bool:
    return _official(value) == f"{published_pct:.2f}"


def _portable_path(path: Path) -> str:
    """Record a repository-relative location, never a host path."""
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return "<checkout outside the repository>"


def _mean(values: Sequence[float]) -> float:
    return sum(values) / len(values)


def _interval(values: Sequence[float], low: float = 0.025,
              high: float = 0.975) -> Tuple[float, float]:
    ordered = sorted(values)
    return ordered[int(low * len(ordered))], ordered[int(high * len(ordered))]


def read_artifact(runs_root: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Walk the run tree once and keep only scalars plus field counts."""
    inventory: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "files": 0,
        "utility_cells": 0,
        "trivial_utility_cells": 0,
        "utility_true": 0,
        "trivial_utility_true": 0,
        "security_cells": Counter(),
        "suites": Counter(),
        "attacks": Counter(),
        "benchmark_versions": Counter(),
        "package_versions": Counter(),
        "pipeline_names": Counter(),
        "errors": 0,
    })
    top_keys: Counter[str] = Counter()
    # paired cells for the shared attack grid
    cell: Dict[Tuple[str, str, str], Dict[str, Tuple[bool, bool]]] = defaultdict(dict)
    # clean utility, keyed by (arm, suite, user task)
    clean: Dict[str, Dict[Tuple[str, str], bool]] = defaultdict(dict)
    # every attack cell of the undefended arm, for the aggregation-unit section
    undefended: Dict[str, Dict[Tuple[str, str, str], Tuple[bool, bool]]] = defaultdict(dict)
    decision_fields = Counter({name: 0 for name in CANDIDATE_DECISION_FIELDS})
    records = 0
    total_bytes = 0

    for path in sorted(runs_root.rglob("*.json")):
        rel = path.relative_to(runs_root).as_posix()
        arm = rel.split("/")[0]
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
        records += 1
        total_bytes += path.stat().st_size
        top_keys.update(data.keys())
        for name in CANDIDATE_DECISION_FIELDS:
            if name in data:
                decision_fields[name] += 1

        item = inventory[arm]
        item["files"] += 1
        if data.get("error"):
            item["errors"] += 1
        item["suites"][data.get("suite_name")] += 1
        item["benchmark_versions"][str(data.get("benchmark_version"))] += 1
        item["package_versions"][str(data.get("agentdojo_package_version"))] += 1
        item["pipeline_names"][str(data.get("pipeline_name"))] += 1

        attack = data.get("attack_type")
        if attack in (None, "none"):
            if data.get("injection_task_id") is None:
                # `none/none.json` exists both under `user_task_k/` and under
                # `injection_task_k/`. Only the first is a clean-utility cell;
                # the second runs the injection goal as a user prompt.
                if str(data.get("user_task_id")).startswith("injection_task"):
                    item["trivial_utility_cells"] += 1
                    item["trivial_utility_true"] += int(bool(data.get("utility")))
                else:
                    item["utility_cells"] += 1
                    item["utility_true"] += int(bool(data.get("utility")))
                    clean[arm][(data["suite_name"], data["user_task_id"])] = bool(
                        data.get("utility"))
            continue

        item["security_cells"][attack] += 1
        item["attacks"][attack] += 1
        if arm not in ARMS:
            continue
        key = (data["suite_name"], data["user_task_id"], data["injection_task_id"])
        if attack == FOCUS_ATTACK:
            cell[key][arm] = (bool(data.get("utility")), bool(data.get("security")))
        if arm == ARMS[0]:
            undefended[attack][key] = (
                bool(data.get("utility")), bool(data.get("security")))

    artifact = {
        "records": records,
        "bytes": total_bytes,
        "top_level_keys": dict(sorted(top_keys.items())),
        "decision_field_occurrences": dict(decision_fields),
        "inventory": {
            arm: {
                "files": item["files"],
                "utility_cells": item["utility_cells"],
                "trivial_utility_cells": item["trivial_utility_cells"],
                "utility_rate_corrected": (
                    round(item["utility_true"] / item["utility_cells"], 4)
                    if item["utility_cells"] else None),
                "utility_rate_naive": (
                    round((item["utility_true"] + item["trivial_utility_true"])
                          / (item["utility_cells"] + item["trivial_utility_cells"]), 4)
                    if (item["utility_cells"] + item["trivial_utility_cells"]) else None),
                "security_cells": dict(sorted(item["security_cells"].items())),
                "suites": dict(sorted(item["suites"].items())),
                "benchmark_versions": dict(item["benchmark_versions"]),
                "package_versions": dict(item["package_versions"]),
                "pipeline_names": dict(item["pipeline_names"]),
                "errors": item["errors"],
            }
            for arm, item in sorted(inventory.items())
        },
    }
    return artifact, {"cell": dict(cell), "clean": dict(clean),
                      "undefended": dict(undefended)}


def paired_keys(cell: Dict[Tuple[str, str, str], Dict[str, Tuple[bool, bool]]],
                arms: Iterable[str] = ARMS) -> List[Tuple[str, str, str]]:
    arms = tuple(arms)
    return sorted(key for key, value in cell.items() if len(value) == len(arms))


def asr(cell, keys: Sequence[Tuple[str, str, str]], arm: str) -> float:
    return _mean([1.0 if cell[key][arm][1] else 0.0 for key in keys])


def utility_under_attack(cell, keys, arm: str) -> float:
    return _mean([1.0 if cell[key][arm][0] else 0.0 for key in keys])


def frame_report(cell, keys, arms: Sequence[str]) -> Dict[str, Any]:
    return {
        "n": len(keys),
        "asr_pct": {arm: _pct(asr(cell, keys, arm)) for arm in arms},
        "utility_under_attack_pct": {
            arm: _pct(utility_under_attack(cell, keys, arm)) for arm in arms},
    }


def ranking(cell, keys, arms: Sequence[str]) -> List[str]:
    return sorted(arms, key=lambda arm: asr(cell, keys, arm))


def summarise(artifact: Dict[str, Any], data: Dict[str, Any], *,
              seed: int, boot: int, draws: int, subset: int) -> Dict[str, Any]:
    cell = data["cell"]
    clean = data["clean"]
    undefended = data["undefended"]
    keys = paired_keys(cell)
    if not keys:
        raise SystemExit("no paired cells: is the sparse checkout complete?")

    suites: Dict[str, List[Tuple[str, str, str]]] = defaultdict(list)
    for key in keys:
        suites[key[0]].append(key)

    repro_rows = []
    for (arm_label, attack), (pub_u, pub_s) in PUBLISHED_TABLE["under_attack"].items():
        arm = next(a for a in ARMS if SHORT[a] == arm_label)
        if attack == FOCUS_ATTACK:
            attack_keys = keys
            util_val = utility_under_attack(cell, attack_keys, arm)
            sec_val = asr(cell, attack_keys, arm)
        else:
            # only the undefended arm was run on the other attacks
            attack_keys = sorted(undefended[attack])
            util_val = _mean([1.0 if v[0] else 0.0
                              for v in undefended[attack].values()])
            sec_val = _mean([1.0 if v[1] else 0.0
                             for v in undefended[attack].values()])
        repro_rows.append({
            "arm": arm_label,
            "attack": attack,
            "n": len(attack_keys),
            "published_utility_under_attack_pct": pub_u,
            "recomputed_utility_under_attack_pct": _pct(util_val),
            "published_targeted_asr_pct": pub_s,
            "recomputed_targeted_asr_pct": _pct(sec_val),
            "utility_match": _matches(util_val, pub_u),
            "asr_match": _matches(sec_val, pub_s),
        })

    utility_rows = {}
    for arm in ARMS:
        label = SHORT[arm]
        vals = list(clean[arm].values())
        naive = artifact["inventory"][arm]["utility_rate_naive"]
        utility_rows[label] = {
            "n": len(vals),
            "recomputed_pct": _pct(_mean([1.0 if v else 0.0 for v in vals])),
            "published_pct": PUBLISHED_TABLE["clean_utility_pct"][label],
            "naive_including_injection_task_baselines_pct": _pct(naive),
        }
        utility_rows[label]["match"] = _matches(
            _mean([1.0 if v else 0.0 for v in vals]),
            PUBLISHED_TABLE["clean_utility_pct"][label])

    none_corrected = utility_rows["none"]["recomputed_pct"]
    none_naive = utility_rows["none"]["naive_including_injection_task_baselines_pct"]
    for row in utility_rows.values():
        row["corrected_delta_vs_none_pp"] = round(row["recomputed_pct"] - none_corrected, 3)
        row["naive_delta_vs_none_pp"] = round(
            row["naive_including_injection_task_baselines_pct"] - none_naive, 3)

    full = frame_report(cell, keys, ARMS)
    prefix = keys[:subset]
    prefix_frame = frame_report(cell, prefix, ARMS)
    prefix_frame["suites"] = dict(sorted(Counter(k[0] for k in prefix).items()))

    rng = random.Random(seed)
    random_sets = [rng.sample(keys, subset) for _ in range(draws)]
    random_frame = {"draws": draws, "subset": subset, "arms": {}}
    for arm in ARMS:
        values = sorted(asr(cell, sample, arm) for sample in random_sets)
        observed = asr(cell, prefix, arm)
        random_frame["arms"][SHORT[arm]] = {
            "median_pct": _pct(values[len(values) // 2]),
            "p05_pct": _pct(values[int(0.05 * len(values))]),
            "p95_pct": _pct(values[int(0.95 * len(values))]),
            "prefix_pct": _pct(observed),
            "prefix_percentile_rank": round(
                sum(1 for v in values if v <= observed) / len(values), 3),
        }

    suite_frames = {suite: frame_report(cell, sub, ARMS)
                    for suite, sub in sorted(suites.items())}

    best_counts: Counter[str] = Counter()
    top2_flips = 0
    full_order = [SHORT[a] for a in ranking(cell, keys, ARMS)]
    for sample in random_sets:
        order = [SHORT[a] for a in ranking(cell, sample, ARMS)]
        best_counts[order[0]] += 1
        if order[:2] != full_order[:2]:
            top2_flips += 1

    contrasts = {}
    boot_rng = random.Random(seed)
    pairs = [(ARMS[1], ARMS[3]), (ARMS[1], ARMS[0]), (ARMS[3], ARMS[0]),
             (ARMS[4], ARMS[0]), (ARMS[2], ARMS[0])]
    boot_values: Dict[Tuple[str, str], List[float]] = {p: [] for p in pairs}
    for _ in range(boot):
        sample = [keys[boot_rng.randrange(len(keys))] for _ in keys]
        values = {arm: asr(cell, sample, arm) for arm in ARMS}
        for pair in pairs:
            boot_values[pair].append(values[pair[0]] - values[pair[1]])
    for pair in pairs:
        low, high = _interval(boot_values[pair])
        contrasts[f"{SHORT[pair[0]]}_minus_{SHORT[pair[1]]}"] = {
            "delta_pp": _pct(asr(cell, keys, pair[0]) - asr(cell, keys, pair[1])),
            "ci95_pp": [_pct(low), _pct(high)],
        }

    # paired versus independent 400-cell sampling for the closest pair
    pair_rng = random.Random(seed + 1)
    paired_reversals = 0
    independent_reversals = 0
    paired_gaps: List[float] = []
    independent_gaps: List[float] = []
    for _ in range(draws):
        sample = pair_rng.sample(keys, subset)
        gap = asr(cell, sample, ARMS[1]) - asr(cell, sample, ARMS[3])
        paired_gaps.append(gap)
        paired_reversals += int(gap > 0)
        left = pair_rng.sample(keys, subset)
        right = pair_rng.sample(keys, subset)
        gap = asr(cell, left, ARMS[1]) - asr(cell, right, ARMS[3])
        independent_gaps.append(gap)
        independent_reversals += int(gap > 0)

    def spread(values: Sequence[float]) -> float:
        mu = _mean(values)
        return (sum((v - mu) ** 2 for v in values) / len(values)) ** 0.5

    per_attack = {attack: _mean([1.0 if v[1] else 0.0 for v in values.values()])
                  for attack, values in sorted(undefended.items())}
    pooled = _mean([1.0 if v[1] else 0.0
                    for values in undefended.values() for v in values.values()])
    non_dos = {a: v for a, v in per_attack.items() if "dos" not in a}
    dos = {a: v for a, v in per_attack.items() if "dos" in a}

    mixed = {}
    for arm in ARMS[1:]:
        mixed[SHORT[arm]] = {
            "delta_vs_matched_none_pp": _pct(asr(cell, keys, arm) - asr(cell, keys, ARMS[0])),
            "delta_vs_pooled_all_attack_none_pp": _pct(asr(cell, keys, arm) - pooled),
        }

    return {
        "artifact": artifact,
        "parameters": {
            "seed": seed,
            "bootstrap_draws": boot,
            "random_draws": draws,
            "subset_size": subset,
            "focus_attack": FOCUS_ATTACK,
        },
        "paired_frame": {
            "n": len(keys),
            "per_suite": dict(sorted(Counter(k[0] for k in keys).items())),
            "attacks_defended": [FOCUS_ATTACK],
        },
        "reproduction": {
            "rows": repro_rows,
            "rows_checked": len(repro_rows),
            "rows_matching": sum(
                1 for row in repro_rows
                if row["asr_match"] and row["utility_match"]),
            "clean_utility": utility_rows,
        },
        "frames": {
            "full_paired": full,
            "prefix_400": prefix_frame,
            "random_400": random_frame,
            "suites": suite_frames,
        },
        "rankings": {
            "by_targeted_asr_asc": {
                "full_paired": full_order,
                "prefix_400": [SHORT[a] for a in ranking(cell, prefix, ARMS)],
                "banking": [SHORT[a] for a in ranking(cell, suites["banking"], ARMS)],
                "random_400_best_counts": dict(best_counts),
                "random_400_top2_flip_rate": round(top2_flips / draws, 3),
            }
        },
        "contrasts": contrasts,
        "pairing": {
            "pair": "tool_filter_minus_pi_detector",
            "paired_reversal_rate": round(paired_reversals / draws, 3),
            "paired_gap_sd_pp": _pct(spread(paired_gaps)),
            "independent_reversal_rate": round(independent_reversals / draws, 3),
            "independent_gap_sd_pp": _pct(spread(independent_gaps)),
        },
        "aggregation_unit": {
            "pooled_cell_mean_pct": _pct(pooled),
            "macro_mean_over_attacks_pct": _pct(_mean(list(per_attack.values()))),
            "non_dos_macro_pct": _pct(_mean(list(non_dos.values()))),
            "dos_macro_pct": _pct(_mean(list(dos.values()))),
            "per_attack_pct": {a: _pct(v) for a, v in per_attack.items()},
            "note": "metric-aggregation unit only; not the gate risk rule of RQ2",
        },
        "mixed_frame_example": mixed,
        "not_evaluable": {
            "enforcement_semantics": (
                "no per-step gate decision, REVIEW state or risk score in any file"),
            "aggregation_rule": (
                "no risk-signal aggregation exists; only metric aggregation is observable"),
            "gate_attribution": (
                "outcome booleans only; attribution_source is structurally outcome_only"),
        },
        "not_measured": [
            "end-to-end ASR under a gate",
            "utility under governance",
            "task success after a block",
            "gate-side intervention records",
        ],
        "environment": {
            "python": platform.python_version(),
        },
    }


def second_run_report(runs_root: Path) -> Dict[str, Any]:
    """Why the Meta-SecAlign run cannot be pooled with the gpt-4o arms."""
    base = runs_root / SECOND_RUN
    if not base.is_dir():
        return {"present": False}
    suites: Dict[str, Dict[str, set]] = defaultdict(lambda: {"users": set(), "injections": set()})
    attacks: Counter[str] = Counter()
    versions: Counter[Tuple[str, str]] = Counter()
    names: Counter[str] = Counter()
    for path in sorted(base.rglob("*.json")):
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
        versions[(str(data.get("benchmark_version")),
                  str(data.get("agentdojo_package_version")))] += 1
        names[str(data.get("pipeline_name"))] += 1
        if data.get("attack_type") in (None, "none"):
            continue
        attacks[data["attack_type"]] += 1
        suites[data["suite_name"]]["users"].add(data.get("user_task_id"))
        suites[data["suite_name"]]["injections"].add(data.get("injection_task_id"))
    return {
        "present": True,
        "cells_per_attack": dict(sorted(attacks.items())),
        "benchmark_versions": {f"{k[0]}|{k[1]}": v for k, v in versions.items()},
        "pipeline_names": dict(names),
        "suites": {
            name: {"user_tasks": len(item["users"]),
                   "injection_tasks": len(item["injections"])}
            for name, item in sorted(suites.items())
        },
        "poolable_with_gpt4o_arms": False,
        "reason": (
            "different task-suite version: workspace carries 14 injection tasks "
            "instead of 6, so the security denominators are 949 rather than 629"),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs-root", type=Path, default=RUNS_DEFAULT)
    parser.add_argument("--out", type=Path, default=OUT_DEFAULT)
    parser.add_argument("--artifact-commit", default=None)
    parser.add_argument("--seed", type=int, default=20261123)
    parser.add_argument("--bootstrap-draws", type=int, default=2000)
    parser.add_argument("--random-draws", type=int, default=2000)
    parser.add_argument("--subset-size", type=int, default=400)
    args = parser.parse_args(argv)

    if not args.runs_root.is_dir():
        print(f"missing artifact: {args.runs_root}", file=sys.stderr)
        return 2
    artifact, data = read_artifact(args.runs_root)
    result = summarise(artifact, data, seed=args.seed,
                       boot=args.bootstrap_draws,
                       draws=args.random_draws,
                       subset=args.subset_size)
    result["source"] = {
        "repo": "<agentdojo-repo>",
        "runs_root": _portable_path(args.runs_root),
        "artifact_commit": args.artifact_commit,
        "published_table": {
            "url": PUBLISHED_TABLE["url"],
            "sha256": PUBLISHED_TABLE["sha256"],
        },
    }
    result["second_run"] = second_run_report(args.runs_root)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    # LF endings: the evidence manifest hashes LF-normalised content, and this
    # file is shipped verbatim in the anonymous snapshot.
    with args.out.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(result, indent=1, sort_keys=False) + "\n")
    print(f"wrote {args.out} ({args.out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
