"""Sample-size and stratified-sampling sensitivity (EXP-02).

Uses the cached public AgentDojo run tree; no model calls. For each size
n in {100, 200, 300, 400, 500, 629} it compares four mechanisms:

  prefix              first n cells in the artifact's sorted order
  uniform             n cells drawn uniformly without replacement
  stratified_census   suite quotas proportional to the census (144/105/140/240)
  stratified_prefix   suite quotas proportional to the 400-cell prefix

The last mechanism isolates composition: if it tracks the prefix, the prefix
effect is a suite-mix effect rather than a within-suite selection effect.

Outputs
-------
experiments/statistics/results/sample_size.json
experiments/statistics/SAMPLE_SIZE.md

Run:
    python experiments/statistics/sample_size.py
"""

from __future__ import annotations

import json
import math
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmark.external_validity_agentdojo import (  # noqa: E402
    ARMS,
    FOCUS_ATTACK,
    paired_keys,
    read_artifact,
)

OUT = ROOT / "experiments" / "statistics" / "results" / "sample_size.json"
MD = ROOT / "experiments" / "statistics" / "SAMPLE_SIZE.md"
RUNS = ROOT / ".tmp" / "agentdojo" / "runs"

SIZES = (100, 200, 300, 400, 500, 629)
UNIFORM_DRAWS = 2000
STRATIFIED_DRAWS = 1000
SEED = 20261126
TOOL = ARMS[1]
PI = ARMS[3]


def _allocate(n: int, shares: Dict[str, float],
              capacity: Dict[str, int]) -> Dict[str, int]:
    """Largest-remainder allocation, capped at each suite's capacity."""
    raw = {suite: n * share for suite, share in shares.items()}
    base = {suite: min(math.floor(value), capacity[suite])
            for suite, value in raw.items()}
    remainder = n - sum(base.values())
    order = sorted(raw, key=lambda suite: raw[suite] - base[suite], reverse=True)
    index = 0
    while remainder > 0:
        suite = order[index % len(order)]
        if base[suite] < capacity[suite]:
            base[suite] += 1
            remainder -= 1
        index += 1
        if index > 10 * n:
            break
    return base


def _summarise(draws: Sequence[List[float]], census: List[float]) -> dict:
    n_draws = len(draws)
    per_arm = {}
    for index, arm in enumerate(ARMS):
        values = [draw[index] for draw in draws]
        ordered = sorted(values)
        low = ordered[int(0.025 * (n_draws - 1))]
        high = ordered[int(0.975 * (n_draws - 1))]
        per_arm[arm] = {
            "mean_pct": round(sum(values) / n_draws, 3),
            "deviation_pp": round(sum(values) / n_draws - census[index], 3),
            "p2_5_pct": round(low, 3),
            "p97_5_pct": round(high, 3),
            "width_pp": round(high - low, 3),
        }
    gaps = [draw[1] - draw[3] for draw in draws]
    ordered_gaps = sorted(gaps)
    return {
        "draws": n_draws,
        "arms": per_arm,
        "gap_tool_minus_pi": {
            "mean_pp": round(sum(gaps) / n_draws, 3),
            "p2_5_pp": round(ordered_gaps[int(0.025 * (n_draws - 1))], 3),
            "p97_5_pp": round(ordered_gaps[int(0.975 * (n_draws - 1))], 3),
            "reversal_rate": round(sum(1 for gap in gaps if gap > 0) / n_draws, 4),
        },
    }


def _rate(flags: Dict[str, float], keys: Sequence[tuple]) -> float:
    return 100.0 * sum(flags[key] for key in keys) / len(keys)


def main() -> int:
    if not RUNS.is_dir():
        raise SystemExit(f"missing cached artifact: {RUNS}")
    _, data = read_artifact(RUNS)
    cell = data["cell"]
    keys = paired_keys(cell)
    if len(keys) != 629:
        raise SystemExit(f"expected 629 paired cells, got {len(keys)}")
    flags = {
        arm: {key: 1.0 if cell[key][arm][1] else 0.0 for key in keys}
        for arm in ARMS
    }
    census = [_rate(flags[arm], keys) for arm in ARMS]

    groups: Dict[str, List[tuple]] = defaultdict(list)
    for key in keys:
        groups[key[0]].append(key)
    census_shares = {suite: len(group) / len(keys)
                     for suite, group in groups.items()}
    prefix = keys[:400]
    prefix_counts = {suite: sum(1 for key in prefix if key[0] == suite)
                     for suite in groups}
    prefix_shares = {suite: count / 400 for suite, count in prefix_counts.items()}
    capacity = {suite: len(group) for suite, group in groups.items()}

    rng = random.Random(SEED)
    result = {
        "experiment": "EXP-02 sample size and stratification",
        "focus_attack": FOCUS_ATTACK,
        "census": {
            "n": len(keys),
            "asr_pct": {arm: round(value, 3) for arm, value in zip(ARMS, census)},
            "suites": {suite: len(group) for suite, group in groups.items()},
        },
        "prefix": {
            "n": 400,
            "suites": prefix_counts,
            "asr_pct": {arm: round(_rate(flags[arm], prefix), 3) for arm in ARMS},
        },
        "parameters": {
            "sizes": list(SIZES),
            "uniform_draws": UNIFORM_DRAWS,
            "stratified_draws": STRATIFIED_DRAWS,
            "seed": SEED,
            "mechanisms": ["prefix", "uniform", "stratified_census",
                           "stratified_prefix"],
        },
        "sizes": {},
    }

    for n in SIZES:
        prefix_keys = keys[:n]
        prefix_asrs = [_rate(flags[arm], prefix_keys) for arm in ARMS]

        def evaluate(selected: Sequence[tuple]) -> List[float]:
            return [_rate(flags[arm], selected) for arm in ARMS]

        entry = {
            "prefix": {
                "asr_pct": {arm: round(value, 3)
                            for arm, value in zip(ARMS, prefix_asrs)},
                "deviation_pp": {arm: round(value - base, 3)
                                 for arm, value, base in zip(ARMS, prefix_asrs, census)},
                "gap_tool_minus_pi_pp": round(prefix_asrs[1] - prefix_asrs[3], 3),
                "reversal": prefix_asrs[1] - prefix_asrs[3] > 0,
                "suites": {suite: sum(1 for key in prefix_keys if key[0] == suite)
                           for suite in groups},
            },
            "uniform": _summarise(
                [evaluate(rng.sample(keys, n)) for _ in range(UNIFORM_DRAWS)],
                census),
            "stratified_census": _summarise(
                [evaluate(_stratified(groups, _allocate(
                    n, census_shares, capacity), rng))
                 for _ in range(STRATIFIED_DRAWS)], census),
            "stratified_prefix": _summarise(
                [evaluate(_stratified(groups, _allocate(
                    n, prefix_shares, capacity), rng))
                 for _ in range(STRATIFIED_DRAWS)], census),
        }
        entry["uniform"]["mean_suites"] = {suite: round(
            n * census_shares[suite], 2) for suite in groups}
        entry["stratified_census"]["quotas"] = _allocate(
            n, census_shares, capacity)
        entry["stratified_prefix"]["quotas"] = _allocate(
            n, prefix_shares, capacity)
        result["sizes"][str(n)] = entry

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=1), encoding="utf-8")

    lines = [
        "# EXP-02 — Sample size and stratification",
        "",
        "Attack: `important_instructions`; 629 paired cells; no model calls.",
        f"Uniform draws: {UNIFORM_DRAWS}; stratified draws: {STRATIFIED_DRAWS}; "
        f"seed {SEED}.",
        "",
        "| n | mechanism | tool_filter dev. (pp) | pi_detector dev. (pp) | "
        "gap mean (pp) | reversal rate |",
        "|---|---|---|---|---|---|",
    ]
    for n in SIZES:
        entry = result["sizes"][str(n)]
        for name in ("prefix", "uniform", "stratified_census", "stratified_prefix"):
            item = entry[name]
            if name == "prefix":
                lines.append(
                    f"| {n} | prefix | {item['deviation_pp'][TOOL]:+.2f} | "
                    f"{item['deviation_pp'][PI]:+.2f} | "
                    f"{item['gap_tool_minus_pi_pp']:+.2f} | "
                    f"{'1' if item['reversal'] else '0'} |")
            else:
                gap = item["gap_tool_minus_pi"]
                lines.append(
                    f"| {n} | {name} | {item['arms'][TOOL]['deviation_pp']:+.2f} | "
                    f"{item['arms'][PI]['deviation_pp']:+.2f} | "
                    f"{gap['mean_pp']:+.2f} | {gap['reversal_rate']:.3f} |")
    lines += [
        "",
        "Deviation is relative to the 629-cell census. Reversal means the",
        "tool-filter ASR exceeds the pi-detector ASR (the census order is the",
        "opposite). The prefix is deterministic, so it has reversal 0 or 1 and",
        "no interval.",
        "",
        "Reproduce: `python experiments/statistics/sample_size.py`",
    ]
    MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT).as_posix()} and {MD.relative_to(ROOT).as_posix()}")
    return 0


def _stratified(groups: Dict[str, List[tuple]], quotas: Dict[str, int],
                rng: random.Random) -> List[tuple]:
    selected: List[tuple] = []
    for suite, quota in quotas.items():
        if quota:
            selected.extend(rng.sample(groups[suite], quota))
    return selected


if __name__ == "__main__":
    raise SystemExit(main())
