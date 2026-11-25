"""Minimum ranking reversal distance (T04).

The public AgentDojo artifact supports a paired comparison of `tool_filter`
against `transformers_pi_detector` on 629 attack cells. On the census the
tool filter has the lower attack success rate; on the 400-cell prefix the order
reverses. EXP-02 showed that the reversal is a composition effect. This script
asks the quantitative follow-up: how far must the suite weights move from the
census before the order reverses?

Reference frame
---------------
The 629-cell census. Weights are suite shares, `w_s = k_s / n`, with `n = 400`
(the size of the published prefix). The gap is

    G(k) = sum_s w_s * (ASR_tool_s - ASR_pi_s),

in percentage points, and the distance from the census is the L1 distance

    d(k) = sum_s |k_s / 400 - n_s / 629|.

Admissible set
--------------
Every same-size frame composition: integer counts `k_s` with
`0 <= k_s <= n_s` and `sum_s k_s = 400`. This is exactly the set of suite
compositions that a 400-cell frame drawn from the census can realise, so the
minimum is a statement about the artifact's frame geometry, not about a
hypothetical continuum. The set is finite (1,501,380 compositions), which
satisfies the T04 stop condition; an unrestricted simplex relaxation is
reported only as a labelled lower bound.

Outputs
-------
experiments/sensitivity/results/reversal_distance.json
experiments/sensitivity/REVERSAL_DISTANCE.md

Run:
    python experiments/sensitivity/reversal_distance.py
"""

from __future__ import annotations

import hashlib
import json
import math
import sys
from collections import defaultdict
from fractions import Fraction
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmark.external_validity_agentdojo import (  # noqa: E402
    ARMS,
    FOCUS_ATTACK,
    paired_keys,
    read_artifact,
)

RUNS = ROOT / ".tmp" / "agentdojo" / "runs"
EXTERNAL = ROOT / "benchmark" / "results" / "external_validity_agentdojo.json"
SAMPLE_SIZE = ROOT / "experiments" / "statistics" / "results" / "sample_size.json"
OUT = ROOT / "experiments" / "sensitivity" / "results" / "reversal_distance.json"
MD = ROOT / "experiments" / "sensitivity" / "REVERSAL_DISTANCE.md"

FRAME = 400
CENSUS_N = 629
TOOL = ARMS[1]
PI = ARMS[3]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _suite_stats(cell: Dict[Tuple[str, str, str], Dict[str, Tuple[bool, bool]]],
                 keys: List[Tuple[str, str, str]]) -> Dict[str, Dict[str, Any]]:
    cells: Dict[str, int] = defaultdict(int)
    tool: Dict[str, int] = defaultdict(int)
    pi: Dict[str, int] = defaultdict(int)
    users: Dict[str, set] = defaultdict(set)
    injections: Dict[str, set] = defaultdict(set)
    for key in keys:
        suite = key[0]
        cells[suite] += 1
        users[suite].add(key[1])
        injections[suite].add(key[2])
        tool[suite] += int(cell[key][TOOL][1])
        pi[suite] += int(cell[key][PI][1])
    stats = {}
    for suite in sorted(cells):
        n = cells[suite]
        gap = Fraction(100) * (Fraction(tool[suite], n) - Fraction(pi[suite], n))
        stats[suite] = {
            "cells": n,
            "user_tasks": len(users[suite]),
            "injection_tasks": len(injections[suite]),
            "tool_filter_successes": tool[suite],
            "pi_detector_successes": pi[suite],
            "tool_filter_asr_pct": round(100 * tool[suite] / n, 3),
            "pi_detector_asr_pct": round(100 * pi[suite] / n, 3),
            "gap_pp": gap,
        }
    return stats


def _scaled_coefficients(stats: Dict[str, Dict[str, Any]]) -> Tuple[List[str], Dict[str, int], int]:
    """Integer gap coefficients: G = sum(k_s * D_s) / (denominator * n)."""
    suites = list(stats)
    denominator = math.lcm(*(stats[suite]["cells"] for suite in suites))
    coeffs = {
        suite: int(stats[suite]["gap_pp"] * denominator)
        for suite in suites
    }
    return suites, coeffs, denominator


def _l1_numerator(counts: Dict[str, int], census: Dict[str, int],
                  frame: int) -> int:
    """Numerator of sum |k_s/frame - n_s/census_n| over a common denominator."""
    return sum(abs(counts[suite] * CENSUS_N - census[suite] * frame)
               for suite in counts)


def _scan_compositions(suites: List[str], caps: Dict[str, int],
                       coeffs: Dict[str, int], census: Dict[str, int],
                       frame: int) -> Dict[str, Any]:
    """Enumerate every same-size composition.

    Three definitions are tracked separately because a discrete composition
    set need not contain a point with an exactly zero gap:

    crossing  min L1 over ``gap >= 0`` (tie or reversal)
    tie       min L1 over ``gap == 0``
    strict    min L1 over ``gap > 0``
    """
    first, second, third, fourth = suites
    best = {"crossing": None, "tie": None, "strict": None}
    total = 0
    reversing = 0
    zero_gap = 0

    def _update(slot: str, distance: int, counts: Dict[str, int],
                gap_num: int) -> None:
        current = best[slot]
        if current is None or distance < current["distance"]:
            best[slot] = {
                "distance": distance,
                "counts": counts,
                "gap_num": gap_num,
                "ties": 1,
            }
        elif distance == current["distance"]:
            current["ties"] += 1

    for k1 in range(caps[first] + 1):
        for k2 in range(caps[second] + 1):
            low = max(0, frame - k1 - k2 - caps[fourth])
            high = min(caps[third], frame - k1 - k2)
            if low > high:
                continue
            base = k1 * coeffs[first] + k2 * coeffs[second]
            for k3 in range(low, high + 1):
                k4 = frame - k1 - k2 - k3
                total += 1
                gap_num = base + k3 * coeffs[third] + k4 * coeffs[fourth]
                counts = {first: k1, second: k2, third: k3, fourth: k4}
                distance = sum(
                    abs(counts[suite] * CENSUS_N - census[suite] * frame)
                    for suite in suites)
                if gap_num >= 0:
                    reversing += 1
                    _update("crossing", distance, counts, gap_num)
                if gap_num == 0:
                    zero_gap += 1
                    _update("tie", distance, counts, gap_num)
                elif gap_num > 0:
                    _update("strict", distance, counts, gap_num)
    return {
        "total": total,
        "reversing": reversing,
        "zero_gap": zero_gap,
        "best": best,
    }


def _prefix_path(keys: List[Tuple[str, str, str]],
                 suites: List[str], coeffs: Dict[str, int],
                 census: Dict[str, int], denominator: int) -> Dict[str, Any]:
    """Gap and distance for every prefix of the artifact's sorted cell order."""
    counts: Dict[str, int] = {suite: 0 for suite in suites}
    reversing = []
    preserving = []
    for index, key in enumerate(keys, start=1):
        counts[key[0]] += 1
        gap_num = sum(counts[suite] * coeffs[suite] for suite in suites)
        gap = float(Fraction(gap_num, denominator * index))
        distance = float(Fraction(
            _l1_numerator(counts, census, index), index * CENSUS_N))
        entry = {
            "n": index,
            "counts": dict(counts),
            "gap_pp": round(gap, 4),
            "distance_l1": round(distance, 6),
            "workspace_share_pct": round(100 * counts[suites[-1]] / index, 3),
        }
        if gap >= 0:
            reversing.append(entry)
        else:
            preserving.append(entry)
    closest = min(reversing, key=lambda item: item["distance_l1"])
    return {
        "prefixes": len(keys),
        "reversing": len(reversing),
        "preserving": len(preserving),
        "largest_reversing": reversing[-1] if reversing else None,
        "smallest_preserving": preserving[0] if preserving else None,
        "minimum_distance_over_prefixes": closest,
    }


def _lp_lower_bound(stats: Dict[str, Dict[str, Any]],
                    census_weights: Dict[str, Fraction]) -> Dict[str, Any]:
    """Unrestricted simplex relaxation: move mass between the extreme suites."""
    gap_census = sum(census_weights[suite] * stats[suite]["gap_pp"]
                     for suite in stats)
    donor = min(stats, key=lambda suite: stats[suite]["gap_pp"])
    receiver = max(stats, key=lambda suite: stats[suite]["gap_pp"])
    spread = stats[receiver]["gap_pp"] - stats[donor]["gap_pp"]
    mass = -gap_census / spread
    feasible = mass <= census_weights[donor] and (
        census_weights[receiver] + mass <= 1)
    return {
        "census_gap_pp": round(float(gap_census), 6),
        "donor": donor,
        "receiver": receiver,
        "mass": round(float(mass), 6),
        "distance_l1": round(float(2 * mass), 6),
        "feasible": bool(feasible),
        "status": "relaxation over the full simplex; lower bound only, not an admissible frame",
    }


def _context_frames(stats: Dict[str, Dict[str, Any]],
                    census: Dict[str, int]) -> Dict[str, Any]:
    suites = list(stats)
    users = {suite: stats[suite]["user_tasks"] for suite in suites}
    user_total = sum(users.values())
    frames = {}
    for name, weights in (
        ("user_task_weights", {suite: Fraction(users[suite], user_total)
                               for suite in suites}),
        ("uniform_suites", {suite: Fraction(1, len(suites)) for suite in suites}),
    ):
        gap = sum(weights[suite] * stats[suite]["gap_pp"] for suite in suites)
        distance = sum(abs(weights[suite] - Fraction(census[suite], CENSUS_N))
                       for suite in suites)
        frames[name] = {
            "weights": {suite: round(float(weights[suite]), 4) for suite in suites},
            "gap_pp": round(float(gap), 4),
            "distance_l1": round(float(distance), 6),
            "reversal": bool(gap >= 0),
        }
    return frames


def main() -> int:
    if not RUNS.is_dir():
        raise SystemExit(f"missing cached artifact: {RUNS}")
    _, data = read_artifact(RUNS)
    cell = data["cell"]
    keys = paired_keys(cell)
    if len(keys) != CENSUS_N:
        raise SystemExit(f"expected {CENSUS_N} paired cells, got {len(keys)}")

    published = json.loads(EXTERNAL.read_text(encoding="utf-8"))
    stats = _suite_stats(cell, keys)
    suites, coeffs, denominator = _scaled_coefficients(stats)
    census = {suite: stats[suite]["cells"] for suite in suites}
    census_weights = {suite: Fraction(census[suite], CENSUS_N) for suite in suites}

    for suite in suites:
        reported = published["frames"]["suites"][suite]["asr_pct"]
        for arm, name in ((TOOL, "tool_filter"), (PI, "pi_detector")):
            expected = stats[suite][f"{name}_asr_pct"]
            if abs(reported[arm] - expected) > 0.001:
                raise SystemExit(
                    f"{suite}/{name}: artifact rate {reported[arm]} "
                    f"disagrees with recomputed {expected}")

    census_gap_num = sum(census[suite] * coeffs[suite] for suite in suites)
    census_gap = float(Fraction(census_gap_num, denominator * CENSUS_N))

    prefix_counts = {suite: 0 for suite in suites}
    for key in keys[:FRAME]:
        prefix_counts[key[0]] += 1
    prefix_gap_num = sum(prefix_counts[suite] * coeffs[suite] for suite in suites)
    prefix_gap = float(Fraction(prefix_gap_num, denominator * FRAME))
    prefix_distance = float(Fraction(
        _l1_numerator(prefix_counts, census, FRAME), FRAME * CENSUS_N))

    scan = _scan_compositions(suites, census, coeffs, census, FRAME)
    crossing = scan["best"]["crossing"]
    if crossing is None:
        raise SystemExit("no crossing frame composition found")
    best_gap = float(Fraction(crossing["gap_num"], denominator * FRAME))
    best_distance = float(Fraction(
        crossing["distance"], FRAME * CENSUS_N))

    def _composition(entry: Dict[str, Any] | None) -> Dict[str, Any] | None:
        if entry is None:
            return None
        return {
            "counts": entry["counts"],
            "weights": {suite: round(entry["counts"][suite] / FRAME, 6)
                        for suite in suites},
            "gap_pp": round(float(Fraction(
                entry["gap_num"], denominator * FRAME)), 6),
            "distance_l1": round(float(Fraction(
                entry["distance"], FRAME * CENSUS_N)), 6),
            "distance_tv": round(float(Fraction(
                entry["distance"], FRAME * CENSUS_N)) / 2, 6),
            "ties": entry["ties"],
        }

    tie = _composition(scan["best"]["tie"])
    strict = _composition(scan["best"]["strict"])

    prefix_path = _prefix_path(keys, suites, coeffs, census, denominator)
    relaxation = _lp_lower_bound(stats, census_weights)
    contexts = _context_frames(stats, census)

    sample = json.loads(SAMPLE_SIZE.read_text(encoding="utf-8"))
    quota = sample["sizes"][str(FRAME)]["stratified_census"]["quotas"]
    quota_counts = {suite: int(quota[suite]) for suite in suites}
    quota_gap = float(Fraction(
        sum(quota_counts[suite] * coeffs[suite] for suite in suites),
        denominator * FRAME))
    quota_distance = float(Fraction(
        _l1_numerator(quota_counts, census, FRAME), FRAME * CENSUS_N))

    result = {
        "experiment": "T04 minimum ranking reversal distance",
        "focus_attack": FOCUS_ATTACK,
        "arms": {"A": TOOL, "B": PI},
        "inputs": {
            "artifact": "benchmark/results/external_validity_agentdojo.json",
            "artifact_sha256": _sha256(EXTERNAL),
            "sample_size_result": "experiments/statistics/results/sample_size.json",
        },
        "population": {
            "n": CENSUS_N,
            "suites": {
                suite: {
                    "cells": stats[suite]["cells"],
                    "user_tasks": stats[suite]["user_tasks"],
                    "injection_tasks": stats[suite]["injection_tasks"],
                    "tool_filter_successes": stats[suite]["tool_filter_successes"],
                    "pi_detector_successes": stats[suite]["pi_detector_successes"],
                    "tool_filter_asr_pct": stats[suite]["tool_filter_asr_pct"],
                    "pi_detector_asr_pct": stats[suite]["pi_detector_asr_pct"],
                    "gap_pp": round(float(stats[suite]["gap_pp"]), 4),
                } for suite in suites
            },
        },
        "metric": {
            "frame_size": FRAME,
            "weights": "w_s = k_s / 400 for the frame's suite counts k",
            "composition_gap_pp": (
                "g(w) = E[Delta_hat | w] = sum_s w_s * (ASR_tool_s - ASR_pi_s), "
                "with suite rates fixed at their census values and uniform "
                "sampling within each suite"),
            "distance_l1": "sum_s |w_s - n_s/629|; total variation is half this value",
            "crossing": "min L1 over g(w) >= 0; a composition-predicted tie or reversal",
            "tie": "min L1 over g(w) == 0",
            "strict": "min L1 over g(w) > 0",
            "scope": (
                "composition-induced distance, not the minimum over realised "
                "400-cell subsets; within-suite task selection also moves ASR"),
        },
        "census": {
            "weights": {suite: round(float(census_weights[suite]), 6)
                        for suite in suites},
            "gap_pp": round(census_gap, 6),
            "ordering": ["tool_filter", "pi_detector"],
        },
        "constructed_prefix": {
            "n": FRAME,
            "counts": prefix_counts,
            "weights": {suite: round(prefix_counts[suite] / FRAME, 6)
                        for suite in suites},
            "gap_pp": round(prefix_gap, 6),
            "distance_l1": round(prefix_distance, 6),
        },
        "admissible_set": {
            "name": "same_size_400_compositions",
            "definition": "0 <= k_s <= n_s, sum_s k_s = 400",
            "size": scan["total"],
            "reversing": scan["reversing"],
            "zero_gap": scan["zero_gap"],
            "reversing_fraction": round(scan["reversing"] / scan["total"], 4),
            "justification": (
                "Every 400-cell frame is a composition in this set; the set is "
                "finite, so the reported distance is a discrete minimum and not "
                "an artefact of unrestricted reweighting."),
        },
        "minimum_reversing_composition": {
            "definition": "crossing: gap_pp >= 0",
            "counts": crossing["counts"],
            "weights": {suite: round(crossing["counts"][suite] / FRAME, 6)
                        for suite in suites},
            "gap_pp": round(best_gap, 6),
            "distance_l1": round(best_distance, 6),
            "distance_tv": round(best_distance / 2, 6),
            "ties": crossing["ties"],
        },
        "minimum_tie_composition": tie,
        "minimum_strict_reversal_composition": strict,
        "enumeration": {
            "complete": True,
            "compositions": scan["total"],
            "note": (
                "The gap depends only on suite counts, so the suite-level rates "
                "are sufficient and the scan is exhaustive over every admissible "
                "400-cell composition, not a local search."),
        },
        "continuous_lower_bound": relaxation,
        "prefix_family": prefix_path,
        "context_frames": {
            **contexts,
            "census_quota_400": {
                "counts": quota_counts,
                "gap_pp": round(quota_gap, 6),
                "distance_l1": round(quota_distance, 6),
                "source": "EXP-02 stratified_census quotas at n=400",
            },
        },
        "not_claimed": [
            "The distance is not a probability: it does not say how likely a reversing frame is.",
            "No causal attribution: the gap is a composition effect of this artifact only.",
            "The simplex relaxation is not an admissible frame and is never quoted as the minimum.",
            "No claim about other attacks or other arm pairs.",
        ],
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=1), encoding="utf-8")

    lines = [
        "# T04 — Minimum ranking reversal distance",
        "",
        f"Attack: `{FOCUS_ATTACK}`; arms: `tool_filter` (A) vs `pi_detector` (B); "
        f"{CENSUS_N} paired cells; no model calls.",
        "",
        "## Per-suite rates",
        "",
        "| suite | cells | users | injections | tool ASR | pi ASR | gap (pp) |",
        "|---|---|---|---|---|---|---|",
    ]
    for suite in suites:
        item = stats[suite]
        lines.append(
            f"| {suite} | {item['cells']} | {item['user_tasks']} | "
            f"{item['injection_tasks']} | {item['tool_filter_asr_pct']:.3f} | "
            f"{item['pi_detector_asr_pct']:.3f} | "
            f"{float(item['gap_pp']):+.3f} |")
    tie_text = "none" if tie is None else f"{tie['distance_l1']:.4f}"
    strict_text = "none" if strict is None else f"{strict['distance_l1']:.4f}"
    lines += [
        "",
        f"Census gap: **{census_gap:+.4f} pp** (tool filter lower).",
        f"Published 400-cell prefix: gap **{prefix_gap:+.4f} pp**, "
        f"L1 weight distance **{prefix_distance:.4f}**.",
        "",
        "## Minimum over same-size frames",
        "",
        f"Admissible set: all 400-cell suite compositions "
        f"(`0 <= k_s <= n_s`, sum 400), {scan['total']:,} points.",
        f"{scan['reversing']:,} of them reverse the census order "
        f"({100 * scan['reversing'] / scan['total']:.1f}%), including "
        f"{scan['zero_gap']} exact ties. The counting fraction weights every "
        "composition equally; it is not the probability that a uniform draw "
        "reverses (EXP-02: 11.45 percent), because the sampling distribution "
        "concentrates near the census composition.",
        "",
        f"Closest crossing composition (definition: gap >= 0): "
        f"banking {crossing['counts'][suites[0]]}, "
        f"slack {crossing['counts'][suites[1]]}, "
        f"travel {crossing['counts'][suites[2]]}, "
        f"workspace {crossing['counts'][suites[3]]}; "
        f"gap {best_gap:+.4f} pp, L1 distance **{best_distance:.4f}** "
        f"(TV {best_distance / 2:.4f}); ties at the minimum: {crossing['ties']}.",
        "",
        f"Closest exact tie (gap == 0): {tie_text}.",
        f"Closest strict reversal (gap > 0): {strict_text}.",
        "",
        f"Unrestricted simplex relaxation (lower bound, not a claim): "
        f"{relaxation['distance_l1']:.4f} by moving {relaxation['mass']:.4f} "
        f"of the mass from {relaxation['donor']} to {relaxation['receiver']}.",
        "",
        "## Prefix family",
        "",
        f"Along the artifact's sorted order, every prefix of length <= "
        f"{prefix_path['largest_reversing']['n']} reverses; every prefix of "
        f"length >= {prefix_path['smallest_preserving']['n']} preserves the "
        f"census order.",
        f"The closest reversing prefix is n={prefix_path['largest_reversing']['n']} "
        f"with {prefix_path['largest_reversing']['counts'][suites[-1]]} "
        f"workspace cells "
        f"({prefix_path['largest_reversing']['workspace_share_pct']:.2f}% of the "
        f"frame), gap "
        f"{prefix_path['largest_reversing']['gap_pp']:+.4f} pp, distance "
        f"{prefix_path['largest_reversing']['distance_l1']:.4f}.",
        "",
        "## Context frames",
        "",
        "| frame | gap (pp) | L1 distance | reversal |",
        "|---|---|---|---|",
        f"| census | {census_gap:+.4f} | 0.0000 | no |",
        f"| prefix 400 | {prefix_gap:+.4f} | {prefix_distance:.4f} | yes |",
        f"| census-quota 400 | {quota_gap:+.4f} | {quota_distance:.4f} | "
        f"{'yes' if quota_gap >= 0 else 'no'} |",
    ]
    for name, item in contexts.items():
        lines.append(
            f"| {name} | {item['gap_pp']:+.4f} | {item['distance_l1']:.4f} | "
            f"{'yes' if item['reversal'] else 'no'} |")
    lines += [
        "",
        "The census-quota frame is the EXP-02 stratified composition at n=400; "
        "the user-task frame weights suites by distinct user tasks "
        f"({sum(stats[s]['user_tasks'] for s in suites)} tasks); the uniform "
        "frame weights the four suites equally.",
        "",
        "## What is not claimed",
        "",
        *[f"- {item}" for item in result["not_claimed"]],
        "",
        "Reproduce: `python experiments/sensitivity/reversal_distance.py`",
    ]
    MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT).as_posix()} and {MD.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
