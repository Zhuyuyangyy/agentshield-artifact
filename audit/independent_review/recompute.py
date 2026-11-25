"""Independent recomputation of the paper's frozen numbers (V01).

This script deliberately does not import the project's analysis modules. It
reads the frozen outcomes, the public run tree, and the attribution file with
plain `json`, recomputes the headline numbers by a separate code path, and
records whether each recomputation matches the reported value.

Checks
------
1. Study 1: trace counts, eight attack rates, eight benign rates, blocked-set
   sizes, and the 400-trace prefix rates.
2. Study 2: 629 paired cells, five defense ASRs and utility values, the 400-cell
   prefix gap, and the banking gap.
3. T04: exhaustive minimum reversal composition over all 400-cell compositions.
4. E03: exact McNemar power and MDE by an independent binomial implementation.
5. E07/E08: the 6/3/6 flip classification and the [6, 12] bound.

Outputs
-------
audit/independent_review/results/recompute.json
audit/independent_review/REPORT.md

Run:
    python audit/independent_review/recompute.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[2]
OUTCOMES = ROOT / "benchmark" / "results" / "e2b_trajectory_outcomes.jsonl"
RUNS = ROOT / ".tmp" / "agentdojo" / "runs"
ATTRIBUTION = (ROOT / "benchmark" / "results" / "agentdojo_live"
               / "headroom-vllm-nemotron-120b-v041" / "attribution.json")
REVERSAL_RESULT = (ROOT / "experiments" / "sensitivity" / "results"
                   / "reversal_distance.json")
REGISTRY = ROOT / "audit" / "independent_review" / "CLAIM_REGISTRY.json"
OUT = ROOT / "audit" / "independent_review" / "results" / "recompute.json"
MD = ROOT / "audit" / "independent_review" / "REPORT.md"

RULES = ("no_relaxation", "global_cap", "band_split", "hard_first")
POLICIES = ("log_and_allow", "block")
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
TOOL = ARMS[1]
PI = ARMS[3]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_rows() -> List[dict]:
    with OUTCOMES.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]


def _study1(rows: Sequence[dict]) -> dict:
    attack = [row for row in rows if row["label"] == "attack"]
    benign = [row for row in rows if row["label"] == "benign"]
    prefix = attack[:400]
    result = {
        "rows": len(rows),
        "attack": len(attack),
        "benign": len(benign),
        "rates_pct": {},
        "prefix_pct": {},
    }
    for rule in RULES:
        for policy in POLICIES:
            key = f"{rule}|{policy}"
            a_blocked = sum(1 for row in attack if row["blocked"][rule][policy])
            b_blocked = sum(1 for row in benign if row["blocked"][rule][policy])
            p_blocked = sum(1 for row in prefix if row["blocked"][rule][policy])
            result["rates_pct"][key] = {
                "attack_blocked": a_blocked,
                "attack_pct": round(100 * a_blocked / len(attack), 4),
                "benign_blocked": b_blocked,
                "benign_pct": round(100 * b_blocked / len(benign), 4),
            }
            if policy == "block":
                result["prefix_pct"][key] = {
                    "blocked": p_blocked,
                    "pct": round(100 * p_blocked / len(prefix), 4),
                }
    band_set = {row["trajectory"] for row in attack
                if row["blocked"]["band_split"]["block"]}
    hard_set = {row["trajectory"] for row in attack
                if row["blocked"]["hard_first"]["block"]}
    result["block_sets"] = {
        "band_split": len(band_set),
        "hard_first": len(hard_set),
        "symmetric_difference": len(band_set ^ hard_set),
    }
    return result


def _read_study2() -> Tuple[Dict[Tuple[str, str, str], Dict[str, Tuple[bool, bool]]],
                            List[Tuple[str, str, str]]]:
    cell: Dict[Tuple[str, str, str], Dict[str, Tuple[bool, bool]]] = {}
    for path in sorted(RUNS.rglob("*.json")):
        arm = path.relative_to(RUNS).parts[0]
        if arm not in ARMS:
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("attack_type") != "important_instructions":
            continue
        key = (data["suite_name"], data["user_task_id"],
               data["injection_task_id"])
        cell.setdefault(key, {})[arm] = (
            bool(data.get("utility")), bool(data.get("security")))
    keys = sorted(key for key, value in cell.items() if len(value) == len(ARMS))
    return cell, keys


def _asr(cell, keys, arm) -> float:
    return 100 * sum(1 for key in keys if cell[key][arm][1]) / len(keys)


def _utility(cell, keys, arm) -> float:
    return 100 * sum(1 for key in keys if cell[key][arm][0]) / len(keys)


def _study2(cell, keys) -> dict:
    suites = {}
    for key in keys:
        suites[key[0]] = suites.get(key[0], 0) + 1
    banking = [key for key in keys if key[0] == "banking"]
    prefix = keys[:400]
    return {
        "cells": len(keys),
        "suites": dict(sorted(suites.items())),
        "census_asr_pct": {SHORT[arm]: round(_asr(cell, keys, arm), 3)
                           for arm in ARMS},
        "census_utility_pct": {SHORT[arm]: round(_utility(cell, keys, arm), 3)
                               for arm in ARMS},
        "census_asr_counts": {
            SHORT[arm]: sum(1 for key in keys if cell[key][arm][1])
            for arm in ARMS},
        "census_utility_counts": {
            SHORT[arm]: sum(1 for key in keys if cell[key][arm][0])
            for arm in ARMS},
        "prefix_asr_pct": {SHORT[arm]: round(_asr(cell, prefix, arm), 3)
                           for arm in ARMS},
        "prefix_asr_counts": {
            SHORT[arm]: sum(1 for key in prefix if cell[key][arm][1])
            for arm in ARMS},
        "prefix_tool_minus_pi_pp": round(
            _asr(cell, prefix, TOOL) - _asr(cell, prefix, PI), 3),
        "banking_tool_minus_pi_pp": round(
            _asr(cell, banking, TOOL) - _asr(cell, banking, PI), 3),
    }


def _reversal_from_counts(counts: Dict[str, int], tool: Dict[str, int],
                          pi: Dict[str, int]) -> dict:
    suites = ("banking", "slack", "travel", "workspace")
    denominator = math.lcm(*(counts[name] for name in suites))
    coefficients = {
        name: 100 * (tool[name] - pi[name]) * (denominator // counts[name])
        for name in suites
    }
    best = {"crossing": None, "tie": None, "strict": None}
    reversing = 0
    zero = 0
    compositions = 0

    def _update(slot, distance, composition, gap):
        current = best[slot]
        if current is None or distance < current["distance_numerator"]:
            best[slot] = {
                "counts": composition,
                "gap_pp": round(gap / (denominator * 400), 6),
                "distance_l1": round(distance / (400 * 629), 6),
                "distance_numerator": distance,
            }
        elif distance == current["distance_numerator"]:
            current["ties"] = current.get("ties", 1) + 1

    for banking in range(counts["banking"] + 1):
        for slack in range(counts["slack"] + 1):
            low = max(0, 400 - banking - slack - counts["workspace"])
            high = min(counts["travel"], 400 - banking - slack)
            for travel in range(low, high + 1):
                compositions += 1
                workspace = 400 - banking - slack - travel
                gap = (banking * coefficients["banking"]
                       + slack * coefficients["slack"]
                       + travel * coefficients["travel"]
                       + workspace * coefficients["workspace"])
                distance = sum(
                    abs(value * 629 - counts[name] * 400)
                    for name, value in (("banking", banking), ("slack", slack),
                                        ("travel", travel), ("workspace", workspace)))
                composition = {"banking": banking, "slack": slack,
                               "travel": travel, "workspace": workspace}
                if gap >= 0:
                    reversing += 1
                    _update("crossing", distance, composition, gap)
                if gap == 0:
                    zero += 1
                    _update("tie", distance, composition, gap)
                elif gap > 0:
                    _update("strict", distance, composition, gap)
    for entry in best.values():
        if entry is not None:
            entry.pop("distance_numerator", None)
    return {
        "compositions": compositions,
        "reversing": reversing,
        "zero_gap": zero,
        "minimum": best["crossing"],
        "minimum_tie": best["tie"],
        "minimum_strict": best["strict"],
        "definitions": {
            "crossing": "min L1 over g(w) >= 0",
            "tie": "min L1 over g(w) == 0",
            "strict": "min L1 over g(w) > 0",
            "scope": ("composition-induced distance with suite rates fixed at "
                      "their census values; not the minimum over realised "
                      "400-cell subsets"),
        },
    }


def _reversal(cell, keys) -> dict:
    counts = {name: 0 for name in ("banking", "slack", "travel", "workspace")}
    tool = dict(counts)
    pi = dict(counts)
    for key in keys:
        suite = key[0]
        counts[suite] += 1
        tool[suite] += int(cell[key][TOOL][1])
        pi[suite] += int(cell[key][PI][1])
    return _reversal_from_counts(counts, tool, pi)


def _reversal_offline() -> dict | None:
    if not REVERSAL_RESULT.is_file():
        return None
    data = json.loads(REVERSAL_RESULT.read_text(encoding="utf-8"))
    suites = data["population"]["suites"]
    counts = {name: int(item["cells"]) for name, item in suites.items()}
    tool = {name: int(item["tool_filter_successes"])
            for name, item in suites.items()}
    pi = {name: int(item["pi_detector_successes"])
          for name, item in suites.items()}
    return _reversal_from_counts(counts, tool, pi)


def _mcnemar_rejection(m: int, alpha: float = 0.05) -> Tuple[int, int]:
    low = -1
    for k in range(m // 2 + 1):
        tail = 2 * sum(math.comb(m, i) for i in range(k + 1)) / 2 ** m
        if tail <= alpha:
            low = k
    if low < 0:
        return (-1, m + 1)
    return (low, m - low)


def _power(n: int, q: float, d: float, alpha: float = 0.05) -> float:
    p = 0.5 * (1 + d / q) if q > 0 else 0.5
    total = 0.0
    for m in range(n + 1):
        pm = math.comb(n, m) * q ** m * (1 - q) ** (n - m)
        if pm == 0:
            continue
        low, high = _mcnemar_rejection(m, alpha)
        if low < 0:
            continue
        total += pm * (
            sum(math.comb(m, i) * p ** i * (1 - p) ** (m - i)
                for i in range(low + 1))
            + sum(math.comb(m, i) * p ** i * (1 - p) ** (m - i)
                  for i in range(high, m + 1))
        )
    return total


def _mde(n: int, q: float, target: float = 0.8) -> float | None:
    low, high = 0.0, min(q, 0.999)
    if _power(n, q, high) < target:
        return None
    for _ in range(60):
        mid = (low + high) / 2
        if _power(n, q, mid) >= target:
            high = mid
        else:
            low = mid
    return 100 * high


def _power_checks() -> dict:
    observed = _power(97, 3 / 97, 3 / 97)
    mde = {
        "q_0.10": round(_mde(97, 0.10), 2),
        "q_0.20": round(_mde(97, 0.20), 2),
    }
    # The minimum attainable two-sided p at m=3 is 2 * P(X = 0).
    min_p = 2 * (1 / 2 ** 3)
    return {
        "observed_power": round(observed, 3),
        "minimum_two_sided_p_m3": min_p,
        "mde_pp": mde,
    }


def _flip_checks() -> dict:
    data = json.loads(ATTRIBUTION.read_text(encoding="utf-8"))
    flips = [cell for cell in data["cells"]
             if cell.get("a_security") and not cell.get("b_security")]
    classes = {"gate_consistent": 0, "zero_intervention": 0, "unrecorded": 0}
    tasks = set()
    for cell in flips:
        blocked = cell.get("blocked_calls")
        if blocked is None:
            classes["unrecorded"] += 1
            tasks.add(cell["user_task_id"])
        elif blocked == 0:
            classes["zero_intervention"] += 1
        else:
            classes["gate_consistent"] += 1
    return {
        "flips": len(flips),
        "classes": classes,
        "unrecorded_tasks": sorted(tasks),
        "bound": [classes["gate_consistent"],
                  classes["gate_consistent"] + classes["unrecorded"]],
    }


def _lookup(value, path):
    current = value
    for key in path:
        if ((isinstance(current, dict) and key in current)
                or (isinstance(current, list) and isinstance(key, int)
                    and 0 <= key < len(current))):
            current = current[key]
        else:
            return None
    return current


def _evaluate_registry(registry: Sequence[dict], scopes: Dict[str, dict]) -> List[dict]:
    checks = []
    for entry in registry:
        scope_name = entry.get("scope")
        scope = scopes.get(scope_name)
        if scope is None:
            checks.append({
                "claim_id": entry.get("claim_id"),
                "scope": scope_name,
                "status": "not_executed",
                "paper_location": entry.get("paper_location", ""),
                "metric_definition": entry.get("metric_definition", ""),
                "expected": entry.get("expected_value"),
                "expected_count": entry.get("expected_count"),
                "expected_denominator": entry.get("expected_denominator"),
                "recomputed": None,
                "recomputed_count": None,
                "tolerance": entry.get("numeric_tolerance"),
                "match": None,
                "errors": ["scope is not available in this mode"],
            })
            continue
        value = _lookup(scope, entry.get("value_path", []))
        count_path = entry.get("count_path")
        count = _lookup(scope, count_path) if count_path else None
        expected = entry.get("expected_value")
        tolerance = float(entry.get("numeric_tolerance", 0.0))
        reasons = []
        if value is None:
            reasons.append("value path is absent from the recomputation")
        elif (not isinstance(value, (int, float))
              or isinstance(value, bool)):
            reasons.append("recomputed value is not numeric")
        elif abs(float(value) - float(expected)) > tolerance:
            reasons.append(
                f"value {value} differs from {expected} by more than "
                f"{tolerance}")
        if count_path:
            expected_count = entry.get("expected_count")
            if count is None:
                reasons.append("count path is absent from the recomputation")
            elif int(count) != int(expected_count):
                reasons.append(f"count {count} != {expected_count}")
        checks.append({
            "claim_id": entry.get("claim_id"),
            "scope": scope_name,
            "status": "executed",
            "paper_location": entry.get("paper_location", ""),
            "metric_definition": entry.get("metric_definition", ""),
            "expected": expected,
            "expected_count": entry.get("expected_count"),
            "expected_denominator": entry.get("expected_denominator"),
            "recomputed": value,
            "recomputed_count": count,
            "tolerance": tolerance,
            "match": not reasons,
            "errors": reasons,
        })
    return checks


def _write_blocked(mode: str, reasons: Sequence[str]) -> int:
    payload = {
        "experiment": "V01 independent recomputation",
        "mode": mode,
        "status": "BLOCKED",
        "blocked": list(reasons),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    MD.parent.mkdir(parents=True, exist_ok=True)
    MD.write_text(
        "# V01 — Independent recomputation\n\n"
        f"Mode: `{mode}`; status: **BLOCKED**.\n\n"
        + "\n".join(f"- {reason}" for reason in reasons)
        + "\n",
        encoding="utf-8")
    print("BLOCKED: " + "; ".join(reasons))
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="recompute")
    parser.add_argument("--mode", choices=("offline", "external", "full"),
                        default="offline",
                        help="offline: shipped files only; external: add the "
                             "AgentDojo run tree; full: add the Arrow dump")
    args = parser.parse_args(argv)

    if not REGISTRY.is_file():
        return _write_blocked(
            args.mode,
            [f"missing input: {REGISTRY.relative_to(ROOT).as_posix()}"])
    try:
        registry_doc = json.loads(REGISTRY.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return _write_blocked(
            args.mode,
            [f"claim registry is not valid JSON: {exc}"])
    registry = registry_doc.get("claims")
    if not isinstance(registry, list) or not registry:
        return _write_blocked(
            args.mode, ["claim registry has no claims array"])

    if not OUTCOMES.is_file() or not ATTRIBUTION.is_file():
        return _write_blocked(
            args.mode,
            ["missing input: Study 1 outcomes or attribution file"])

    rows = _load_rows()
    study1 = _study1(rows)
    power = _power_checks()
    flips = _flip_checks()
    blocked: List[str] = []
    study2 = None
    if args.mode == "offline":
        reversal = _reversal_offline()
        if reversal is None:
            return _write_blocked(
                args.mode,
                [f"missing input: {REVERSAL_RESULT.relative_to(ROOT).as_posix()}"])
        blocked.append("Study 2 run tree: offline mode uses shipped suite counts")
    else:
        if not RUNS.is_dir():
            return _write_blocked(
                args.mode,
                [f"missing input: {RUNS.relative_to(ROOT).as_posix()}"])
        cell, keys = _read_study2()
        study2 = _study2(cell, keys)
        reversal = _reversal(cell, keys)
    if args.mode == "full":
        return _write_blocked(
            args.mode,
            [*blocked,
             "Full Arrow-dump replay: not shipped with this artifact"])

    scopes = {
        "study1": study1,
        "reversal": reversal,
        "power": power,
        "flips": flips,
    }
    if study2 is not None:
        scopes["study2"] = study2
    checks = _evaluate_registry(registry, scopes)
    matches = {
        check["claim_id"]: bool(check["match"])
        for check in checks if check["status"] == "executed"
    }
    not_executed = [
        check for check in checks if check["status"] != "executed"
    ]
    if not_executed:
        blocked.append(
            f"{len(not_executed)} registry entries were not executed in this "
            f"mode and are not counted as passed")
    if study2 is None:
        blocked.append("Study 2 external recomputation: run tree not required "
                       "in offline mode")

    status = "pass" if matches and all(matches.values()) else "fail"
    result = {
        "experiment": "V01 independent recomputation",
        "mode": args.mode,
        "status": status,
        "blocked": blocked,
        "registry": {
            "path": REGISTRY.relative_to(ROOT).as_posix(),
            "entries": len(registry),
            "executed": len(matches),
            "not_executed": len(not_executed),
        },
        "inputs": {
            "outcomes_sha256": _sha256(OUTCOMES),
            "attribution_sha256": _sha256(ATTRIBUTION),
            "reversal_result": REVERSAL_RESULT.relative_to(ROOT).as_posix(),
        },
        "study1": study1,
        "study2": study2,
        "reversal": reversal,
        "power": power,
        "flips": flips,
        "checks": checks,
        "not_executed": [check["claim_id"] for check in not_executed],
        "matches": matches,
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=1), encoding="utf-8")

    lines = [
        "# V01 — Independent recomputation",
        "",
        f"Mode: `{args.mode}`; status: **{status}**.",
        "",
        "A separate code path reads the frozen outcomes, the attribution file, "
        "the shipped suite counts and the claim registry; it imports none of the "
        "project's analysis modules.",
        "",
        "| claim | scope | recomputed | expected | match |",
        "|---|---|---|---|---|",
    ]
    for check in checks:
        if check["status"] == "executed":
            recomputed = str(check["recomputed"])
            if check["recomputed_count"] is not None:
                recomputed += f" ({check['recomputed_count']})"
            expected = str(check["expected"])
            if check["expected_count"] is not None:
                expected += f" ({check['expected_count']})"
            match = str(check["match"])
        else:
            recomputed = "—"
            expected = str(check["expected"])
            match = "NOT EXECUTED"
        lines.append(
            f"| {check['claim_id']} | {check['scope']} | {recomputed} | "
            f"{expected} | {match} |")
    lines += [
        "",
        f"Executed checks: {len(matches)}; not executed: {len(not_executed)}; "
        f"all executed checks match: {all(matches.values())}.",
        "",
        "## Not executed",
        "",
        *([f"- {check['claim_id']} ({check['scope']})"
           for check in not_executed] or ["- none"]),
        "",
        "## Blocked layers",
        "",
        *[f"- {item}" for item in blocked],
        "",
        "## Scope",
        "",
        "The offline mode covers counts, all eight attack and eight benign "
        "rates, the bounded REVIEW logic, the prefix counts, the "
        "composition-induced reversal geometry, power and the full flip "
        "classification. The external mode adds the AgentDojo run tree. The full "
        "mode would require the Arrow dump and a live replay; it reports BLOCKED "
        "rather than crashing.",
        "",
        f"Reproduce: `python audit/independent_review/recompute.py --mode "
        f"{args.mode}`",
    ]
    MD.parent.mkdir(parents=True, exist_ok=True)
    MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT).as_posix()} and {MD.relative_to(ROOT).as_posix()}")
    print(result["matches"])
    return 0 if matches and all(matches.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
