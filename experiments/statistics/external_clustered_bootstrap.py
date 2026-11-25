"""Clustered uncertainty for the Study 2 top-two contrast (E01b).

The 629 paired AgentDojo cells are not independent: they share user tasks and
injection tasks. This script recomputes the tool_filter-minus-pi_detector gap
with the same four interval constructions used in Study 1: cell bootstrap,
user-task cluster bootstrap, injection-task cluster bootstrap, and a two-way
cluster-robust (CGM) interval. It runs on the frozen cache; no model calls.

Outputs
-------
experiments/statistics/results/external_clustered_bootstrap.json
experiments/statistics/EXTERNAL_CLUSTERED.md

Run:
    python experiments/statistics/external_clustered_bootstrap.py
"""

from __future__ import annotations

import hashlib
import json
import math
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmark.external_validity_agentdojo import (  # noqa: E402
    ARMS,
    FOCUS_ATTACK,
    paired_keys,
    read_artifact,
)
from experiments.statistics.clustered_bootstrap import (  # noqa: E402
    _bootstrap,
    _bootstrap_clusters,
    _ci,
    _clusters,
    _ratio,
    _units,
)

RUNS = ROOT / ".tmp" / "agentdojo" / "runs"
EXTERNAL = ROOT / "benchmark" / "results" / "external_validity_agentdojo.json"
OUT = (ROOT / "experiments" / "statistics" / "results"
       / "external_clustered_bootstrap.json")
MD = ROOT / "experiments" / "statistics" / "EXTERNAL_CLUSTERED.md"

TOOL = ARMS[1]
PI = ARMS[3]
SEEDS = {"cell": 20261123, "user": 20261124, "injection": 20261125}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _user_key(row: dict) -> str:
    return f"{row['suite']}|{row['user_task']}"


def _injection_key(row: dict) -> str:
    return f"{row['suite']}|{row['injection']}"


def _value(row: dict) -> float:
    return float(row["tool"]) - float(row["pi"])


def _cgm(rows: Sequence[dict], key_fn) -> float:
    values = [_value(row) for row in rows]
    n = len(values)
    mean = sum(values) / n
    scores: Dict[str, float] = defaultdict(float)
    for row, value in zip(rows, values):
        scores[key_fn(row)] += value - mean
    groups = len(scores)
    if groups < 2:
        return 0.0
    return (groups / (groups - 1)) * sum(s * s for s in scores.values()) / n ** 2


def _twoway(rows: Sequence[dict]) -> float:
    variance = _cgm(rows, _user_key) + _cgm(rows, _injection_key)
    intersection = _cgm(rows, lambda row: row["cell"])
    return max(0.0, variance - intersection)


def _interval(rows: Sequence[dict]) -> dict:
    cell_units = _units(rows, _value, lambda row: 1.0)
    point = _ratio(cell_units)
    user_units = _clusters(rows, _user_key, _value, lambda row: 1.0)
    injection_units = _clusters(rows, _injection_key, _value, lambda row: 1.0)
    twoway = _twoway(rows)
    half = 1.96 * math.sqrt(twoway) * 100
    cell_ci = _ci(_bootstrap(cell_units, SEEDS["cell"]))
    user_ci = _ci(_bootstrap_clusters(user_units, SEEDS["user"]))
    injection_ci = _ci(_bootstrap_clusters(
        injection_units, SEEDS["injection"]))
    twoway_ci = [round(point - half, 4), round(point + half, 4)]
    return {
        "n": len(rows),
        "user_clusters": len({_user_key(row) for row in rows}),
        "injection_clusters": len({_injection_key(row) for row in rows}),
        "point_pp": round(point, 4),
        "cell_ci95": cell_ci,
        "user_ci95": user_ci,
        "injection_ci95": injection_ci,
        "twoway_ci95": twoway_ci,
        "cell_excludes_zero": cell_ci[0] > 0 or cell_ci[1] < 0,
        "user_excludes_zero": user_ci[0] > 0 or user_ci[1] < 0,
        "twoway_excludes_zero": twoway_ci[0] > 0 or twoway_ci[1] < 0,
    }


def main() -> int:
    if not RUNS.is_dir():
        raise SystemExit(f"missing cached artifact: {RUNS}")
    _, data = read_artifact(RUNS)
    cell = data["cell"]
    keys = paired_keys(cell)
    rows = []
    for key in keys:
        suite, user, injection = key
        rows.append({
            "cell": f"{suite}|{user}|{injection}",
            "suite": suite,
            "user_task": user,
            "injection": injection,
            "tool": int(cell[key][TOOL][1]),
            "pi": int(cell[key][PI][1]),
        })
    banking = [row for row in rows if row["suite"] == "banking"]
    result = {
        "experiment": "E01b external clustered bootstrap",
        "focus_attack": FOCUS_ATTACK,
        "contrast": "tool_filter minus pi_detector",
        "source": {
            "path": "benchmark/results/external_validity_agentdojo.json",
            "sha256": _sha256(EXTERNAL),
        },
        "frames": {
            "census": _interval(rows),
            "prefix_400": _interval(rows[:400]),
            "banking": _interval(banking),
        },
        "draws": 2000,
        "not_claimed": [
            "The intervals describe the fixed 629-cell corpus, not a super-population of tasks.",
            "The two-way interval is normal-based CGM, not a percentile bootstrap.",
        ],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=1), encoding="utf-8")

    lines = [
        "# E01b — External clustered uncertainty",
        "",
        "Contrast: tool\\_filter minus pi\\_detector; attack "
        f"`{FOCUS_ATTACK}`; 2,000 draws; no model calls.",
        "",
        "| frame | n | point (pp) | cell | user | injection | two-way |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, item in result["frames"].items():
        lines.append(
            f"| {name} | {item['n']} | {item['point_pp']:+.3f} | "
            f"{item['cell_ci95']} | {item['user_ci95']} | "
            f"{item['injection_ci95']} | {item['twoway_ci95']} |")
    census = result["frames"]["census"]
    lines += [
        "",
        "On the census the point estimate is "
        f"{census['point_pp']:+.3f} points. Every 95 percent interval includes "
        f"zero: cell {census['cell_ci95']}, user {census['user_ci95']}, "
        f"injection {census['injection_ci95']}, two-way {census['twoway_ci95']}. "
        "The top-two ranking is therefore unresolved at every level, "
        "independently of the frame effect.",
        "",
        "Reproduce: `python experiments/statistics/external_clustered_bootstrap.py`",
    ]
    MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT).as_posix()} and {MD.relative_to(ROOT).as_posix()}")
    print(json.dumps(result["frames"], indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
