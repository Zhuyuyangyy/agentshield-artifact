"""E2, first pass: compare the aggregation rules on recorded cell evidence.

Four rules, one decision function. The question this answers is not "does the
band split block more" but "does it differ at all from the simplest rule that
also protects hard risk".

  no_relaxation  S = max(H, P)                       (authorization ignored)
  global_cap     S = min(max(H, P), tau)             (authorization caps all)
  band_split     S = max(H, min(P, tau))             (v0.4.1)
  hard_first     BLOCK if H >= 0.90, else decision(global_cap)

where H folds in the structural components and intervention value, P is the
peak suppressible provenance score, and tau is the lowest authorization cap.
The rules are evaluated on the twelve recorded control cells and on an
exhaustive grid of (H, P, tau), so a difference that only exists in the grid is
reported as such rather than attributed to the cells.

Exit status is 0 whether or not the rules differ; the result is the artifact.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.shield.risk_signals import (
    SUPPRESSIBLE_PROVENANCE_SIGNALS,
    SUPPRESSION_EVIDENCE_SIGNALS,
    RiskSignalType,
)
from app.shield.v3_engine import _action_for_score

MATRIX = ROOT / "benchmark" / "results" / "authorization_invariant_matrix" / "matrix.json"
OUT = ROOT / "benchmark" / "results" / "aggregation_rule_comparison.json"

BLOCK_THRESHOLD = 0.90
GRID = (0.0, 0.3, 0.55, 0.59, 0.6, 0.7, 0.89, 0.9, 0.95, 1.0)
TAU_GRID = (None, 0.3, 0.55, 0.6, 0.7, 0.9)


def _classify(signal: Dict[str, Any]) -> str:
    try:
        kind = RiskSignalType(signal["signal_type"])
    except ValueError:
        return "hard"  # unknown types fail closed, as combined_risk does
    if kind in SUPPRESSIBLE_PROVENANCE_SIGNALS:
        return "suppressible"
    if kind in SUPPRESSION_EVIDENCE_SIGNALS:
        return "evidence"
    return "hard"  # unclassified signal types are hard in the engine


def _components(cell: Dict[str, Any]) -> Tuple[float, float, Optional[float]]:
    structural = cell["structural"]
    hard = [
        structural.get("local_risk", 0.0),
        structural.get("inherited_risk", 0.0),
        structural.get("path_risk", 0.0),
        structural.get("downstream_exposure", 0.0),
    ]
    suppressible: List[float] = []
    caps: List[float] = []
    for signal in cell.get("signals", []):
        band = _classify(signal)
        if band == "suppressible":
            suppressible.append(float(signal.get("score", 0.0)))
        elif band == "hard":
            hard.append(float(signal.get("score", 0.0)))
        elif signal.get("caps_risk") is not None:
            caps.append(float(signal["caps_risk"]))
    h = max(hard, default=0.0)
    h = max(h, float(structural.get("intervention_value", 0.0)))
    p = max(suppressible, default=0.0)
    tau = min(caps) if caps else None
    return h, p, tau


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


def _normalise_action(action: str) -> str:
    """The matrix records lowercase actions; the engine returns uppercase."""
    action = action.upper()
    return "REVIEW" if action in ("HUMAN_REVIEW", "REVIEW") else action


def scores(h: float, p: float, tau: Optional[float]) -> Dict[str, float]:
    no_relaxation = _clamp(max(h, p))
    global_cap = _clamp(min(max(h, p), tau) if tau is not None else max(h, p))
    band_split = _clamp(max(h, min(p, tau)) if tau is not None else max(h, p))
    return {
        "no_relaxation": no_relaxation,
        "global_cap": global_cap,
        "band_split": band_split,
    }


def actions(h: float, p: float, tau: Optional[float]) -> Dict[str, str]:
    s = scores(h, p, tau)
    hard_first = "BLOCK" if h >= BLOCK_THRESHOLD else _action_for_score(s["global_cap"])
    return {
        "no_relaxation": _action_for_score(s["no_relaxation"]),
        "global_cap": _action_for_score(s["global_cap"]),
        "band_split": _action_for_score(s["band_split"]),
        "hard_first": hard_first,
    }


def evaluate_cells() -> List[Dict[str, Any]]:
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    rows: List[Dict[str, Any]] = []
    for cell in matrix["cells"]:
        h, p, tau = _components(cell)
        s = scores(h, p, tau)
        a = {k: _normalise_action(v) for k, v in actions(h, p, tau).items()}
        engine_action = _normalise_action(cell["engine_decision"])
        rows.append({
            "cell_id": cell["cell_id"],
            "auth": cell["auth"],
            "risk": cell["risk"],
            "actuation": cell["actuation"],
            "engine_decision": cell["engine_decision"],
            "engine_risk_score": cell["engine_risk_score"],
            "components": {"H": h, "P": p, "tau": tau},
            "scores": {k: round(v, 4) for k, v in s.items()},
            "actions": a,
            "band_split_matches_engine": a["band_split"] == engine_action,
        })
    return rows


def _count_actions(rows: Iterable[Dict[str, Any]], rule: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for row in rows:
        action = row["actions"][rule]
        counts[action] = counts.get(action, 0) + 1
    return counts


def evaluate_grid() -> Dict[str, Any]:
    diffs_bs_hf = 0
    diffs_bs_gc = 0
    diffs_bs_nr = 0
    pairs: Dict[str, int] = {}
    hf_pairs: Dict[str, int] = {}
    hf_examples: Dict[str, Dict[str, float]] = {}
    for h in GRID:
        for p in GRID:
            for tau in TAU_GRID:
                a = {k: _normalise_action(v) for k, v in actions(h, p, tau).items()}
                if a["band_split"] != a["hard_first"]:
                    diffs_bs_hf += 1
                    key = f"{a['band_split']}->{a['hard_first']}"
                    hf_pairs[key] = hf_pairs.get(key, 0) + 1
                    hf_examples.setdefault(
                        key,
                        {"H": h, "P": p, "tau": tau,
                         "band_split_score": scores(h, p, tau)["band_split"]},
                    )
                if a["band_split"] != a["global_cap"]:
                    diffs_bs_gc += 1
                if a["band_split"] != a["no_relaxation"]:
                    diffs_bs_nr += 1
                key = f"{a['band_split']}->{a['global_cap']}"
                pairs[key] = pairs.get(key, 0) + 1
    return {
        "points": len(GRID) ** 2 * len(TAU_GRID),
        "band_split_vs_hard_first_action_differences": diffs_bs_hf,
        "band_split_vs_global_cap_action_differences": diffs_bs_gc,
        "band_split_vs_no_relaxation_action_differences": diffs_bs_nr,
        "band_split_to_global_cap_pairs": dict(sorted(pairs.items())),
        "band_split_to_hard_first_pairs": dict(sorted(hf_pairs.items())),
        "band_split_to_hard_first_examples": hf_examples,
    }


def main() -> int:
    cells = evaluate_cells()
    grid = evaluate_grid()

    cell_diff_bs_hf = [
        row["cell_id"] for row in cells
        if row["actions"]["band_split"] != row["actions"]["hard_first"]
    ]
    cell_diff_bs_gc = [
        row["cell_id"] for row in cells
        if row["actions"]["band_split"] != row["actions"]["global_cap"]
    ]
    payload = {
        "experiment": "aggregation_rule_comparison",
        "tier": "rule_level",
        "source_matrix": MATRIX.relative_to(ROOT).as_posix(),
        "thresholds": {
            "block": 0.90,
            "review": 0.60,
            "hard_first_priority_uses": "H >= block threshold",
        },
        "rules": {
            "no_relaxation": "S = max(H, P)",
            "global_cap": "S = min(max(H, P), tau)",
            "band_split": "S = max(H, min(P, tau))",
            "hard_first": "BLOCK if H >= 0.90 else action(global_cap)",
        },
        "cells": cells,
        "cell_summary": {
            "n_cells": len(cells),
            "actions": {
                rule: _count_actions(cells, rule)
                for rule in ("no_relaxation", "global_cap", "band_split", "hard_first")
            },
            "band_split_matches_engine_decisions": sum(
                1 for row in cells if row["band_split_matches_engine"]),
            "band_split_vs_hard_first_differences": cell_diff_bs_hf,
            "band_split_vs_global_cap_differences": cell_diff_bs_gc,
        },
        "grid": grid,
    }
    OUT.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(f"wrote {OUT.relative_to(ROOT)}")
    print(f"  cells: {len(cells)}  band_split==engine: "
          f"{payload['cell_summary']['band_split_matches_engine_decisions']}/{len(cells)}")
    for rule, counts in payload["cell_summary"]["actions"].items():
        print(f"  {rule:14s} {counts}")
    print(f"  cells BS vs HF: {len(cell_diff_bs_hf)} difference(s) {cell_diff_bs_hf}")
    print(f"  cells BS vs GC: {len(cell_diff_bs_gc)} difference(s)")
    print(f"  grid points: {grid['points']}")
    print(f"  grid BS vs HF action differences: "
          f"{grid['band_split_vs_hard_first_action_differences']}")
    print(f"  grid BS vs GC action differences: "
          f"{grid['band_split_vs_global_cap_action_differences']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
