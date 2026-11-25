"""Joint design and sampling uncertainty (E04).

T03 reports a range over declared designs; E01 reports a sampling interval at
the census. This script keeps the two layers separate and states when their
combination licenses a uniform-dominance claim.

For each contrast the output records:

  * the design envelope (min, max, sign) from T03;
  * the point estimate and paired cell bootstrap interval at every design
    configuration, recomputed from the frozen outcomes with E01's seed so the
    census cell interval matches E01 exactly;
  * the clustered census intervals from E01 (user, injection, two-way);
  * one verdict: set_identity, not_resolvable, census_cell_only, sign_change,
    or strict_uniform.

A strict uniform-dominance claim is licensed only when the design envelope
excludes zero, every configuration's cell interval excludes zero, and the
clustered census intervals also exclude zero. No contrast in this corpus meets
all three conditions.

Outputs
-------
experiments/sensitivity/results/joint.json
experiments/sensitivity/JOINT.md

Run:
    python experiments/sensitivity/joint.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.statistics.clustered_bootstrap import (  # noqa: E402
    _block_value,
    _bootstrap,
    _ci,
    _units,
    load_rows,
)

REANALYSIS = ROOT / "benchmark" / "results" / "measurement_reanalysis.json"
ENVELOPE = ROOT / "experiments" / "sensitivity" / "results" / "envelope.json"
CLUSTERED = ROOT / "experiments" / "statistics" / "results" / "clustered_bootstrap.json"
OUT = ROOT / "experiments" / "sensitivity" / "results" / "joint.json"
MD = ROOT / "experiments" / "sensitivity" / "JOINT.md"

SEED = 20261123
FRAMES = ("full", "prefix_400")
SEMANTICS = ("log_and_allow", "block")
PAIRS = (
    ("band_split", "hard_first", "band_minus_hard"),
    ("band_split", "global_cap", "band_minus_global"),
)
CLUSTERED_KEYS = {
    ("band_minus_hard", "log_and_allow"): "band_minus_hard|log_and_allow",
    ("band_minus_hard", "block"): "band_minus_hard|block",
    ("band_minus_global", "block"): "band_minus_global|block",
}


def _neg(value: float) -> float:
    return 0.0 if value == 0 else -value


def _oriented(differences: Dict[str, dict], left: str, right: str) -> dict:
    key = f"{left}_minus_{right}"
    if key in differences:
        return differences[key]
    reverse = differences[f"{right}_minus_{left}"]
    flip = {"positive": "negative", "negative": "positive",
            "nonnegative": "nonpositive", "nonpositive": "nonnegative",
            "tie": "tie", "sign_change": "sign_change"}
    return {
        "min": {"config": reverse["max"]["config"],
                "difference_pp": _neg(reverse["max"]["difference_pp"])},
        "max": {"config": reverse["min"]["config"],
                "difference_pp": _neg(reverse["min"]["difference_pp"])},
        "span_pp": reverse["span_pp"],
        "sign": flip[reverse["sign"]],
    }


def _point_ci(rows: Sequence[dict], value_fn) -> Tuple[float, List[float]]:
    units = _units(rows, value_fn, lambda row: 1.0)
    point = 100.0 * sum(value for value, _ in units) / len(units)
    return round(point, 4), _ci(_bootstrap(units, SEED))


def _excludes_zero(interval: Sequence[float], point: float) -> bool:
    if point == 0 and interval[0] == 0 and interval[1] == 0:
        return False
    return interval[0] > 0 or interval[1] < 0


def _clustered(entry: dict) -> dict:
    keys = ("cell_ci95", "user_cluster_ci95", "injection_cluster_ci95",
            "twoway_ci95")
    intervals = {key: entry[key] for key in keys if key in entry}
    point = entry["point_pp"]
    return {
        "point_pp": point,
        "intervals": intervals,
        "excludes_zero": {
            key: _excludes_zero(value, point) for key, value in intervals.items()
        },
        "all_exclude_zero": all(
            _excludes_zero(value, point) for value in intervals.values()),
    }


def _verdict(design_min: float, design_max: float, configs: Sequence[dict],
             clustered: dict) -> Tuple[str, str]:
    if design_min == 0 and design_max == 0:
        return ("set_identity",
                "The two rules block identical trace sets at every configuration.")
    if design_min < 0 < design_max:
        return ("sign_change",
                "The design envelope contains both signs, so no ranking is "
                "uniform over the declared designs.")
    any_excl = any(item["excludes_zero"] for item in configs)
    all_excl = all(item["excludes_zero"] for item in configs)
    if design_min > 0 and all_excl and clustered["all_exclude_zero"]:
        return ("strict_uniform",
                "The design envelope is positive and every cell and clustered "
                "interval excludes zero.")
    if any_excl:
        return ("census_cell_only",
                "Some configuration excludes zero, but the design envelope or "
                "the clustered census intervals do not support a uniform claim.")
    return ("not_resolvable",
            "Every interval includes zero; the point estimate is below the "
            "design's resolution.")


def _contrast(rows_attack: Sequence[dict], rows_benign: Sequence[dict],
              pair: Tuple[str, str, str], metric: str,
              design: dict, clustered_entry: dict) -> dict:
    rule_a, rule_b, _ = pair
    configs = []
    for semantics in SEMANTICS:
        value_fn = _block_value(rule_a, rule_b, semantics)
        if metric == "attack_trace_block_rate":
            for frame in FRAMES:
                subset = rows_attack if frame == "full" else rows_attack[:400]
                point, interval = _point_ci(subset, value_fn)
                configs.append({
                    "frame": frame,
                    "semantics": semantics,
                    "point_pp": point,
                    "cell_ci95": interval,
                    "excludes_zero": _excludes_zero(interval, point),
                })
        else:
            point, interval = _point_ci(rows_benign, value_fn)
            configs.append({
                "frame": "full",
                "semantics": semantics,
                "point_pp": point,
                "cell_ci95": interval,
                "excludes_zero": _excludes_zero(interval, point),
            })
    clustered = _clustered(clustered_entry)
    verdict, reason = _verdict(design["min"]["difference_pp"],
                               design["max"]["difference_pp"],
                               configs, clustered)
    return {
        "metric": metric,
        "design_envelope": design,
        "configurations": configs,
        "clustered_census": clustered,
        "verdict": verdict,
        "reason": reason,
        "uniform_dominance_licensed": verdict == "strict_uniform",
    }


def main() -> int:
    rows = load_rows()
    attack = [row for row in rows if row["label"] == "attack"]
    benign = [row for row in rows if row["label"] == "benign"]
    if len(attack) != 10439 or len(benign) != 97:
        raise SystemExit("unexpected frozen row counts")
    if attack[:400] and abs(100 * sum(
            row["blocked"]["no_relaxation"]["block"] for row in attack[:400])
            / 400 - 10.5) > 1e-9:
        raise SystemExit("the first 400 attack rows are not the published prefix")

    reanalysis = json.loads(REANALYSIS.read_text(encoding="utf-8"))
    for rule in ("no_relaxation", "global_cap", "band_split", "hard_first"):
        for semantics in SEMANTICS:
            expected = reanalysis["frames"]["published_prefix"][
                f"{rule}|{semantics}"]["attack_trace_block_rate"]
            observed = 100 * sum(
                row["blocked"][rule][semantics] for row in attack[:400]) / 400
            if abs(observed - 100 * expected) > 5e-4:
                raise SystemExit(
                    f"prefix mismatch for {rule}|{semantics}: "
                    f"{observed} vs {100 * expected}")

    envelope = json.loads(ENVELOPE.read_text(encoding="utf-8"))
    clustered = json.loads(CLUSTERED.read_text(encoding="utf-8"))
    attack_env = envelope["study1"]["attack_trace_block_rate"]["between_system"]
    benign_env = envelope["study1"]["benign_trace_block_rate"]["between_system"]

    contrasts = {}
    for rule_a, rule_b, short in PAIRS:
        for metric, design_source, clustered_key in (
            ("attack_trace_block_rate", attack_env,
             CLUSTERED_KEYS[(short, "block")]),
            ("benign_trace_block_rate", benign_env, None),
        ):
            design = _oriented(design_source, rule_a, rule_b)
            if metric == "attack_trace_block_rate":
                entry = clustered["contrasts"][clustered_key]["attack"]
            elif short == "band_minus_hard":
                entry = clustered["contrasts"]["band_minus_hard|block"]["benign"]
            else:
                entry = clustered["contrasts"]["band_minus_global|block"]["benign"]
            contrasts[f"{short}|{metric}"] = _contrast(
                attack, benign, (rule_a, rule_b, short), metric, design, entry)

    study2 = envelope["study2"]["between_system"]["tool_filter_minus_pi_detector"]
    study2_entry = {
        "design_envelope": study2,
        "verdict": "sign_change",
        "reason": "The design envelope contains both signs, so no ranking is "
                  "uniform over the declared frames.",
        "uniform_dominance_licensed": False,
        "clustered_census": None,
    }

    result = {
        "experiment": "E04 joint design and sampling uncertainty",
        "inputs": {
            "envelope": "experiments/sensitivity/results/envelope.json",
            "clustered": "experiments/statistics/results/clustered_bootstrap.json",
            "outcomes": "benchmark/results/e2b_trajectory_outcomes.jsonl",
        },
        "rule": (
            "A strict uniform-dominance claim requires (i) a one-sign design "
            "envelope that excludes zero, (ii) every configuration's paired "
            "cell interval excluding zero, and (iii) the clustered census "
            "intervals excluding zero. Any failure downgrades the verdict."),
        "contrasts": contrasts,
        "study2_top_two": study2_entry,
        "summary": {
            "strict_uniform_claims": sum(
                1 for item in contrasts.values()
                if item["uniform_dominance_licensed"]),
            "licensed_claims": [],
            "verdicts": {name: item["verdict"]
                         for name, item in contrasts.items()},
        },
        "not_claimed": [
            "No confidence interval is attached to the design envelope; it is "
            "a range over enumerated configurations.",
            "No uniform-dominance claim is licensed anywhere in this corpus.",
            "The prefix has no clustered interval; clustering is reported at "
            "the census only.",
            "Study 2 has no per-step actions, so only its frame envelope is used.",
        ],
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=1), encoding="utf-8")

    lines = [
        "# E04 — Joint design and sampling uncertainty",
        "",
        "Design envelopes from T03, paired cell intervals recomputed from the "
        "frozen outcomes (seed 20261123), clustered census intervals from E01.",
        "",
        "## Rule",
        "",
        result["rule"],
        "",
        "## Contrasts",
        "",
        "| contrast | design min | design max | configs excluding 0 | "
        "census clustered excludes 0 | verdict |",
        "|---|---|---|---|---|---|",
    ]
    for name, item in contrasts.items():
        design = item["design_envelope"]
        configs = sum(1 for config in item["configurations"]
                      if config["excludes_zero"])
        clustered_ok = item["clustered_census"]["all_exclude_zero"]
        lines.append(
            f"| {name} | {design['min']['difference_pp']:+.3f} | "
            f"{design['max']['difference_pp']:+.3f} | "
            f"{configs}/{len(item['configurations'])} | "
            f"{'yes' if clustered_ok else 'no'} | {item['verdict']} |")
    lines += [
        "",
        "The band-split-minus-hard-first attack contrast is a set identity, not "
        "a sampling question: every configuration and every resample gives "
        "exactly zero. The band-split-minus-global-cap attack contrast is "
        "positive at the census (cell interval excludes zero) but exactly zero "
        "on the prefix and not supported by the user or two-way census "
        "intervals. The benign contrasts have positive point estimates but "
        "intervals that include zero.",
        "",
        f"Study 2 top two: design envelope "
        f"[{study2['min']['difference_pp']:+.2f}, "
        f"{study2['max']['difference_pp']:+.2f}] pp, sign change; no sampling "
        "interval can license a uniform ranking.",
        "",
        "## What is not claimed",
        "",
        *[f"- {item}" for item in result["not_claimed"]],
        "",
        "Reproduce: `python experiments/sensitivity/joint.py`",
    ]
    MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT).as_posix()} and {MD.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
