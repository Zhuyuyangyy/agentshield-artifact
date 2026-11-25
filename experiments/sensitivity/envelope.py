"""Design sensitivity envelope (T03).

Two pre-declared design sets, both finite:

  Study 1  4 aggregation rules x 2 enforcement semantics x 2 frames
           (census, published 400-trace prefix) = 16 configurations.
           The benign rate is frame-invariant because the prefix truncates
           attack traces only, so it has 8 distinct values.
  Study 2  5 defenses x 3 frames (629-cell census, 400-cell prefix, banking
           suite) = 15 configurations.

For each system (rule or defense) the script reports the envelope of its metric
across the design set and the width max - min in percentage points. For each
pair it reports the paired difference envelope. A uniform-dominance claim is
licensed only when the difference envelope excludes zero; a joint claim over
two metrics also requires that the second metric not reverse. Sampling
uncertainty is deliberately not combined here; E04 does that.

Outputs
-------
experiments/sensitivity/results/envelope.json
experiments/sensitivity/ENVELOPE.md

Run:
    python experiments/sensitivity/envelope.py
"""

from __future__ import annotations

import hashlib
import json
from itertools import combinations
from pathlib import Path
from typing import Dict, List, Sequence

ROOT = Path(__file__).resolve().parents[2]
REANALYSIS = ROOT / "benchmark" / "results" / "measurement_reanalysis.json"
EXTERNAL = ROOT / "benchmark" / "results" / "external_validity_agentdojo.json"
OUTCOMES = ROOT / "benchmark" / "results" / "e2b_trajectory_outcomes.jsonl"
OUT = ROOT / "experiments" / "sensitivity" / "results" / "envelope.json"
MD = ROOT / "experiments" / "sensitivity" / "ENVELOPE.md"

STUDY1_RULES = ("no_relaxation", "global_cap", "band_split", "hard_first")
STUDY1_FRAMES = ("full", "published_prefix")
STUDY1_SEMANTICS = ("log_and_allow", "block")
STUDY2_FRAMES = ("census", "prefix_400", "banking")
FOCUS_PAIR = ("band_split", "hard_first")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _exact_ratio() -> dict:
    """Count-based width and contrast for the headline ratio.

    The frozen reanalysis stores rates rounded to five decimals, so a ratio
    computed from them inherits rounding. The outcomes carry one Boolean per
    trace, which yields the exact integer counts over the same denominator.
    """
    rows = [json.loads(line) for line in OUTCOMES.read_text(
        encoding="utf-8").splitlines() if line.strip()]
    attack = sorted((row for row in rows if row["label"] == "attack"),
                    key=lambda row: row["index"])
    prefix = attack[:400]
    n = len(attack)

    def count(data, rule: str, policy: str) -> int:
        return sum(1 for row in data if row["blocked"][rule][policy])

    band_log = count(attack, "band_split", "log_and_allow")
    band_block = count(attack, "band_split", "block")
    global_block = count(attack, "global_cap", "block")
    prefix_band = count(prefix, "band_split", "block")
    prefix_global = count(prefix, "global_cap", "block")
    width_numerator = band_block - band_log
    contrast_numerator = (band_block - global_block) - (prefix_band - prefix_global)
    return {
        "definition": (
            "attack counts over the same denominator: (block - log) for the "
            "band-split width, and (census difference - prefix difference) "
            "for the band-minus-global span"),
        "denominator": n,
        "band_split": {
            "log_blocked": band_log,
            "block_blocked": band_block,
            "width_numerator": width_numerator,
            "width_pp": round(100 * width_numerator / n, 4),
        },
        "band_minus_global": {
            "census_numerator": band_block - global_block,
            "prefix_numerator": prefix_band - prefix_global,
            "span_numerator": contrast_numerator,
            "span_pp": round(100 * contrast_numerator / n, 4),
        },
        "ratio": round(width_numerator / contrast_numerator, 2)
        if contrast_numerator else None,
    }


def _envelope(readings: Sequence[dict]) -> dict:
    ordered = sorted(readings, key=lambda item: item["value"])
    low = ordered[0]
    high = ordered[-1]
    return {
        "min": {"config": low["config"], "value": round(low["value"], 4)},
        "max": {"config": high["config"], "value": round(high["value"], 4)},
        "width_pp": round(high["value"] - low["value"], 4),
    }


def _sign(low: float, high: float) -> str:
    if low > 0:
        return "positive"
    if low == 0 and high > 0:
        return "nonnegative"
    if high == 0 and low < 0:
        return "nonpositive"
    if high < 0:
        return "negative"
    if low == 0 and high == 0:
        return "tie"
    return "sign_change"


def _differences(readings: Dict[str, List[dict]]) -> Dict[str, dict]:
    """Paired difference envelopes for every system pair."""
    systems = list(readings)
    result = {}
    for left, right in combinations(systems, 2):
        left_by_config = {item["config"]: item["value"] for item in readings[left]}
        right_by_config = {item["config"]: item["value"] for item in readings[right]}
        pairs = []
        for config in left_by_config:
            pairs.append({
                "config": config,
                "difference_pp": round(left_by_config[config]
                                      - right_by_config[config], 4),
            })
        ordered = sorted(pairs, key=lambda item: item["difference_pp"])
        low = ordered[0]
        high = ordered[-1]
        result[f"{left}_minus_{right}"] = {
            "min": low,
            "max": high,
            "span_pp": round(high["difference_pp"] - low["difference_pp"], 4),
            "sign": _sign(low["difference_pp"], high["difference_pp"]),
        }
    return result


def _oriented(differences: Dict[str, dict], left: str, right: str) -> dict:
    """Return the difference envelope for left minus right, in that order."""
    key = f"{left}_minus_{right}"
    if key in differences:
        return differences[key]
    reverse = differences[f"{right}_minus_{left}"]
    flip = {"positive": "negative", "negative": "positive",
            "nonnegative": "nonpositive", "nonpositive": "nonnegative",
            "tie": "tie", "sign_change": "sign_change"}
    return {
        "min": {"config": reverse["max"]["config"],
                "difference_pp": -reverse["max"]["difference_pp"]},
        "max": {"config": reverse["min"]["config"],
                "difference_pp": -reverse["min"]["difference_pp"]},
        "span_pp": reverse["span_pp"],
        "sign": flip[reverse["sign"]],
    }


def _study1(data: dict) -> dict:
    frames = data["frames"]
    result = {}
    for metric in ("attack_trace_block_rate", "benign_trace_block_rate"):
        readings: Dict[str, List[dict]] = {rule: [] for rule in STUDY1_RULES}
        for frame in STUDY1_FRAMES:
            for semantics in STUDY1_SEMANTICS:
                for rule in STUDY1_RULES:
                    key = f"{rule}|{semantics}"
                    value = 100.0 * frames[frame][key][metric]
                    readings[rule].append({
                        "config": f"{frame}|{semantics}",
                        "value": value,
                    })
        envelopes = {rule: _envelope(items) for rule, items in readings.items()}
        differences = _differences(readings)
        result[metric] = {
            "envelopes": envelopes,
            "between_system": differences,
            "distinct_values": sorted({
                item["value"] for items in readings.values() for item in items}),
        }
    result["review_step_rate_pct"] = {
        rule: {
            "min": round(100 * min(
                frames[frame][f"{rule}|{semantics}"]["benign_review_step_rate"]
                for frame in STUDY1_FRAMES for semantics in STUDY1_SEMANTICS), 4),
            "max": round(100 * max(
                frames[frame][f"{rule}|{semantics}"]["benign_review_step_rate"]
                for frame in STUDY1_FRAMES for semantics in STUDY1_SEMANTICS), 4),
        }
        for rule in STUDY1_RULES
    }
    return result


def _study2(data: dict) -> dict:
    frames = data["frames"]
    arms = list(frames["full_paired"]["asr_pct"])
    short = {
        "gpt-4o-2024-05-13": "none",
        "gpt-4o-2024-05-13-tool_filter": "tool_filter",
        "gpt-4o-2024-05-13-spotlighting_with_delimiting": "spotlighting",
        "gpt-4o-2024-05-13-transformers_pi_detector": "pi_detector",
        "gpt-4o-2024-05-13-repeat_user_prompt": "repeat_user_prompt",
    }
    source = {
        "census": frames["full_paired"]["asr_pct"],
        "prefix_400": frames["prefix_400"]["asr_pct"],
        "banking": frames["suites"]["banking"]["asr_pct"],
    }
    readings: Dict[str, List[dict]] = {short[arm]: [] for arm in arms}
    for frame in STUDY2_FRAMES:
        for arm in arms:
            readings[short[arm]].append({
                "config": frame,
                "value": source[frame][arm],
            })
    envelopes = {name: _envelope(items) for name, items in readings.items()}
    differences = _differences(readings)
    return {
        "envelopes": envelopes,
        "between_system": differences,
        "sign_changes": sorted(
            name for name, item in differences.items()
            if item["sign"] == "sign_change"),
        "frame_values": source,
    }


def main() -> int:
    reanalysis = json.loads(REANALYSIS.read_text(encoding="utf-8"))
    external = json.loads(EXTERNAL.read_text(encoding="utf-8"))

    study1 = _study1(reanalysis)
    study2 = _study2(external)
    attack_differences = study1["attack_trace_block_rate"]["between_system"]
    benign_differences = study1["benign_trace_block_rate"]["between_system"]
    focus = _oriented(attack_differences, FOCUS_PAIR[0], FOCUS_PAIR[1])
    contrast = _oriented(attack_differences, "band_split", "global_cap")
    exact = _exact_ratio()

    result = {
        "experiment": "T03 design sensitivity envelope",
        "inputs": {
            "study1": {
                "path": "benchmark/results/measurement_reanalysis.json",
                "sha256": _sha256(REANALYSIS),
            },
            "study2": {
                "path": "benchmark/results/external_validity_agentdojo.json",
                "sha256": _sha256(EXTERNAL),
            },
        },
        "design_sets": {
            "study1": {
                "frames": list(STUDY1_FRAMES),
                "semantics": list(STUDY1_SEMANTICS),
                "rules": list(STUDY1_RULES),
                "configurations": 16,
                "benign_distinct_values": 8,
                "note": "The prefix truncates attack traces only, so benign readings duplicate across frames.",
            },
            "study2": {
                "frames": list(STUDY2_FRAMES),
                "defenses": 5,
                "configurations": 15,
            },
        },
        "study1": study1,
        "study2": study2,
        "licensing": {
            "rule": (
                "A one-metric uniform-dominance claim requires the paired "
                "difference envelope to exclude zero. A joint claim over attack "
                "and benign rates also requires the second metric not to "
                "reverse. Sampling uncertainty is added in E04."),
            "study1_attack_and_benign": {
                "band_split_vs_hard_first": {
                    "attack": focus,
                    "benign": _oriented(
                        benign_differences, "band_split", "hard_first"),
                    "review_step_rate_pct": {
                        rule: study1["review_step_rate_pct"][rule]
                        for rule in ("band_split", "hard_first")
                    },
                    "joint": "hard first weakly dominates: attack tie, benign "
                             "never higher; review load is also lower.",
                },
                "band_split_vs_global_cap": {
                    "attack": contrast,
                    "benign": _oriented(
                        benign_differences, "band_split", "global_cap"),
                    "joint": "no uniform dominance: the attack edge is "
                             "frame-specific and the benign cost is positive.",
                },
            },
            "study2_top_two": {
                "pair": "tool_filter_minus_pi_detector",
                "difference": study2["between_system"][
                    "tool_filter_minus_pi_detector"],
                "joint": "no uniform ranking: the pair changes sign across frames.",
            },
            "design_to_difference_ratio": {
                "pair": "band_split_minus_global_cap",
                "single_system_width_pp": exact["band_split"]["width_pp"],
                "between_system_span_pp": exact["band_minus_global"]["span_pp"],
                "ratio": exact["ratio"],
                "exact": exact,
            },
        },
        "not_claimed": [
            "The envelope is a range over declared designs, not a confidence interval.",
            "No probability is assigned to any design; the set is enumerated, not sampled.",
            "No claim beyond the four rules, two semantics and three frames listed.",
            "No joint utility claim: the envelope covers trace block rates and ASR only.",
        ],
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=1), encoding="utf-8")

    lines = [
        "# T03 — Design sensitivity envelope",
        "",
        "Both design sets are finite and pre-declared; no model calls.",
        "",
        "## Study 1: 4 rules x 2 semantics x 2 frames",
        "",
        "| rule | attack min | attack max | width (pp) | benign min | benign max | width (pp) |",
        "|---|---|---|---|---|---|---|",
    ]
    for rule in STUDY1_RULES:
        attack = study1["attack_trace_block_rate"]["envelopes"][rule]
        benign = study1["benign_trace_block_rate"]["envelopes"][rule]
        lines.append(
            f"| {rule} | {attack['min']['value']:.2f} | {attack['max']['value']:.2f} | "
            f"{attack['width_pp']:.2f} | {benign['min']['value']:.2f} | "
            f"{benign['max']['value']:.2f} | {benign['width_pp']:.2f} |")
    lines += [
        "",
        "Between-system difference envelopes (attack, pp):",
        "",
        "| pair | min | max | span | sign |",
        "|---|---|---|---|---|",
    ]
    for name, item in study1["attack_trace_block_rate"]["between_system"].items():
        lines.append(
            f"| {name} | {item['min']['difference_pp']:+.2f} | "
            f"{item['max']['difference_pp']:+.2f} | {item['span_pp']:.2f} | "
            f"{item['sign']} |")
    lines += [
        "",
        "The single-system attack width for band split is "
        f"{exact['band_split']['width_pp']:.4f} points "
        f"({exact['band_split']['width_numerator']}/{exact['denominator']}); "
        f"the band-split-minus-global-cap span is "
        f"{exact['band_minus_global']['span_pp']:.4f} points "
        f"({exact['band_minus_global']['span_numerator']}/"
        f"{exact['denominator']}), so the ratio is "
        f"{exact['ratio']:.2f}. Hard first weakly "
        "dominates band split on the reported metrics: identical attack "
        "blocking, lower benign blocking under blocking semantics, and lower "
        f"review load ({study1['review_step_rate_pct']['hard_first']['min']:.3f} "
        f"versus {study1['review_step_rate_pct']['band_split']['min']:.3f} "
        "percent of steps).",
        "",
        "## Study 2: 5 defenses x 3 frames",
        "",
        "| defense | min ASR | max ASR | width (pp) |",
        "|---|---|---|---|",
    ]
    for name, item in study2["envelopes"].items():
        lines.append(
            f"| {name} | {item['min']['value']:.2f} | {item['max']['value']:.2f} | "
            f"{item['width_pp']:.2f} |")
    lines += [
        "",
        f"Sign changes across the 10 defense pairs: "
        f"{len(study2['sign_changes'])} "
        f"({', '.join(study2['sign_changes'])}). "
        "Only the top-two pair reverses; the other nine keep their order.",
        "",
        "## Licensing",
        "",
        result["licensing"]["rule"],
        "",
        "- Band split vs hard first: hard first weakly dominates on both metrics.",
        "- Band split vs global cap: no uniform dominance; the attack edge is "
        "frame-specific and the benign cost is positive.",
        "- Study 2 top two: no uniform ranking; the pair changes sign across frames.",
        "",
        "## What is not claimed",
        "",
        *[f"- {item}" for item in result["not_claimed"]],
        "",
        "Reproduce: `python experiments/sensitivity/envelope.py`",
    ]
    MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT).as_posix()} and {MD.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
