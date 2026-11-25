"""Deterministic checks behind the Claim Auditor CLI.

Every function takes plain dictionaries and returns plain dictionaries. There
is no model call, no network access, and no hidden state.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import re
from pathlib import Path
from typing import Any, Dict, List, Sequence

from .schema import CLAIM_TYPES, DESIGN_FIELDS, HEX_DIGITS, METRIC_FIELDS, validate_report

METRIC_LABELS = {
    "attack_trace_block_rate": "attack trace block rate",
    "benign_trace_block_rate": "benign trace block rate",
    "human_review_rate": "human review rate",
    "benign_step_block_fpr": "benign step block FPR",
    "end_to_end_asr": "end-to-end ASR",
    "benign_task_utility": "benign task utility",
}

ASR_WORDS = ("asr", "attack success")


def inspect_report(report: Dict[str, Any]) -> Dict[str, Any]:
    design = report.get("design", {})
    metrics = report.get("metrics", {})
    uncertainty = report.get("uncertainty", {})
    missing = [field for field in DESIGN_FIELDS if field not in design]
    return {
        "system": report.get("system"),
        "benchmark": report.get("benchmark"),
        "protocol": report.get("protocol"),
        "design": {field: design.get(field) for field in DESIGN_FIELDS},
        "metrics": {name: metrics.get(name) for name in METRIC_FIELDS
                    if name in metrics},
        "metrics_without_interval": sorted(
            name for name in metrics if name not in uncertainty),
        "missing_design_fields": missing,
        "provenance": report.get("provenance", {}),
    }


def identify(report: Dict[str, Any]) -> Dict[str, Any]:
    design = report.get("design", {})
    errors = validate_report(report)
    can_population = bool(design.get("sampling_frame")) and bool(
        design.get("frame_size"))
    can_mechanism = bool(design.get("aggregation_rule")) and bool(
        design.get("enforcement_semantics"))
    can_attribution = design.get("attribution_source") == "gate_side"
    notes = []
    if design.get("attribution_source") == "outcome_only":
        notes.append(
            "outcome-only reports cannot support a causal attribution claim; "
            "they can support population or mechanism comparisons.")
    if design.get("frame_size") in (1,):
        notes.append("a one-unit frame cannot support a population claim.")
    return {
        "valid": not errors,
        "errors": errors,
        "design_vector": {field: design.get(field) for field in DESIGN_FIELDS},
        "can_enter": {
            "population": can_population,
            "mechanism": can_mechanism,
            "attribution": can_attribution,
        },
        "notes": notes,
    }


def _coverage(report: Dict[str, Any]) -> float | None:
    value = report.get("evidence", {}).get("attribution_coverage")
    return float(value) if isinstance(value, (int, float)) else None


def _design_differences(left: Dict[str, Any],
                        right: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    left_design = left.get("design", {})
    right_design = right.get("design", {})
    return {
        field: {"left": left_design.get(field), "right": right_design.get(field)}
        for field in DESIGN_FIELDS
        if left_design.get(field) != right_design.get(field)
    }


def _question_type(changed, systems_differ: bool, coverage_differs: bool,
                   shared: Sequence[str]) -> tuple[str, bool]:
    """Stage 2 only: which single question may this pair answer?

    The design vector permits changing one coordinate at a time. A mechanism
    change must hold every design coordinate fixed; a population comparison may
    move only the frame; a design-sensitivity comparison may move only the
    enforcement semantics or only the aggregation rule.
    """
    if not changed:
        if systems_differ:
            return "mechanism", True
        if coverage_differs:
            return "descriptive", True
        return "same_design", True
    if changed == {"enforcement_semantics"} or changed == {"aggregation_rule"}:
        return "design_sensitivity", True
    if changed <= {"sampling_frame", "frame_size"}:
        return "population", True
    if changed == {"attribution_source"}:
        if set(shared) == {"end_to_end_asr"}:
            return "descriptive", True
        return "attribution", True
    return "not_comparable", False


def compare(left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    """Four-stage comparison: schema, question, identifiability, ranking.

    Stage 2 must finish before the unknown-REVIEW branch is reached. Otherwise a
    confounded pair (a mechanism change plus a frame change) could be reported
    as a bounded interval comparison merely because both reports declare
    bounds.
    """
    # Stage 1: report schema.
    left_errors = validate_report(left)
    right_errors = validate_report(right)
    if left_errors or right_errors:
        return {
            "comparable": False,
            "comparison_type": "invalid",
            "licensed": False,
            "errors": {"left": left_errors, "right": right_errors},
        }

    shared = sorted(set(left.get("metrics", {})) & set(right.get("metrics", {})))
    if not shared:
        return {
            "comparable": False,
            "comparison_type": "not_comparable",
            "licensed": False,
            "reason": "no shared metric with the same definition",
        }

    definition_mismatches = []
    for name in shared:
        left_entry = left.get("uncertainty", {}).get(name, {})
        right_entry = right.get("uncertainty", {}).get(name, {})
        if left_entry.get("unit") != right_entry.get("unit"):
            definition_mismatches.append({
                "metric": name,
                "field": "unit",
                "left": left_entry.get("unit"),
                "right": right_entry.get("unit"),
            })
        left_denominator = left_entry.get("denominator")
        right_denominator = right_entry.get("denominator")
        if left_denominator != right_denominator:
            definition_mismatches.append({
                "metric": name,
                "field": "denominator",
                "left": left_denominator,
                "right": right_denominator,
            })
    if definition_mismatches:
        return {
            "comparable": False,
            "comparison_type": "not_comparable",
            "licensed": False,
            "shared_metrics": shared,
            "definition_mismatches": definition_mismatches,
            "reason": ("a shared metric is defined with a different unit or "
                       "denominator; the two values do not measure the same "
                       "quantity"),
        }

    differences = _design_differences(left, right)
    changed = set(differences)
    systems_differ = left.get("system") != right.get("system")
    benchmarks_differ = left.get("benchmark") != right.get("benchmark")
    protocols_differ = left.get("protocol") != right.get("protocol")
    left_coverage = _coverage(left)
    right_coverage = _coverage(right)
    coverage_differs = left_coverage != right_coverage
    evidence_coverage = {"left": left_coverage, "right": right_coverage}

    # Stage 2a: common benchmark and protocol.
    if benchmarks_differ or protocols_differ:
        return {
            "comparable": False,
            "comparison_type": "not_comparable",
            "licensed": False,
            "shared_metrics": shared,
            "differences": differences,
            "evidence_coverage": evidence_coverage,
            "note": ("The benchmark or protocol differs; without a declared "
                     "common protocol the reports are not comparable."),
        }

    # Stage 2b: one question at a time. A mechanism change cannot be combined
    # with any design-coordinate change, including a frame change.
    if systems_differ and changed:
        return {
            "comparable": False,
            "comparison_type": "not_comparable",
            "licensed": False,
            "shared_metrics": shared,
            "differences": differences,
            "evidence_coverage": evidence_coverage,
            "note": ("The mechanism and a design coordinate both change; the "
                     "comparison is confounded and answers no single question."),
        }
    comparison, licensed = _question_type(
        changed, systems_differ, coverage_differs, shared)
    if not licensed:
        return {
            "comparable": False,
            "comparison_type": "not_comparable",
            "licensed": False,
            "shared_metrics": shared,
            "differences": differences,
            "evidence_coverage": evidence_coverage,
            "note": ("More than one coordinate differs, or the changed "
                     "coordinates do not form one admissible question."),
        }

    # Stage 3: identifiability. Only now may unknown REVIEW semantics replace a
    # point comparison with a bounded one.
    block_metrics = sorted(
        set(shared) & {"attack_trace_block_rate", "benign_trace_block_rate"})
    unknown_semantics = (
        left.get("design", {}).get("enforcement_semantics") == "unknown"
        or right.get("design", {}).get("enforcement_semantics") == "unknown")
    if unknown_semantics and block_metrics:
        have_bounds = all(
            all(metric in report.get("bounds", {}) for metric in block_metrics)
            for report in (left, right))
        if not have_bounds:
            return {
                "comparable": False,
                "comparison_type": "interval_only",
                "licensed": False,
                "strict_ranking_licensed": False,
                "question": comparison,
                "shared_metrics": shared,
                "differences": differences,
                "evidence_coverage": evidence_coverage,
                "note": ("Unknown REVIEW semantics do not identify a point "
                         "block rate. Compare declared bounds only; a point "
                         "comparison is not licensed."),
            }
        difference_bounds = {}
        strict = True
        for metric in block_metrics:
            left_low, left_high = (float(value)
                                   for value in left["bounds"][metric])
            right_low, right_high = (float(value)
                                     for value in right["bounds"][metric])
            low = left_low - right_high
            high = left_high - right_low
            disjoint = low > 0.0 or high < 0.0
            difference_bounds[metric] = {
                "left_minus_right": [round(low, 6), round(high, 6)],
                "intervals_overlap": not disjoint,
                "strict_ranking": disjoint,
            }
            strict = strict and disjoint
        return {
            "comparable": True,
            "comparison_type": "interval_comparison",
            "licensed": True,
            "strict_ranking_licensed": strict,
            "question": comparison,
            "shared_metrics": shared,
            "differences": differences,
            "evidence_coverage": evidence_coverage,
            "difference_bounds": difference_bounds,
            "note": ("Both reports declare bounds for the block metrics. The "
                     "comparison is a bounded interval comparison; a strict "
                     "ranking is licensed only where the difference interval "
                     "excludes zero. Overlapping intervals leave the sign "
                     "undetermined." if not strict else
                     "Both reports declare bounds and every difference interval "
                     "excludes zero; the ordering is identified in sign, but "
                     "the magnitudes remain intervals."),
        }

    # Stage 4: the question passed and the metrics are point-identified.
    notes = {
        "same_design": ("The two reports share one design; differences are "
                        "sampling or run variation."),
        "mechanism": ("Different defense mechanisms under the same protocol and "
                      "design vector; this is a mechanism comparison, not a "
                      "design-sensitivity comparison."),
        "design_sensitivity": ("The same mechanism is evaluated under a "
                               "different rule or semantics; report both "
                               "semantics for a gate with a REVIEW state."),
        "population": ("Frames differ but the mechanism is the same. Verify "
                       "that both frames are subsets of one declared "
                       "population."),
        "attribution": ("Attribution differs. A causal reading needs the "
                        "gate-side report to cover the flips; a concordant "
                        "record is intervention evidence, not causal "
                        "attribution."),
        "descriptive": ("The reports share a metric but not an admissible "
                        "causal question; the comparison is descriptive."),
    }
    return {
        "comparable": True,
        "comparison_type": comparison,
        "licensed": True,
        "question": comparison,
        "shared_metrics": shared,
        "differences": differences,
        "evidence_coverage": evidence_coverage,
        "note": notes[comparison],
    }


def sensitivity(reports: Sequence[Dict[str, Any]], metric: str) -> Dict[str, Any]:
    if metric not in METRIC_FIELDS:
        raise ValueError(f"unknown metric: {metric}")
    invalid = []
    for index, report in enumerate(reports):
        errors = validate_report(report)
        if errors:
            invalid.append({"report": index, "errors": errors})
    if invalid:
        return {
            "metric": metric,
            "comparable": False,
            "error": "every report must pass the schema before a design "
                     "envelope is computed",
            "report_errors": invalid,
            "systems": {},
            "pairs": {},
            "max_single_system_width_pp": 0.0,
        }
    benchmarks = sorted({report.get("benchmark") for report in reports},
                        key=str)
    protocols = sorted({report.get("protocol") for report in reports},
                       key=str)
    if len(benchmarks) > 1 or len(protocols) > 1:
        return {
            "metric": metric,
            "comparable": False,
            "error": ("a design envelope may not pool reports from different "
                      "benchmarks or protocols"),
            "benchmarks": benchmarks,
            "protocols": protocols,
            "systems": {},
            "pairs": {},
            "max_single_system_width_pp": 0.0,
        }
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for report in reports:
        value = report.get("metrics", {}).get(metric)
        if value is None:
            continue
        design = report.get("design", {})
        groups.setdefault(report.get("system", "unknown"), []).append({
            "design": {field: design.get(field) for field in DESIGN_FIELDS},
            "value": float(value),
        })
    systems = {}
    for name, entries in groups.items():
        low = min(entries, key=lambda item: item["value"])
        high = max(entries, key=lambda item: item["value"])
        systems[name] = {
            "n": len(entries),
            "min": {"design": low["design"], "value": low["value"]},
            "max": {"design": high["design"], "value": high["value"]},
            "width_pp": round(100 * (high["value"] - low["value"]), 4),
        }

    pairs = {}
    for left, right in itertools.combinations(sorted(groups), 2):
        left_by_design = {
            tuple(sorted(entry["design"].items())): entry["value"]
            for entry in groups[left]}
        right_by_design = {
            tuple(sorted(entry["design"].items())): entry["value"]
            for entry in groups[right]}
        shared = sorted(set(left_by_design) & set(right_by_design))
        if not shared:
            continue
        differences = [100 * (left_by_design[key] - right_by_design[key])
                       for key in shared]
        pairs[f"{left}_minus_{right}"] = {
            "shared_designs": len(shared),
            "min_pp": round(min(differences), 4),
            "max_pp": round(max(differences), 4),
            "sign_change": min(differences) < 0 < max(differences),
        }

    return {
        "metric": metric,
        "comparable": True,
        "systems": systems,
        "pairs": pairs,
        "max_single_system_width_pp": round(
            max((item["width_pp"] for item in systems.values()), default=0.0), 4),
    }


def _claim_uses_asr_wording(claim: str) -> bool:
    text = claim.lower()
    return any(word in text for word in ASR_WORDS)


CAUSAL_PATTERN = re.compile(
    r"\b(caused|causes|cause|prevented|prevents|prevent|attributable|"
    r"credited|due to the gate|because of the gate)\b")
NEGATED_CAUSAL_PATTERN = re.compile(
    r"\b(did not|does not|do not|cannot|can't|no evidence that|not)\b"
    r"(?:\s+\w+){0,3}\s+(cause|prevent|attribut|credit)")
EQUIVALENCE_PATTERN = re.compile(
    r"\b(no difference|not different|equivalent|same effect|tie)\b")


def _asserts_causal(text: str) -> bool:
    """Clause-level causal detection.

    A global negation check is wrong here: ``caused the improvement, not the
    model`` asserts a gate effect while negating a rival explanation. Only the
    clause that contains the causal verb is inspected for a negation.
    """
    for clause in re.split(r"(?<=[.;])\s+|,\s+", text.lower()):
        if NEGATED_CAUSAL_PATTERN.search(clause):
            continue
        if CAUSAL_PATTERN.search(clause):
            return True
    return False


def _asserts_equivalence(text: str) -> bool:
    return bool(EQUIVALENCE_PATTERN.search(text.lower()))


def _claims_zero_equality(text: str) -> bool:
    lowered = text.lower()
    if "reversal" not in lowered:
        return False
    if "crossing" in lowered or "not equal" in lowered:
        return False
    return ("zero" in lowered or "equal" in lowered or "exactly" in lowered)


def _finite_number(value: Any) -> bool:
    return (isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(float(value)))


def _difference_pair(value: Any) -> list[float] | None:
    """A paired difference interval on the rate scale, or None."""
    if (not isinstance(value, list) or len(value) != 2
            or any(not _finite_number(entry) for entry in value)):
        return None
    low, high = float(value[0]), float(value[1])
    if not -1.0 <= low <= high <= 1.0:
        return None
    return [low, high]


def _equivalence_error(report: Dict[str, Any],
                       item: Dict[str, Any]) -> str | None:
    """Equivalence needs a paired contrast, not one group's interval."""
    contrast = item.get("contrast")
    if not isinstance(contrast, dict):
        return ("an equivalence claim requires item.contrast with left, right, "
                "paired, difference_ci95, equivalence_margin, and method; a "
                "single-group confidence interval is not a contrast")
    required = ("left", "right", "paired", "difference_ci95",
                "equivalence_margin", "method")
    missing = [field for field in required if field not in contrast]
    if missing:
        return ("equivalence contrast is missing required field(s): "
                + ", ".join(missing))
    left = contrast.get("left")
    right = contrast.get("right")
    if (not isinstance(left, str) or not left.strip()
            or not isinstance(right, str) or not right.strip()):
        return "equivalence contrast must name both reports as non-empty strings"
    if left == right:
        return "equivalence contrast must compare two different reports"
    if report.get("system") not in (left, right):
        return ("equivalence contrast must identify the report system as one "
                "of its two sides")
    if contrast.get("paired") is not True:
        return "equivalence contrast must declare paired=true"
    interval = _difference_pair(contrast.get("difference_ci95"))
    if interval is None:
        return ("equivalence contrast needs difference_ci95 = [low, high] with "
                "-1 <= low <= high <= 1")
    margin = contrast.get("equivalence_margin")
    if (not _finite_number(margin) or float(margin) <= 0.0
            or float(margin) > 0.5):
        return ("equivalence_margin must be a finite number in (0, 0.5]")
    method = contrast.get("method")
    if not isinstance(method, str) or not method.strip():
        return "equivalence contrast must declare a non-empty method"
    report_margin = report.get("evidence", {}).get("equivalence_margin")
    if report_margin is not None:
        if not _finite_number(report_margin):
            return "report evidence.equivalence_margin must be numeric"
        if not math.isclose(float(report_margin), float(margin),
                            rel_tol=0.0, abs_tol=1e-12):
            return ("contrast equivalence_margin does not match the report's "
                    "pre-specified margin")
    if not (interval[0] >= -float(margin)
            and interval[1] <= float(margin)):
        return (f"the paired difference interval {interval} is not contained "
                f"in the pre-specified equivalence margin "
                f"[-{float(margin)}, +{float(margin)}]")
    return None


def _counterfactual_error(report: Dict[str, Any],
                          root: Path | str | None,
                          metric: str | None,
                          item: Dict[str, Any]) -> str | None:
    """A causal claim needs a verifiable, semantically matching artifact."""
    counterfactual = report.get("evidence", {}).get("counterfactual")
    if not isinstance(counterfactual, dict):
        return ("causal claim requires an evidence.counterfactual object with "
                "source and sha256; a boolean is not evidence")
    source = counterfactual.get("source")
    digest = counterfactual.get("sha256")
    if not isinstance(source, str) or not source.strip():
        return "counterfactual.source must be a non-empty relative path"
    if (not isinstance(digest, str) or len(digest) != 64
            or any(char not in HEX_DIGITS for char in digest)):
        return "counterfactual.sha256 must be a lowercase hex digest"
    if root is None:
        return ("counterfactual evidence cannot be verified without a root; "
                "pass --root so the source file and digest can be checked")
    base = Path(root).resolve()
    path = (base / source).resolve()
    if path != base and base not in path.parents:
        return "counterfactual.source escapes the declared root"
    if not path.is_file():
        return f"counterfactual.source {source!r} is not a file"
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != digest:
        return (f"counterfactual.source hashes to {actual}, not the declared "
                f"{digest}")
    if counterfactual.get("scientific_values_preserved") is not True:
        return ("counterfactual.scientific_values_preserved must be true after "
                "a field-level comparison")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "counterfactual.source is not a JSON evidence document"
    if not isinstance(document, dict):
        return "counterfactual.source must contain a JSON object"
    required = ("system", "benchmark", "metric", "unit", "n",
                "estimate_pp", "design")
    missing = [field for field in required if field not in document]
    if missing:
        return ("counterfactual evidence is missing required field(s): "
                + ", ".join(missing))
    if document.get("system") != report.get("system"):
        return "counterfactual evidence belongs to a different mechanism"
    if document.get("benchmark") != report.get("benchmark"):
        return "counterfactual evidence belongs to a different benchmark"
    if metric is not None and document.get("metric") != metric:
        return "counterfactual evidence addresses a different metric"
    unit = document.get("unit")
    if not isinstance(unit, str) or not unit.strip():
        return "counterfactual evidence must declare a non-empty unit"
    reported_unit = report.get("uncertainty", {}).get(metric or "", {}).get(
        "unit")
    if reported_unit is not None and unit != reported_unit:
        return (f"counterfactual evidence uses unit {unit!r}, but the report "
                f"declares {reported_unit!r} for {metric}")
    if (not isinstance(document.get("n"), int)
            or isinstance(document.get("n"), bool)
            or document["n"] <= 0):
        return "counterfactual evidence must declare a positive integer n"
    reported_n = report.get("design", {}).get("frame_size")
    if isinstance(reported_n, int) and document["n"] != reported_n:
        return (f"counterfactual evidence has n={document['n']}, but the "
                f"report declares frame_size={reported_n}")
    estimate = document.get("estimate_pp")
    if (not isinstance(estimate, (int, float))
            or isinstance(estimate, bool)
            or not math.isfinite(float(estimate))
            or abs(float(estimate)) > 100.0):
        return ("counterfactual evidence must declare a finite estimate_pp "
                "in [-100, 100]")
    design = document.get("design")
    if (not isinstance(design, dict)
            or not isinstance(design.get("treatment"), str)
            or not design["treatment"].strip()
            or not isinstance(design.get("control"), str)
            or not design["control"].strip()):
        return ("counterfactual evidence must name a treatment and a control "
                "as non-empty strings")
    if design["treatment"] == design["control"]:
        return ("counterfactual evidence must use different treatment and "
                "control conditions")
    expected = item.get("expected_effect")
    if expected not in ("positive", "negative", "nonzero"):
        return ("a causal claim must declare expected_effect as 'positive', "
                "'negative', or 'nonzero'")
    value = float(estimate)
    if expected == "positive" and value <= 0.0:
        return ("expected_effect='positive' contradicts estimate_pp="
                f"{value}")
    if expected == "negative" and value >= 0.0:
        return ("expected_effect='negative' contradicts estimate_pp="
                f"{value}")
    if expected == "nonzero" and value == 0.0:
        return "expected_effect='nonzero' contradicts estimate_pp=0"
    return None


def claims(report: Dict[str, Any],
           claim_list: Sequence[Dict[str, Any]],
           root: Path | str | None = None) -> Dict[str, Any]:
    report_errors = validate_report(report)
    if report_errors:
        message = "report schema is invalid: " + "; ".join(report_errors)
        results = [{
            "claim": str(item.get("claim", "")),
            "claim_type": item.get("claim_type"),
            "metric": item.get("metric"),
            "value": item.get("value"),
            "tolerance": item.get("tolerance", 0.0),
            "contract_valid": False,
            "eligible_for_causal_assessment": False,
            "causal_validity_established": False,
            "passed": False,
            "errors": [message],
        } for item in claim_list]
        return {
            "passed": False,
            "contract_valid": False,
            "causal_validity_established": False,
            "report_errors": report_errors,
            "results": results,
        }

    results = []
    design = report.get("design", {})
    for item in claim_list:
        if not isinstance(item, dict):
            results.append({
                "claim": str(item),
                "claim_type": None,
                "metric": None,
                "value": None,
                "tolerance": 0.0,
                "contract_valid": False,
                "eligible_for_causal_assessment": False,
                "causal_validity_established": False,
                "passed": False,
                "errors": ["a claim must be a JSON object"],
            })
            continue
        name = item.get("metric")
        if not isinstance(name, str):
            name = None
        text = str(item.get("claim", ""))
        value = item.get("value")
        raw_tolerance = item.get("tolerance", 0.0)
        claim_type = item.get("claim_type")
        errors = []
        tolerance_valid = (
            _finite_number(raw_tolerance)
            and 0.0 <= float(raw_tolerance) <= 0.05)
        tolerance = float(raw_tolerance) if tolerance_valid else 0.0
        reported = report.get("metrics", {}).get(name)
        if name not in METRIC_FIELDS:
            errors.append(f"unknown metric {name!r}")
        elif reported is None:
            errors.append(f"metric {name!r} is not reported")
        else:
            if not _finite_number(value):
                errors.append("claim value must be a finite number")
            elif abs(float(value) - float(reported)) > tolerance:
                errors.append(
                    f"claimed {value} but the report has {reported} "
                    f"(tolerance {tolerance})")
        if not tolerance_valid:
            errors.append("tolerance must be a finite number in [0, 0.05]")
        if name == "attack_trace_block_rate" and _claim_uses_asr_wording(text):
            errors.append(
                "an attack trace block rate is not an attack success rate")

        claim_protocol = item.get("protocol")
        if claim_protocol is not None:
            if not isinstance(claim_protocol, str) or not claim_protocol.strip():
                errors.append(
                    "claim protocol must be a non-empty string when present")
            elif claim_protocol != report.get("protocol"):
                errors.append(
                    "claim protocol does not match the report protocol")
        claim_denominator = item.get("denominator")
        report_denominator = report.get("uncertainty", {}).get(name, {}).get(
            "denominator")
        if claim_denominator is not None:
            if (not isinstance(claim_denominator, str)
                    or not claim_denominator.strip()):
                errors.append(
                    "claim denominator must be a non-empty string when present")
            elif claim_denominator != report_denominator:
                errors.append(
                    "claim denominator does not match the report metric "
                    "denominator")

        if claim_type is None:
            errors.append(
                "claim_type is required; use one of "
                f"{CLAIM_TYPES}")
        elif claim_type not in CLAIM_TYPES:
            errors.append(
                f"claim_type must be one of {CLAIM_TYPES}, got {claim_type!r}")

        # Natural language is an auxiliary signal, never the licence.
        if _asserts_causal(text) and claim_type != "causal":
            errors.append(
                "causal wording requires claim_type='causal' and a "
                "verifiable counterfactual artifact")
        if _asserts_equivalence(text) and claim_type != "equivalence":
            errors.append(
                "equivalence wording requires claim_type='equivalence' and "
                "a paired contrast with a pre-specified margin; "
                "non-significance is not equivalence")
        block_metric = name in ("attack_trace_block_rate",
                                "benign_trace_block_rate")
        unknown_semantics = (
            design.get("enforcement_semantics") == "unknown")
        if (block_metric and unknown_semantics
                and claim_type in ("descriptive", "point")):
            errors.append(
                "unknown REVIEW semantics do not identify a point block "
                "rate; use claim_type='interval' with the report bounds")
        if _claims_zero_equality(text):
            errors.append(
                "a discrete composition set may not contain an exact zero "
                "gap; define the distance as crossing (g >= 0), or report "
                "tie and strict distances separately")

        if claim_type == "causal":
            if design.get("attribution_source") != "gate_side":
                errors.append(
                    "a causal claim requires gate-side attribution")
            coverage = _coverage(report)
            if coverage is None or coverage <= 0.0:
                errors.append(
                    "a causal claim requires positive attribution_coverage; "
                    "zero coverage cannot support it")
            problem = _counterfactual_error(report, root, name, item)
            if problem:
                errors.append(problem)
        elif claim_type == "equivalence":
            problem = _equivalence_error(report, item)
            if problem:
                errors.append(problem)
        elif claim_type == "point":
            if unknown_semantics:
                errors.append(
                    "a point claim is not identified under unknown REVIEW "
                    "semantics; use claim_type='interval'")
        elif claim_type == "interval":
            bounds = item.get("bounds")
            report_bounds = report.get("bounds", {}).get(name)
            if report_bounds is None:
                errors.append(
                    "an interval claim requires report.bounds for the metric; "
                    "a caller may not invent an interval")
            elif (not isinstance(bounds, list) or len(bounds) != 2
                    or any(not _finite_number(entry) for entry in bounds)
                    or not 0.0 <= float(bounds[0]) <= float(bounds[1]) <= 1.0):
                errors.append(
                    "an interval claim requires item.bounds = [low, high] "
                    "with 0 <= low <= high <= 1")
            elif any(abs(float(entry) - float(reference)) > 1e-12
                     for entry, reference in zip(bounds, report_bounds)):
                errors.append(
                    "item.bounds must equal report.bounds[metric]; narrowing "
                    "or shifting the interval is not permitted")
            elif _finite_number(value) and not (
                    float(bounds[0]) <= float(value) <= float(bounds[1])):
                errors.append(
                    "the claimed value lies outside the declared bounds")
        passed = not errors
        results.append({
            "claim": text,
            "claim_type": claim_type,
            "metric": name,
            "value": value,
            "tolerance": tolerance if tolerance_valid else raw_tolerance,
            "contract_valid": passed,
            "eligible_for_causal_assessment": bool(
                claim_type == "causal" and passed),
            "causal_validity_established": False,
            "passed": passed,
            "errors": errors,
        })
    passed = all(item["passed"] for item in results)
    return {
        "passed": passed,
        "contract_valid": passed,
        "causal_validity_established": False,
        "note": ("Contract validity is not causal validity; the auditor checks "
                 "the declared evidence, not the truth of a counterfactual "
                 "model."),
        "results": results,
    }


def render_markdown(report: Dict[str, Any], validation: Dict[str, Any],
                    identification: Dict[str, Any],
                    claims_result: Dict[str, Any] | None = None) -> str:
    lines = [
        f"# Claim audit: {report.get('system', 'unknown')}",
        "",
        f"- Benchmark: `{report.get('benchmark')}`",
        f"- Valid: {validation.get('valid')}",
        f"- Design: `{identification['design_vector']}`",
        "",
        "## Licensed comparison types",
        "",
        f"- Population: {identification['can_enter']['population']}",
        f"- Mechanism: {identification['can_enter']['mechanism']}",
        f"- Attribution: {identification['can_enter']['attribution']}",
        "",
        "## Metrics",
        "",
        "| metric | value | interval | unit |",
        "|---|---|---|---|",
    ]
    for name, value in report.get("metrics", {}).items():
        uncertainty = report.get("uncertainty", {}).get(name, {})
        interval = uncertainty.get("ci95")
        lines.append(
            f"| {name} | {value} | "
            f"{interval if interval is not None else 'missing'} | "
            f"{uncertainty.get('unit', '')} |")
    if claims_result is not None:
        lines += ["", "## Claims", ""]
        for item in claims_result["results"]:
            status = "pass" if item["passed"] else "fail"
            lines.append(f"- [{status}] {item['claim']}")
            for error in item["errors"]:
                lines.append(f"  - {error}")
    return "\n".join(lines) + "\n"
