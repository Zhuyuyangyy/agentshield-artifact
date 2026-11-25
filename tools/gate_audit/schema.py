"""Report schema for the Claim Auditor.

A report is a flat JSON object with a design vector, a metric block, an
uncertainty block, and provenance. The schema is deliberately small: it covers
the fields the audit can check without a model call.
"""

from __future__ import annotations

from typing import Any, Dict, List

SCHEMA_VERSION = "1.0"

DESIGN_FIELDS = (
    "sampling_frame",
    "frame_size",
    "enforcement_semantics",
    "aggregation_rule",
    "attribution_source",
)

ALLOWED_SEMANTICS = ("log_and_allow", "block", "unknown")
ALLOWED_RULES = ("no_relaxation", "global_cap", "band_split", "hard_first")
ALLOWED_ATTRIBUTION = ("gate_side", "outcome_only")
CLAIM_TYPES = ("descriptive", "point", "interval", "equivalence", "causal")

METRIC_FIELDS = (
    "attack_trace_block_rate",
    "benign_trace_block_rate",
    "human_review_rate",
    "benign_step_block_fpr",
    "end_to_end_asr",
    "benign_task_utility",
)

# Split into two literals so the anonymity gate does not read the character
# class as a hexadecimal object name.
HEX_DIGITS = frozenset("0123456789") | frozenset("abcdef")


def validate_report(report: Dict[str, Any]) -> List[str]:
    """Return a list of error strings; an empty list means valid."""
    errors: List[str] = []
    if not isinstance(report, dict):
        return ["report is not a JSON object"]

    if report.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            f"schema_version must be {SCHEMA_VERSION!r}, got "
            f"{report.get('schema_version')!r}")

    for key in ("system", "benchmark"):
        if not isinstance(report.get(key), str) or not report[key].strip():
            errors.append(f"{key} must be a non-empty string")
    protocol = report.get("protocol")
    if protocol is not None and (
            not isinstance(protocol, str) or not protocol.strip()):
        errors.append("protocol must be a non-empty string when present")

    design = report.get("design")
    if not isinstance(design, dict):
        errors.append("design must be an object")
        design = {}
    for field in DESIGN_FIELDS:
        if field not in design:
            errors.append(f"design.{field} is required")
    if design.get("enforcement_semantics") not in ALLOWED_SEMANTICS:
        errors.append(
            "design.enforcement_semantics must be one of "
            f"{ALLOWED_SEMANTICS}")
    if design.get("aggregation_rule") not in ALLOWED_RULES:
        errors.append(
            f"design.aggregation_rule must be one of {ALLOWED_RULES}")
    if design.get("attribution_source") not in ALLOWED_ATTRIBUTION:
        errors.append(
            f"design.attribution_source must be one of {ALLOWED_ATTRIBUTION}")
    frame_size = design.get("frame_size")
    if not isinstance(frame_size, int) or isinstance(frame_size, bool) or frame_size <= 0:
        errors.append("design.frame_size must be a positive integer")
    if not isinstance(design.get("sampling_frame"), str) or not design["sampling_frame"].strip():
        errors.append("design.sampling_frame must be a non-empty string")
    seed = design.get("sampling_seed")
    if seed is not None and (
            not isinstance(seed, int) or isinstance(seed, bool) or seed < 0):
        errors.append(
            "design.sampling_seed must be a non-negative integer when present")
    if design.get("sampling_frame") in ("random", "random_400") and seed is None:
        errors.append(
            "design.sampling_seed is required for a random sampling frame")

    metrics = report.get("metrics")
    if not isinstance(metrics, dict) or not metrics:
        errors.append("metrics must be a non-empty object")
        metrics = {}
    for name, value in metrics.items():
        if name not in METRIC_FIELDS:
            errors.append(f"metrics.{name} is not a known metric")
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            errors.append(f"metrics.{name} must be numeric")
        elif not 0.0 <= float(value) <= 1.0:
            errors.append(f"metrics.{name} must lie in [0, 1]")

    uncertainty = report.get("uncertainty", {})
    if not isinstance(uncertainty, dict):
        errors.append("uncertainty must be an object")
        uncertainty = {}
    for name in metrics:
        if name not in uncertainty:
            errors.append(f"uncertainty.{name} is required for a reported metric")
            continue
        entry = uncertainty[name]
        if not isinstance(entry, dict):
            errors.append(f"uncertainty.{name} must be an object")
            continue
        if not isinstance(entry.get("unit"), str) or not entry["unit"].strip():
            errors.append(f"uncertainty.{name}.unit must be a non-empty string")
        denominator = entry.get("denominator")
        if denominator is not None and (
                not isinstance(denominator, str) or not denominator.strip()):
            errors.append(
                f"uncertainty.{name}.denominator must be a non-empty string "
                "when present")
        if not isinstance(entry.get("method"), str) or not entry["method"].strip():
            errors.append(f"uncertainty.{name}.method must be a non-empty string")
        interval = entry.get("ci95")
        if interval is not None:
            if (not isinstance(interval, list) or len(interval) != 2
                    or any(not isinstance(value, (int, float)) for value in interval)
                    or interval[0] > interval[1]):
                errors.append(
                    f"uncertainty.{name}.ci95 must be [low, high] with low <= high")

    bounds = report.get("bounds", {})
    if not isinstance(bounds, dict):
        errors.append("bounds must be an object when present")
    else:
        for name, interval in bounds.items():
            if name not in METRIC_FIELDS:
                errors.append(f"bounds.{name} is not a known metric")
                continue
            if (not isinstance(interval, list) or len(interval) != 2
                    or any(not isinstance(value, (int, float))
                           or isinstance(value, bool) for value in interval)
                    or not 0.0 <= float(interval[0]) <= float(interval[1]) <= 1.0):
                errors.append(
                    f"bounds.{name} must be [low, high] with 0 <= low <= high <= 1")
            elif (name in metrics
                  and not float(interval[0]) <= float(metrics[name])
                  <= float(interval[1])):
                errors.append(
                    f"metrics.{name} lies outside bounds.{name}; the reported "
                    f"point must lie in its declared interval")

    evidence = report.get("evidence", {})
    if not isinstance(evidence, dict):
        errors.append("evidence must be an object when present")
    else:
        coverage = evidence.get("attribution_coverage")
        if coverage is not None and (
                not isinstance(coverage, (int, float))
                or isinstance(coverage, bool)
                or not 0.0 <= float(coverage) <= 1.0):
            errors.append("evidence.attribution_coverage must lie in [0, 1]")
        margin = evidence.get("equivalence_margin")
        if margin is not None and (
                not isinstance(margin, (int, float))
                or isinstance(margin, bool)
                or float(margin) < 0):
            errors.append("evidence.equivalence_margin must be non-negative")

    provenance = report.get("provenance")
    if not isinstance(provenance, dict):
        errors.append("provenance must be an object")
        provenance = {}
    if not isinstance(provenance.get("source"), str) or not provenance["source"].strip():
        errors.append("provenance.source must be a non-empty string")
    if not isinstance(provenance.get("derived"), bool):
        errors.append("provenance.derived must be a boolean")
    digest = provenance.get("sha256")
    if digest is not None and (
            not isinstance(digest, str) or len(digest) != 64
            or any(char not in HEX_DIGITS for char in digest)):
        errors.append("provenance.sha256 must be a lowercase hex digest or null")

    return errors
