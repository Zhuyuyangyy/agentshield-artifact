"""Claim Auditor CLI.

Zero model calls, deterministic output, JSON or Markdown. The auditor checks a
structured evidence contract, not the causal validity of a counterfactual.

    python -m tools.gate_audit.cli inspect REPORT
    python -m tools.gate_audit.cli validate REPORT [--format json|markdown]
    python -m tools.gate_audit.cli identify REPORT
    python -m tools.gate_audit.cli compare LEFT RIGHT [--format json|markdown]
    python -m tools.gate_audit.cli sensitivity REPORT... [--metric NAME]
    python -m tools.gate_audit.cli claims REPORT CLAIMS [--format json|markdown]
    python -m tools.gate_audit.cli report REPORT [--claims CLAIMS]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from . import core
from .schema import METRIC_FIELDS, validate_report


def _load(path: str) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def _validate_markdown(report: Dict[str, Any], errors: Sequence[str]) -> str:
    lines = [
        f"# Validation: {report.get('system', 'unknown')}",
        "",
        f"- Valid: {not errors}",
        f"- Errors: {len(errors)}",
    ]
    lines += [f"- {error}" for error in errors]
    return "\n".join(lines) + "\n"


def _compare_markdown(result: Dict[str, Any]) -> str:
    lines = [
        "# Comparison",
        "",
        f"- Type: {result.get('comparison_type')}",
        f"- Licensed: {result.get('licensed', result.get('comparable'))}",
        f"- Note: {result.get('note', result.get('reason', ''))}",
        "",
        "| field | left | right |",
        "|---|---|---|",
    ]
    for field, values in result.get("differences", {}).items():
        lines.append(f"| {field} | {values['left']} | {values['right']} |")
    return "\n".join(lines) + "\n"


def _sensitivity_markdown(result: Dict[str, Any]) -> str:
    lines = [
        f"# Sensitivity: {result['metric']}",
        "",
        "| system | n | min | max | width (pp) |",
        "|---|---|---|---|---|",
    ]
    for name, item in result["systems"].items():
        lines.append(
            f"| {name} | {item['n']} | {item['min']['value']:.4f} | "
            f"{item['max']['value']:.4f} | {item['width_pp']:.2f} |")
    lines += ["", f"Maximum single-system width: {result['max_single_system_width_pp']:.2f} pp"]
    if result.get("comparable") is False:
        lines += ["", f"Not comparable: {result.get('error', 'unknown reason')}"]
    return "\n".join(lines) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="gate-audit")
    sub = parser.add_subparsers(dest="command", required=True)

    inspect_p = sub.add_parser("inspect")
    inspect_p.add_argument("report")

    validate_p = sub.add_parser("validate")
    validate_p.add_argument("report")
    validate_p.add_argument("--format", choices=("json", "markdown"), default="json")

    identify_p = sub.add_parser("identify")
    identify_p.add_argument("report")

    compare_p = sub.add_parser("compare")
    compare_p.add_argument("left")
    compare_p.add_argument("right")
    compare_p.add_argument("--format", choices=("json", "markdown"), default="json")

    sensitivity_p = sub.add_parser("sensitivity")
    sensitivity_p.add_argument("reports", nargs="+")
    sensitivity_p.add_argument("--metric", choices=METRIC_FIELDS,
                               default="attack_trace_block_rate")
    sensitivity_p.add_argument("--format", choices=("json", "markdown"), default="json")

    claims_p = sub.add_parser("claims")
    claims_p.add_argument("report")
    claims_p.add_argument("claims")
    claims_p.add_argument("--format", choices=("json", "markdown"), default="json")
    claims_p.add_argument("--root", default=".",
                          help="root for verifying counterfactual evidence paths")

    report_p = sub.add_parser("report")
    report_p.add_argument("report")
    report_p.add_argument("--claims")
    report_p.add_argument("--root", default=".")
    report_p.add_argument("--format", choices=("json", "markdown"), default="markdown")

    args = parser.parse_args(argv)

    if args.command == "inspect":
        _print_json(core.inspect_report(_load(args.report)))
        return 0

    if args.command == "validate":
        report = _load(args.report)
        errors = validate_report(report)
        if args.format == "markdown":
            print(_validate_markdown(report, errors), end="")
        else:
            _print_json({"valid": not errors, "errors": errors})
        return 0 if not errors else 1

    if args.command == "identify":
        _print_json(core.identify(_load(args.report)))
        return 0

    if args.command == "compare":
        result = core.compare(_load(args.left), _load(args.right))
        if args.format == "markdown":
            print(_compare_markdown(result), end="")
        else:
            _print_json(result)
        return 0 if result.get("licensed", result.get("comparable")) else 1

    if args.command == "sensitivity":
        reports = [_load(path) for path in args.reports]
        result = core.sensitivity(reports, args.metric)
        if args.format == "markdown":
            print(_sensitivity_markdown(result), end="")
        else:
            _print_json(result)
        return 0 if result.get("comparable", True) else 1

    if args.command == "claims":
        report = _load(args.report)
        claim_list = json.loads(Path(args.claims).read_text(encoding="utf-8"))
        result = core.claims(report, claim_list, root=args.root)
        if args.format == "markdown":
            print(core.render_markdown(
                report,
                {"valid": not validate_report(report)},
                core.identify(report),
                result), end="")
        else:
            _print_json(result)
        return 0 if result["passed"] else 1

    if args.command == "report":
        report = _load(args.report)
        errors = validate_report(report)
        claims_result = None
        if args.claims:
            claim_list = json.loads(Path(args.claims).read_text(encoding="utf-8"))
            claims_result = core.claims(report, claim_list, root=args.root)
        if args.format == "json":
            _print_json({
                "validation": {"valid": not errors, "errors": errors},
                "identification": core.identify(report),
                "claims": claims_result,
            })
        else:
            print(core.render_markdown(
                report, {"valid": not errors}, core.identify(report),
                claims_result), end="")
        return 0 if not errors and (
            claims_result is None or claims_result["passed"]) else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
