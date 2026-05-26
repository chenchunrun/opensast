"""Structured triage report generator for OpenSAST findings."""

from __future__ import annotations

import argparse
import json
from typing import Any


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def load_findings(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        findings = data.get("findings", [])
        return findings if isinstance(findings, list) else []
    return data if isinstance(data, list) else []


def _matches_focus(finding: dict, focus: str) -> bool:
    if focus == "all":
        return True
    return finding.get("severity", "info").lower() == focus


def _triage_bucket(finding: dict) -> str:
    triage = (finding.get("triage") or {}).get("status")
    if finding.get("is_suppressed") or triage == "false-positive":
        return "false_positive"
    if triage == "needs-review":
        return "needs_review"
    severity = finding.get("severity", "info").lower()
    if severity in {"critical", "high"}:
        return "priority"
    if severity in {"medium", "low"}:
        return "important"
    return "informational"


def triage_findings(findings: list[dict], focus: str = "all") -> dict[str, Any]:
    selected = [f for f in findings if _matches_focus(f, focus)]
    selected.sort(
        key=lambda f: (
            _triage_bucket(f) in {"false_positive", "informational"},
            -SEVERITY_ORDER.get(f.get("severity", "info").lower(), 0),
            f.get("file", ""),
            f.get("start_line", 0),
        )
    )

    buckets = {
        "priority": [],
        "important": [],
        "needs_review": [],
        "false_positive": [],
        "informational": [],
    }
    for finding in selected:
        buckets[_triage_bucket(finding)].append(finding)

    return {
        "focus": focus,
        "total_findings": len(selected),
        "counts": {name: len(items) for name, items in buckets.items()},
        "priority_fix_list": buckets["priority"] + buckets["important"],
        "needs_review": buckets["needs_review"],
        "false_positives": buckets["false_positive"],
        "informational": buckets["informational"],
    }


def generate_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# SAST Triage Report",
        "",
        "## Summary",
        f"- Focus: {report['focus']}",
        f"- Total findings: {report['total_findings']}",
        f"- Priority: {report['counts']['priority']}",
        f"- Important: {report['counts']['important']}",
        f"- Needs review: {report['counts']['needs_review']}",
        f"- False positive / suppressed: {report['counts']['false_positive']}",
        f"- Informational: {report['counts']['informational']}",
        "",
        "## Priority Fix List",
    ]

    if report["priority_fix_list"]:
        for idx, finding in enumerate(report["priority_fix_list"], start=1):
            location = f"{finding.get('file', '?')}:{finding.get('start_line', '?')}"
            lines.append(
                f"{idx}. [{finding.get('severity', 'info').upper()}] {finding.get('title', finding.get('rule_id', 'Untitled'))} — {location}"
            )
    else:
        lines.append("_None_")

    lines.extend(["", "## Needs Review", ""])
    if report["needs_review"]:
        for idx, finding in enumerate(report["needs_review"], start=1):
            location = f"{finding.get('file', '?')}:{finding.get('start_line', '?')}"
            rationale = (finding.get("triage") or {}).get("rationale", "Needs manual validation")
            lines.append(f"{idx}. {finding.get('title', finding.get('rule_id', 'Untitled'))} — {location} — {rationale}")
    else:
        lines.append("_None_")

    lines.extend(["", "## False Positive / Suppressed", ""])
    if report["false_positives"]:
        for idx, finding in enumerate(report["false_positives"], start=1):
            location = f"{finding.get('file', '?')}:{finding.get('start_line', '?')}"
            reason = finding.get("suppression_reason") or (finding.get("triage") or {}).get("rationale", "Suppressed")
            lines.append(f"{idx}. {finding.get('title', finding.get('rule_id', 'Untitled'))} — {location} — {reason}")
    else:
        lines.append("_None_")

    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Triage OpenSAST findings")
    parser.add_argument("--findings", default=".claude/sast/results/findings.json", help="Findings JSON path")
    parser.add_argument("--focus", choices=["critical", "high", "medium", "low", "info", "all"], default="all")
    parser.add_argument("--output", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--output-file", help="Optional output file path")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    findings = load_findings(args.findings)
    report = triage_findings(findings, args.focus)
    rendered = generate_markdown(report) if args.output == "markdown" else json.dumps(report, indent=2, ensure_ascii=False)

    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as f:
            f.write(rendered)
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
