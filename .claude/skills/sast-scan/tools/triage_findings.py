"""Structured triage report generator for OpenSAST findings.

Three-phase triage workflow:
  Phase A — Auto-bucket findings by severity, suppression status, and triage metadata
  Phase B — LLM validate each finding as TP/FP with confidence scoring and code context
  Phase C — Recommend fix priority, generate suppressions for confirmed FPs, export to baseline
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from typing import Any


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

BUCKET_PRIORITY = {
    "priority": 0,
    "important": 1,
    "needs_review": 2,
    "false_positive": 3,
    "informational": 4,
}


# ---------------------------------------------------------------------------
# Phase A: Auto-bucket
# ---------------------------------------------------------------------------

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
            BUCKET_PRIORITY.get(_triage_bucket(f), 99),
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


# ---------------------------------------------------------------------------
# Phase B: LLM validation
# ---------------------------------------------------------------------------

def triage_with_llm_context(findings: list[dict], repo_root: str, focus: str = "all") -> list[dict]:
    """Enrich findings with code context for LLM-based TP/FP validation.

    Returns a list of validation targets, each containing the finding plus
    enough context for Claude to make a triage decision.
    """
    from fix_finding import read_code_context

    selected = [f for f in findings if _matches_focus(f, focus)]
    enriched = []
    for finding in selected:
        context = read_code_context(repo_root, finding, radius=5)
        bucket = _triage_bucket(finding)
        enriched.append({
            "finding": finding,
            "bucket": bucket,
            "code_context": context,
            "validation_prompt": _build_validation_prompt(finding, bucket, context),
        })
    return enriched


def _build_validation_prompt(finding: dict, bucket: str, context: dict) -> str:
    title = finding.get("title") or finding.get("rule_id") or "Unknown"
    severity = finding.get("severity", "info").upper()
    file_path = finding.get("file", "?")
    line = finding.get("start_line", "?")
    message = finding.get("message", "")

    code_snippet = ""
    for item in (context.get("lines") or []):
        marker = ">" if item["highlight"] else " "
        code_snippet += f"{marker} {item['line']:>4}: {item['text']}\n"

    return (
        f"Validate finding: [{severity}] {title}\n"
        f"Location: {file_path}:{line}\n"
        f"Current bucket: {bucket}\n"
        f"Message: {message}\n"
        f"Code:\n{code_snippet}\n"
        f"Is this a TRUE POSITIVE or FALSE POSITIVE? "
        f"Provide: verdict, confidence (0.0-1.0), rationale."
    )


def apply_triage_verdicts(findings: list[dict], verdicts: list[dict]) -> list[dict]:
    """Apply LLM verdicts back to findings.

    Each verdict: {"fingerprint": str, "verdict": "TP"|"FP", "confidence": float, "rationale": str}
    """
    verdict_map = {v["fingerprint"]: v for v in verdicts}
    result = []
    for finding in findings:
        fp = finding.get("fingerprint", "")
        if fp in verdict_map:
            v = verdict_map[fp]
            result.append({
                **finding,
                "triage": {
                    "status": "false-positive" if v["verdict"] == "FP" else "confirmed",
                    "confidence": v.get("confidence", 0.5),
                    "rationale": v.get("rationale", ""),
                    "validated_at": _utcnow_iso(),
                },
            })
        else:
            result.append(finding)
    return result


# ---------------------------------------------------------------------------
# Phase C: Recommendations and export
# ---------------------------------------------------------------------------

def auto_suppress_false_positives(
    findings: list[dict],
    baseline_path: str,
    owner: str = "triage-llm",
) -> dict[str, Any]:
    """Export confirmed false positives to baseline suppressions."""
    from baseline import add_suppression, load_baseline, save_baseline

    baseline = load_baseline(baseline_path)
    suppressed_count = 0

    for finding in findings:
        triage = finding.get("triage") or {}
        if triage.get("status") == "false-positive" and triage.get("confidence", 0) >= 0.7:
            fp = finding.get("fingerprint", "")
            if fp:
                reason = f"LLM triage: {triage.get('rationale', 'Auto-suppressed as false positive')}"
                baseline = add_suppression(baseline, fp, reason, owner, expires_at=None)
                suppressed_count += 1

    save_baseline(baseline_path, baseline)
    return {
        "suppressed_count": suppressed_count,
        "baseline_path": baseline_path,
        "total_suppressions": len(baseline.get("suppressions", [])),
    }


def bulk_triage(
    findings_path: str,
    repo_root: str,
    focus: str = "all",
) -> dict[str, Any]:
    """Process all findings from a scan for bulk triage.

    Returns the auto-bucket report plus enriched findings for LLM validation.
    """
    findings = load_findings(findings_path)
    report = triage_findings(findings, focus)
    enriched = triage_with_llm_context(findings, repo_root, focus)

    return {
        "auto_bucket": report,
        "validation_targets": [
            {
                "fingerprint": e["finding"].get("fingerprint"),
                "bucket": e["bucket"],
                "prompt": e["validation_prompt"],
            }
            for e in enriched
        ],
        "total_targets": len(enriched),
    }


def export_triage_to_baseline(
    findings: list[dict],
    baseline_path: str,
    owner: str = "triage-analyst",
    min_confidence: float = 0.7,
) -> dict[str, Any]:
    """Export triaged false positives to baseline format.

    Only exports findings with confidence >= min_confidence.
    """
    from baseline import add_suppression, load_baseline, save_baseline

    baseline = load_baseline(baseline_path)
    exported: list[dict] = []

    for finding in findings:
        triage = finding.get("triage") or {}
        if triage.get("status") == "false-positive":
            confidence = triage.get("confidence", 0.0)
            if confidence >= min_confidence:
                fp = finding.get("fingerprint", "")
                if fp:
                    reason = triage.get("rationale", "Triaged as false positive")
                    baseline = add_suppression(baseline, fp, reason, owner, expires_at=None)
                    exported.append({"fingerprint": fp, "confidence": confidence, "reason": reason})

    save_baseline(baseline_path, baseline)
    return {
        "exported_count": len(exported),
        "exported": exported,
        "baseline_path": baseline_path,
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
            severity = finding.get('severity', 'info').upper()
            title = finding.get('title', finding.get('rule_id', 'Untitled'))
            triage = finding.get("triage") or {}
            confidence = triage.get("confidence")
            conf_str = f" (confidence: {confidence:.1f})" if confidence is not None else ""
            lines.append(f"{idx}. [{severity}] {title} — {location}{conf_str}")
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
            confidence = (finding.get("triage") or {}).get("confidence")
            conf_str = f" (confidence: {confidence:.1f})" if confidence is not None else ""
            lines.append(f"{idx}. {finding.get('title', finding.get('rule_id', 'Untitled'))} — {location} — {reason}{conf_str}")
    else:
        lines.append("_None_")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Triage OpenSAST findings")
    parser.add_argument("--findings", default=".claude/sast/results/findings.json", help="Findings JSON path")
    parser.add_argument("--focus", choices=["critical", "high", "medium", "low", "info", "all"], default="all")
    parser.add_argument("--output", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--output-file", help="Optional output file path")
    parser.add_argument("--repo-root", default=".", help="Repository root for code context enrichment")
    parser.add_argument("--bulk", action="store_true", help="Run bulk triage with validation targets")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.bulk:
        result = bulk_triage(args.findings, os.path.abspath(args.repo_root), args.focus)
        rendered = json.dumps(result, indent=2, ensure_ascii=False)
    else:
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
