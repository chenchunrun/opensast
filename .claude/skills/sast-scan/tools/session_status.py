"""Report SAST session progress from .claude/sast/results/ artifacts."""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

DEFAULT_RESULTS_DIR = ".claude/sast/results"

PHASE_ORDER = ("scan", "phase_a", "phase_b", "phase_c", "triage", "import", "fix")


def _read_json(path: str) -> dict | list | None:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None


def load_findings(results_dir: str) -> list[dict]:
    path = os.path.join(results_dir, "findings.json")
    data = _read_json(path)
    if isinstance(data, dict):
        findings = data.get("findings", [])
        return findings if isinstance(findings, list) else []
    if isinstance(data, list):
        return data
    return []


def _triage_status(finding: dict) -> str | None:
    triage = finding.get("triage")
    if isinstance(triage, dict):
        return triage.get("status")
    enrichment = finding.get("analysis_enrichment", {})
    nested = enrichment.get("triage")
    if isinstance(nested, dict):
        return nested.get("status")
    return None


def count_unfixed_high(findings: list[dict]) -> int:
    count = 0
    for finding in findings:
        severity = str(finding.get("severity", "")).lower()
        if severity not in {"critical", "high"}:
            continue
        if finding.get("is_suppressed"):
            continue
        if _triage_status(finding) == "false-positive":
            continue
        count += 1
    return count


def infer_completed_phases(
    summary: dict | None,
    plan: dict | None,
    llm_findings: dict | None,
    findings: list[dict],
) -> list[str]:
    phases: set[str] = set()
    if plan:
        phases.update(plan.get("completed_phases", []))
    if summary:
        phases.add("scan")

    if llm_findings:
        if llm_findings.get("findings_dismissed", 0) or llm_findings.get("validate_targets_analyzed", 0):
            phases.add("phase_a")
        if llm_findings.get("findings_discovered", 0) or llm_findings.get("discover_targets_analyzed", 0):
            phases.add("phase_b")
        if llm_findings.get("agent_review_complete"):
            phases.add("phase_c")
        if llm_findings.get("llm_analysis_complete"):
            phases.update({"phase_a", "phase_b"})
        if llm_findings.get("imported_into_scan"):
            phases.add("import")

    for finding in findings:
        status = _triage_status(finding)
        if status in {"confirmed", "likely", "false-positive", "needs-review"}:
            phases.add("triage")
            break

    return [phase for phase in PHASE_ORDER if phase in phases]


def pending_discover_count(plan: dict | None, llm_findings: dict | None) -> int:
    if not plan:
        return 0
    total = len(plan.get("discover_targets", []))
    if not llm_findings:
        return total
    analyzed = int(llm_findings.get("discover_targets_analyzed", 0) or 0)
    return max(0, total - analyzed)


def build_next_steps(status: dict[str, Any]) -> list[str]:
    steps: list[str] = []
    if not status["scan_complete"]:
        steps.append("Run `/sast-scan . --profile standard --format all` to start a session.")
        return steps

    profile = status.get("profile", "standard")
    if profile in {"standard", "deep"} and "phase_c" not in status["completed_phases"]:
        if status["pending_discover"] > 0:
            steps.append(
                "Continue Phase B in `/sast-scan`: analyze remaining discover targets "
                f"({status['pending_discover']} pending) and save `llm-findings.json`."
            )
        elif not status.get("llm_findings_present"):
            steps.append(
                "Complete Phase A–C in `/sast-scan` using `llm-analysis-plan.json`, "
                "then save `.claude/sast/results/llm-findings.json`."
            )
        elif "import" not in status["completed_phases"]:
            steps.append(
                "Re-run `/sast-scan . --llm-findings .claude/sast/results/llm-findings.json` "
                "to merge LLM findings into the main report."
            )

    if status["unfixed_high"] > 0:
        steps.append(
            f"Run `/sast-triage --findings .claude/sast/results/findings.json --bulk` "
            f"to review {status['unfixed_high']} HIGH/CRITICAL finding(s)."
        )
        steps.append(
            "Fix confirmed issues with `/sast-fix <fingerprint> --test` "
            "or suppress FPs via `/sast-baseline suppress`."
        )
    elif "triage" not in status["completed_phases"] and status.get("total_findings", 0) > 0:
        steps.append(
            "Run `/sast-triage --findings .claude/sast/results/findings.json --focus high` "
            "to prioritize remaining findings."
        )
    else:
        steps.append("Session looks healthy. Use `/sast-scan --changed-only --profile quick` before commits.")

    return steps[:3]


def compute_session_status(results_dir: str) -> dict[str, Any]:
    summary_path = os.path.join(results_dir, "summary.json")
    plan_path = os.path.join(results_dir, "llm-analysis-plan.json")
    llm_path = os.path.join(results_dir, "llm-findings.json")

    summary = _read_json(summary_path)
    plan = _read_json(plan_path)
    llm_findings = _read_json(llm_path)
    findings = load_findings(results_dir)

    summary_dict = summary if isinstance(summary, dict) else None
    plan_dict = plan if isinstance(plan, dict) else None
    llm_dict = llm_findings if isinstance(llm_findings, dict) else None

    completed = infer_completed_phases(summary_dict, plan_dict, llm_dict, findings)
    pending = pending_discover_count(plan_dict, llm_dict)

    status: dict[str, Any] = {
        "results_dir": results_dir,
        "scan_complete": summary_dict is not None,
        "session_id": (plan_dict or {}).get("session_id"),
        "profile": (summary_dict or {}).get("profile"),
        "completed_phases": completed,
        "pending_discover": pending,
        "unfixed_high": count_unfixed_high(findings),
        "total_findings": len(findings) or (summary_dict or {}).get("total_findings", 0),
        "llm_findings_present": llm_dict is not None,
        "artifacts": {
            "summary.json": os.path.isfile(summary_path),
            "findings.json": os.path.isfile(os.path.join(results_dir, "findings.json")),
            "llm-analysis-plan.json": os.path.isfile(plan_path),
            "llm-findings.json": os.path.isfile(llm_path),
            "report.md": os.path.isfile(os.path.join(results_dir, "report.md")),
        },
    }
    status["next_steps"] = build_next_steps(status)
    return status


def format_markdown(status: dict[str, Any]) -> str:
    lines = [
        "# SAST Session Status",
        "",
        f"- **Results dir:** `{status['results_dir']}`",
        f"- **Scan complete:** {'yes' if status['scan_complete'] else 'no'}",
        f"- **Session ID:** {status.get('session_id') or '—'}",
        f"- **Profile:** {status.get('profile') or '—'}",
        f"- **Completed phases:** {', '.join(status['completed_phases']) or 'none'}",
        f"- **Pending discover targets:** {status['pending_discover']}",
        f"- **Unfixed HIGH/CRITICAL:** {status['unfixed_high']}",
        f"- **Total findings:** {status['total_findings']}",
        "",
        "## Artifacts",
        "",
    ]
    for name, present in status["artifacts"].items():
        lines.append(f"- `{name}`: {'present' if present else 'missing'}")
    lines.extend(["", "## Next steps", ""])
    for index, step in enumerate(status["next_steps"], start=1):
        lines.append(f"{index}. {step}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Show SAST session progress and next steps.")
    parser.add_argument(
        "--results",
        default=DEFAULT_RESULTS_DIR,
        help=f"Results directory (default: {DEFAULT_RESULTS_DIR})",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Output format",
    )
    args = parser.parse_args(argv)

    results_dir = os.path.abspath(args.results)
    status = compute_session_status(results_dir)

    if args.format == "json":
        print(json.dumps(status, indent=2))
    else:
        print(format_markdown(status))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
