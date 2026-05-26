"""GitHub PR integration for posting scan results as comments."""

import json
import logging
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))

from report_writer import summarize_analysis_enrichment


def _gate_mode_label(gate: dict) -> tuple[str, str]:
    if gate.get("review_findings_blocking"):
        return ("strict", "needs-review findings also block")
    return ("standard", "needs-review findings are advisory")

logger = logging.getLogger(__name__)


def is_github_actions() -> bool:
    return os.environ.get("GITHUB_ACTIONS", "") == "true"


def _run_gh(args: list[str], check: bool = True) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(
            ["gh", *args],
            capture_output=True, text=True, timeout=30, check=check,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return None


def get_pr_number() -> int | None:
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not event_path or not os.path.isfile(event_path):
        return None
    try:
        with open(event_path, encoding="utf-8") as f:
            event = json.load(f)
        return event.get("pull_request", {}).get("number")
    except (json.JSONDecodeError, OSError, KeyError):
        return None


def get_pr_changed_files(repo: str | None = None, pr_number: int | None = None) -> set[str]:
    if pr_number is None:
        return set()
    args = ["pr", "diff", "--name-only", str(pr_number)]
    if repo:
        args.extend(["--repo", repo])
    result = _run_gh(args, check=False)
    if not result or result.returncode != 0:
        return set()
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def format_pr_comment(summary: dict, findings: list[dict]) -> str:
    lines = ["## SAST Scan Results\n"]
    sev = summary.get("severity_counts", {})
    total = summary.get("total_findings", 0)
    new = summary.get("new_findings", 0)
    blocking = summary.get("blocking_findings", 0)

    review = summary.get("review_findings", 0)
    lines.append(f"**{total} findings** ({new} new, {blocking} blocking, {review} needs review)\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for level in ("critical", "high", "medium", "low"):
        if sev.get(level, 0) > 0:
            lines.append(f"| {level.capitalize()} | {sev[level]} |")

    gate = summary.get("gate_result", {})
    gate_mode, gate_mode_desc = _gate_mode_label(gate)
    if gate.get("passed"):
        lines.append(f"\n**Gate: PASSED** ({gate_mode} mode; {gate_mode_desc})")
    else:
        lines.append(
            f"\n**Gate: FAILED** ({gate.get('blocking_count', 0)} blocking findings, "
            f"{gate_mode} mode; {gate_mode_desc})"
        )

    enrichment = summary.get("analysis_enrichment") or summarize_analysis_enrichment(findings)
    if enrichment:
        origins = ", ".join(f"{k}={v}" for k, v in enrichment.get("by_origin", {}).items() if v > 0)
        triage = ", ".join(f"{k}={v}" for k, v in enrichment.get("by_triage", {}).items() if v > 0)
        lines.append("\n### Analysis Enrichment\n")
        if summary.get("project_archetype"):
            lines.append(f"- Archetype: `{summary['project_archetype']}`")
        if summary.get("llm_analysis_targets") is not None:
            lines.append(
                f"- LLM targets: validation={summary.get('llm_analysis_targets', 0)}, "
                f"discovery={summary.get('llm_discovery_targets', 0)}"
            )
        if origins:
            lines.append(f"- Origins: {origins}")
        if triage:
            lines.append(f"- Triage: {triage}")
        discovery = enrichment.get("llm_discovery_categories", {})
        if discovery:
            lines.append("- LLM discovery categories: " + ", ".join(f"{k}={v}" for k, v in discovery.items()))

    unsuppressed = [f for f in findings if not f.get("is_suppressed") and f.get("is_new")]
    blocking_findings = [f for f in unsuppressed if (f.get("triage") or {}).get("status") != "needs-review"]
    review_findings = [f for f in unsuppressed if (f.get("triage") or {}).get("status") == "needs-review"]
    if blocking_findings:
        lines.append("\n### Blocking Findings\n")
        for f in blocking_findings[:5]:
            sev_str = f.get("severity", "info").upper()
            file_str = f.get("file", "")
            line_str = f.get("start_line", "")
            title = f.get("title", f.get("rule_id", ""))
            triage = (f.get("triage") or {}).get("status")
            note = f" ({triage})" if triage else ""
            lines.append(f"- **[{sev_str}]** {title}{note} — `{file_str}:{line_str}`")
    if review_findings:
        lines.append("\n### Needs Review\n")
        for f in review_findings[:5]:
            sev_str = f.get("severity", "info").upper()
            file_str = f.get("file", "")
            line_str = f.get("start_line", "")
            title = f.get("title", f.get("rule_id", ""))
            rationale = (f.get("triage") or {}).get("rationale", "")
            note = f" — {rationale}" if rationale else ""
            lines.append(f"- **[{sev_str}]** {title} — `{file_str}:{line_str}`{note}")

    return "\n".join(lines)


def post_pr_comment(summary: dict, findings: list[dict], repo: str | None = None,
                    pr_number: int | None = None) -> bool:
    if not is_github_actions():
        logger.debug("Not in GitHub Actions, skipping PR comment")
        return False

    if pr_number is None:
        pr_number = get_pr_number()
    if pr_number is None:
        logger.debug("Could not determine PR number")
        return False

    body = format_pr_comment(summary, findings)
    args = ["pr", "comment", str(pr_number), "--body", body]
    if repo:
        args.extend(["--repo", repo])

    result = _run_gh(args, check=False)
    if result and result.returncode == 0:
        logger.info("Posted PR comment on #%d", pr_number)
        return True

    logger.warning("Failed to post PR comment: %s", result.stderr if result else "gh not available")
    return False


def post_inline_comments(
    findings: list[dict], repo: str | None = None,
    pr_number: int | None = None, commit_sha: str | None = None,
) -> int:
    if not is_github_actions():
        return 0

    if pr_number is None:
        pr_number = get_pr_number()
    if not pr_number or not commit_sha:
        return 0

    changed = get_pr_changed_files(repo, pr_number)
    if not changed:
        return 0

    posted = 0
    for f in findings:
        if f.get("is_suppressed") or not f.get("is_new"):
            continue
        if f.get("file", "") not in changed:
            continue
        if f.get("severity", "info") not in ("critical", "high"):
            continue

        body = f"**[{f.get('severity', 'info').upper()}]** {f.get('title', f.get('rule_id', ''))}\n{f.get('message', '')}"
        args = [
            "api", f"repos/{repo}/pulls/{pr_number}/comments",
            "-f", f"body={body}",
            "-f", f"commit_id={commit_sha}",
            "-f", f"path={f.get('file', '')}",
            "-f", f"line={f.get('start_line', 1)}",
            "-f", "side=RIGHT",
        ]
        result = _run_gh(args, check=False)
        if result and result.returncode == 0:
            posted += 1

    return posted
