"""GitHub PR integration for posting scan results as comments."""

import json
import logging
import os
import subprocess

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

    lines.append(f"**{total} findings** ({new} new, {blocking} blocking)\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for level in ("critical", "high", "medium", "low"):
        if sev.get(level, 0) > 0:
            lines.append(f"| {level.capitalize()} | {sev[level]} |")

    gate = summary.get("gate_result", {})
    if gate.get("passed"):
        lines.append("\n**Gate: PASSED**")
    else:
        lines.append(f"\n**Gate: FAILED** ({gate.get('blocking_count', 0)} blocking findings)")

    unsuppressed = [f for f in findings if not f.get("is_suppressed") and f.get("is_new")]
    if unsuppressed:
        lines.append("\n### Top Findings\n")
        for f in unsuppressed[:5]:
            sev_str = f.get("severity", "info").upper()
            file_str = f.get("file", "")
            line_str = f.get("start_line", "")
            title = f.get("title", f.get("rule_id", ""))
            lines.append(f"- **[{sev_str}]** {title} — `{file_str}:{line_str}`")

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
