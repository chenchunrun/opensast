"""Generate structured remediation guidance for a specific finding."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from typing import Any


SKILL_DIR = os.path.dirname(os.path.dirname(__file__))
RUNNER_PATH = os.path.join(SKILL_DIR, "tools", "sast_runner.py")


def load_findings(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        findings = data.get("findings", [])
        return findings if isinstance(findings, list) else []
    return data if isinstance(data, list) else []


def find_finding(findings: list[dict], identifier: str) -> dict | None:
    for finding in findings:
        if identifier in {
            finding.get("id"),
            finding.get("fingerprint"),
            finding.get("fingerprint_v1"),
        }:
            return finding
    return None


def _fix_template(finding: dict) -> dict[str, Any]:
    haystack = " ".join(
        str(part or "")
        for part in [
            finding.get("rule_id"),
            finding.get("title"),
            finding.get("message"),
            " ".join(finding.get("cwe", [])),
        ]
    ).lower()

    templates = [
        (
            ("sql", "cwe-89", "queryraw", "select *"),
            {
                "summary": "Replace string-built queries with parameterized queries or ORM placeholders.",
                "fix_steps": [
                    "Move user-controlled values out of SQL string interpolation.",
                    "Use parameter binding supported by the database client or ORM.",
                    "Validate identifiers separately if table or column names are dynamic.",
                ],
                "example_before": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
                "example_after": 'cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])',
            },
        ),
        (
            ("command", "shell=true", "subprocess", "exec", "cwe-78"),
            {
                "summary": "Avoid shell interpretation and pass arguments as a fixed array.",
                "fix_steps": [
                    "Replace shell command strings with explicit argument lists.",
                    "Allowlist user-selectable subcommands or flags.",
                    "Prefer native library APIs over shelling out when possible.",
                ],
                "example_before": 'subprocess.run(f"grep {user_input} file.txt", shell=True)',
                "example_after": 'subprocess.run(["grep", user_input, "file.txt"], check=True)',
            },
        ),
        (
            ("xss", "innerhtml", "render", "template", "cwe-79"),
            {
                "summary": "Ensure untrusted data is escaped or rendered through safe templating primitives.",
                "fix_steps": [
                    "Route output through framework auto-escaping where available.",
                    "Avoid assigning user input directly to raw HTML sinks.",
                    "Add contextual escaping for HTML, attribute, or JavaScript contexts.",
                ],
                "example_before": "element.innerHTML = userBio",
                "example_after": "element.textContent = userBio",
            },
        ),
        (
            ("path traversal", "cwe-22", "../", "filepath", "open("),
            {
                "summary": "Normalize paths and enforce that resolved files stay within an allowed base directory.",
                "fix_steps": [
                    "Resolve the candidate path with realpath/resolve.",
                    "Compare the resolved path against an allowlisted base directory.",
                    "Reject paths that escape the intended root or contain unexpected path segments.",
                ],
                "example_before": "open(os.path.join(base_dir, user_path))",
                "example_after": "candidate = os.path.realpath(os.path.join(base_dir, user_path))",
            },
        ),
        (
            ("deserial", "pickle", "yaml.load", "unserialize", "cwe-502"),
            {
                "summary": "Replace unsafe deserialization with safe parsers and explicit schemas.",
                "fix_steps": [
                    "Avoid general object deserialization for untrusted input.",
                    "Use safe loader variants such as yaml.safe_load or typed JSON parsing.",
                    "Validate the decoded structure before use.",
                ],
                "example_before": "data = yaml.load(body, Loader=yaml.Loader)",
                "example_after": "data = yaml.safe_load(body)",
            },
        ),
        (
            ("secret", "credential", "password", "token", "api key", "cwe-798"),
            {
                "summary": "Move embedded secrets out of source code and into environment-backed secret management.",
                "fix_steps": [
                    "Replace the hardcoded value with an environment or secret manager lookup.",
                    "Fail closed if the secret is missing instead of falling back to insecure defaults.",
                    "Rotate the exposed credential if it was ever real.",
                ],
                "example_before": 'SECRET_KEY = "dev-secret"',
                "example_after": 'SECRET_KEY = os.environ["SECRET_KEY"]',
            },
        ),
        (
            ("idor", "ownership", "cwe-639", "access control"),
            {
                "summary": "Bind record lookup or mutation to the authenticated principal, not only to a raw object identifier.",
                "fix_steps": [
                    "Add ownership or tenant filters to record fetches and updates.",
                    "Reject access when the resource does not belong to the caller.",
                    "Keep authorization checks close to the data access boundary.",
                ],
                "example_before": "record = db.orders.find_unique(where={'id': order_id})",
                "example_after": "record = db.orders.find_first(where={'id': order_id, 'user_id': auth_user.id})",
            },
        ),
    ]

    for keywords, template in templates:
        if any(keyword in haystack for keyword in keywords):
            return template

    return {
        "summary": "Validate the data flow, remove unsafe assumptions, and replace the sink with a safer primitive.",
        "fix_steps": [
            "Confirm the true source of attacker-controlled input.",
            "Add validation or authorization before the dangerous sink.",
            "Replace the risky API or pattern with a safer equivalent where possible.",
        ],
        "example_before": None,
        "example_after": None,
    }


def read_code_context(repo_root: str, finding: dict, radius: int = 3) -> dict[str, Any]:
    rel_path = finding.get("file", "")
    if not rel_path:
        return {"path": None, "lines": []}
    abs_path = rel_path if os.path.isabs(rel_path) else os.path.join(repo_root, rel_path)
    if not os.path.isfile(abs_path):
        return {"path": abs_path, "lines": []}

    start_line = max(int(finding.get("start_line") or 1), 1)
    begin = max(1, start_line - radius)
    end = start_line + radius
    with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    excerpt = []
    for line_no in range(begin, min(end, len(lines)) + 1):
        excerpt.append(
            {
                "line": line_no,
                "text": lines[line_no - 1].rstrip("\n"),
                "highlight": line_no == start_line,
            }
        )
    return {"path": abs_path, "lines": excerpt}


def rerun_targeted_scan(
    repo_root: str,
    finding: dict,
    profile: str = "quick",
    output_dir: str | None = None,
) -> dict[str, Any]:
    lang = finding.get("language") or "auto"
    file_path = finding.get("file") or ""
    scan_target = repo_root
    if file_path:
        abs_file = file_path if os.path.isabs(file_path) else os.path.join(repo_root, file_path)
        if os.path.isfile(abs_file):
            scan_target = os.path.dirname(abs_file) or repo_root

    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="opensast-fix-rerun-")

    cmd = [
        sys.executable,
        RUNNER_PATH,
        scan_target,
        "--profile",
        profile,
        "--format",
        "json",
        "--output-dir",
        output_dir,
    ]
    if lang and lang != "unknown":
        cmd.extend(["--lang", lang])

    result = subprocess.run(cmd, capture_output=True, text=True)
    return {
        "command": cmd,
        "scan_target": scan_target,
        "output_dir": output_dir,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def build_fix_report(
    finding: dict,
    repo_root: str,
    apply_requested: bool = False,
    rerun_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    template = _fix_template(finding)
    context = read_code_context(repo_root, finding)
    location = f"{finding.get('file', '?')}:{finding.get('start_line', '?')}"

    return {
        "finding_id": finding.get("id"),
        "fingerprint": finding.get("fingerprint"),
        "title": finding.get("title") or finding.get("rule_id") or "Untitled finding",
        "rule_id": finding.get("rule_id"),
        "severity": finding.get("severity", "info"),
        "confidence": finding.get("confidence", "unknown"),
        "location": location,
        "message": finding.get("message", ""),
        "recommendation": finding.get("recommendation"),
        "apply_requested": apply_requested,
        "apply_supported": False,
        "fix_summary": template["summary"],
        "fix_steps": template["fix_steps"],
        "example_before": template.get("example_before"),
        "example_after": template.get("example_after"),
        "context": context,
        "rerun": rerun_result,
    }


def render_markdown(report: dict[str, Any]) -> str:
    rerun = report.get("rerun") or {}
    lines = [
        f"# Fix for finding: {report['fingerprint'] or report['finding_id'] or report['rule_id']}",
        "",
        "## Vulnerability",
        f"- Type: {report['title']}",
        f"- Rule: {report.get('rule_id') or 'n/a'}",
        f"- Severity: {str(report['severity']).upper()}",
        f"- Confidence: {report['confidence']}",
        f"- File: {report['location']}",
        "",
        "## Analysis",
        report["message"] or "No additional scanner message provided.",
        "",
        "## Proposed fix",
        report["fix_summary"],
        "",
    ]

    if report["fix_steps"]:
        lines.append("### Steps")
        for step in report["fix_steps"]:
            lines.append(f"- {step}")
        lines.append("")

    if report["example_before"] or report["example_after"]:
        lines.extend(["### Example", "```text"])
        if report["example_before"]:
            lines.append(f"- {report['example_before']}")
        if report["example_after"]:
            lines.append(f"+ {report['example_after']}")
        lines.extend(["```", ""])

    context = report.get("context") or {}
    if context.get("lines"):
        lines.extend(["## Local context", "```text"])
        for item in context["lines"]:
            marker = ">" if item["highlight"] else " "
            lines.append(f"{marker} {item['line']:>4}: {item['text']}")
        lines.extend(["```", ""])

    lines.extend(
        [
            "## Validation",
            f"- [{'x' if report['apply_requested'] and report['apply_supported'] else ' '}] Fix applied",
            f"- [{'x' if rerun else ' '}] Scan re-run",
            f"- [{'x' if rerun.get('returncode') == 0 else ' '}] Re-scan passed without blocking errors",
        ]
    )

    if rerun:
        command_str = " ".join(rerun["command"])
        lines.extend(
            [
                "",
                "### Re-scan result",
                f"- Command: `{command_str}`",
                f"- Exit code: {rerun['returncode']}",
                f"- Output dir: `{rerun['output_dir']}`",
            ]
        )

    if report["apply_requested"] and not report["apply_supported"]:
        lines.extend(["", "_Automatic patch application is not implemented in this helper. Apply the change manually or via the agent workflow._"])

    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate remediation guidance for an OpenSAST finding")
    parser.add_argument("identifier", help="Finding id or fingerprint")
    parser.add_argument("--findings", default=".claude/sast/results/findings.json", help="Findings JSON path")
    parser.add_argument("--repo-root", default=".", help="Repository root for reading code context")
    parser.add_argument("--apply", action="store_true", help="Enter fix-apply mode (guidance only in current implementation)")
    parser.add_argument("--test", action="store_true", help="Re-run a targeted scan after preparing the fix guidance")
    parser.add_argument("--test-profile", choices=["quick", "standard", "deep"], default="quick")
    parser.add_argument("--output", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--output-file", help="Optional report output path")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    findings = load_findings(args.findings)
    finding = find_finding(findings, args.identifier)
    if not finding:
        parser.error(f"finding not found: {args.identifier}")

    rerun_result = None
    if args.test:
        rerun_result = rerun_targeted_scan(os.path.abspath(args.repo_root), finding, profile=args.test_profile)

    report = build_fix_report(
        finding,
        repo_root=os.path.abspath(args.repo_root),
        apply_requested=args.apply,
        rerun_result=rerun_result,
    )

    rendered = render_markdown(report) if args.output == "markdown" else json.dumps(report, indent=2, ensure_ascii=False)
    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as f:
            f.write(rendered)
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
