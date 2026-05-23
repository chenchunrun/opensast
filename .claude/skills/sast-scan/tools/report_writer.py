import json
import os
from datetime import datetime, timezone


def generate_markdown_report(summary: dict, findings: list[dict], output_path: str) -> str:
    lines = [
        "# SAST Scan Report",
        "",
        "## Summary",
        "",
        f"- **Target:** {summary.get('target', 'N/A')}",
        f"- **Profile:** {summary.get('profile', 'N/A')}",
        f"- **Scan time:** {summary.get('scan_time', 'N/A')}",
        f"- **Languages:** {', '.join(summary.get('languages', []))}",
        f"- **Tools executed:** {', '.join(summary.get('tools_executed', []))}",
        f"- **Total findings:** {summary.get('total_findings', 0)}",
        f"- **New findings:** {summary.get('new_findings', 0)}",
        f"- **Blocking findings:** {summary.get('blocking_findings', 0)}",
        "",
    ]

    severity_counts = summary.get("severity_counts", {})
    lines.extend([
        "## Risk Overview",
        "",
        "| Severity | Count |",
        "|---|---:|",
        f"| Critical | {severity_counts.get('critical', 0)} |",
        f"| High | {severity_counts.get('high', 0)} |",
        f"| Medium | {severity_counts.get('medium', 0)} |",
        f"| Low | {severity_counts.get('low', 0)} |",
        f"| Info | {severity_counts.get('info', 0)} |",
        "",
    ])

    blocking = [f for f in findings if f.get("is_new") and not f.get("is_suppressed")]
    sorted_findings = sorted(blocking, key=_severity_sort_key, reverse=True)

    if sorted_findings:
        lines.append("## Top Findings")
        lines.append("")
        for i, f in enumerate(sorted_findings[:20], 1):
            lines.extend(_format_finding(i, f))
            lines.append("")

    suppressed = [f for f in findings if f.get("is_suppressed")]
    if suppressed:
        lines.extend([
            "## Suppressed / Baseline Findings",
            "",
            f"_{len(suppressed)} findings suppressed by baseline._",
            "",
        ])

    tool_errors = summary.get("tool_errors", [])
    if tool_errors:
        lines.extend([
            "## Tool Errors",
            "",
        ])
        for err in tool_errors:
            lines.append(f"- **{err.get('tool', 'unknown')}:** {err.get('error', 'unknown error')}")
        lines.append("")

    gate_result = summary.get("gate_result", {})
    if gate_result:
        status = "PASS" if gate_result.get("passed") else "FAIL"
        lines.extend([
            "## CI Gate Result",
            "",
            f"**Status: {status}**",
            f"- Fail-on threshold: {gate_result.get('fail_on', 'N/A')}",
            f"- Blocking count: {gate_result.get('blocking_count', 0)}",
            "",
        ])

    content = "\n".join(lines)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return content


def generate_json_summary(summary: dict, findings: list[dict], output_path: str) -> dict:
    data = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "target": summary.get("target", ""),
        "profile": summary.get("profile", ""),
        "languages": summary.get("languages", []),
        "tools_executed": summary.get("tools_executed", []),
        "total_findings": summary.get("total_findings", 0),
        "new_findings": summary.get("new_findings", 0),
        "blocking_findings": summary.get("blocking_findings", 0),
        "severity_counts": summary.get("severity_counts", {}),
        "gate_result": summary.get("gate_result", {}),
        "tool_errors": summary.get("tool_errors", []),
        "findings": findings,
    }
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    return data


def generate_claude_summary(summary: dict, findings: list[dict]) -> str:
    severity_counts = summary.get("severity_counts", {})
    blocking = [
        f for f in findings
        if f.get("is_new") and not f.get("is_suppressed")
    ]
    sorted_blockers = sorted(blocking, key=_severity_sort_key, reverse=True)[:5]

    lines = [
        f"Scan complete: {summary.get('total_findings', 0)} total, "
        f"{summary.get('new_findings', 0)} new, "
        f"{summary.get('blocking_findings', 0)} blocking.",
        "",
        "Severity breakdown: "
        + ", ".join(f"{k}={v}" for k, v in severity_counts.items() if v > 0),
        "",
    ]

    if sorted_blockers:
        lines.append("Top findings to address:")
        for i, f in enumerate(sorted_blockers, 1):
            cwe = ", ".join(f.get("cwe", []))
            lines.append(
                f"  {i}. [{f.get('severity', '?').upper()}] "
                f"{f.get('title', 'Untitled')} "
                f"({f.get('file', '?')}:{f.get('start_line', '?')}) "
                f"[{cwe}]"
            )
        lines.append("")

    return "\n".join(lines)


def _severity_sort_key(finding: dict) -> int:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return order.get(finding.get("severity", "info"), 0)


def _format_finding(index: int, f: dict) -> list[str]:
    cwe = ", ".join(f.get("cwe", []))
    owasp = ", ".join(f.get("owasp", []))
    lines = [
        f"### {index}. {f.get('title', 'Untitled')}",
        "",
        f"- **Severity:** {f.get('severity', 'unknown')}",
        f"- **Confidence:** {f.get('confidence', 'unknown')}",
        f"- **Tool:** {f.get('tool', 'unknown')}",
    ]
    if cwe:
        lines.append(f"- **CWE:** {cwe}")
    if owasp:
        lines.append(f"- **OWASP:** {owasp}")
    lines.extend([
        f"- **File:** `{f.get('file', 'unknown')}:{f.get('start_line', '?')}`",
        f"- **Message:** {f.get('message', '')}",
    ])
    evidence = f.get("evidence", {})
    if evidence.get("source"):
        lines.append(f"- **Source:** `{evidence['source']}`")
    if evidence.get("sink"):
        lines.append(f"- **Sink:** `{evidence['sink']}`")
    if f.get("recommendation"):
        lines.append(f"- **Recommended fix:** {f['recommendation']}")
    return lines
