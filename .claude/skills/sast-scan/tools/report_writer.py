import json
import os
from collections import defaultdict
from datetime import datetime, timezone

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SEVERITY_DEDUCTION = {"critical": 15, "high": 8, "medium": 4, "low": 2, "info": 0.5}
CONFIDENCE_MULTIPLIER = {"very-high": 1.0, "high": 1.0, "medium": 0.7, "low": 0.4}

OWASP_TOP_10_2025 = {
    "A01:2021 - Broken Access Control": ["CWE-22", "CWE-78", "CWE-200", "CWE-352", "CWE-639", "CWE-862"],
    "A02:2021 - Cryptographic Failures": ["CWE-261", "CWE-296", "CWE-310", "CWE-327", "CWE-328", "CWE-798"],
    "A03:2021 - Injection": ["CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-94", "CWE-77"],
    "A04:2021 - Insecure Design": ["CWE-73", "CWE-209", "CWE-269", "CWE-285", "CWE-770"],
    "A05:2021 - Security Misconfiguration": ["CWE-611", "CWE-16", "CWE-434", "CWE-190"],
    "A06:2021 - Vulnerable Components": [],
    "A07:2021 - Auth Failures": ["CWE-287", "CWE-798", "CWE-306", "CWE-307"],
    "A08:2021 - Data Integrity Failures": ["CWE-502", "CWE-829", "CWE-190"],
    "A09:2021 - Logging Failures": ["CWE-778", "CWE-532"],
    "A10:2021 - SSRF": ["CWE-918", "CWE-939"],
}

CWE_TOP_25 = [
    "CWE-787", "CWE-79", "CWE-89", "CWE-78", "CWE-20",
    "CWE-125", "CWE-22", "CWE-352", "CWE-434", "CWE-862",
    "CWE-476", "CWE-502", "CWE-287", "CWE-190", "CWE-77",
    "CWE-798", "CWE-306", "CWE-119", "CWE-200", "CWE-276",
    "CWE-918", "CWE-94", "CWE-770", "CWE-611",
]


def _severity_sort_key(finding: dict) -> int:
    return SEVERITY_ORDER.get(finding.get("severity", "info"), 0)


def _extract_cwe_ids(findings: list[dict]) -> set[str]:
    ids = set()
    for f in findings:
        for cwe in f.get("cwe", []):
            code = cwe.split(":")[0].strip() if ":" in cwe else cwe.strip()
            ids.add(code)
    return ids


def compute_risk_score(findings: list[dict]) -> tuple[float, str]:
    score = 100.0
    for f in findings:
        sev = f.get("severity", "info").lower()
        conf = f.get("confidence", "medium").lower()
        deduction = SEVERITY_DEDUCTION.get(sev, 0.5)
        multiplier = CONFIDENCE_MULTIPLIER.get(conf, 0.7)
        if not f.get("is_suppressed"):
            score -= deduction * multiplier
    score = max(0.0, min(100.0, score))
    if score >= 95:
        grade = "A+"
    elif score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    return round(score, 1), grade


def compute_compliance_mapping(findings: list[dict]) -> dict:
    cwe_ids = _extract_cwe_ids(findings)
    owasp_map = {}
    for category, cwes in OWASP_TOP_10_2025.items():
        matched = cwe_ids & set(cwes)
        owasp_map[category] = {
            "matched_cwes": sorted(matched),
            "status": "fail" if matched else "pass",
            "finding_count": sum(
                1 for f in findings
                if not f.get("is_suppressed")
                and any(c in set(cwes) for c in f.get("cwe", []))
            ),
        }
    cwe25_map = {}
    for cwe in CWE_TOP_25:
        hit = cwe in cwe_ids
        cwe25_map[cwe] = {"hit": hit, "count": sum(1 for f in findings if cwe in f.get("cwe", []))}
    return {"owasp_top_10": owasp_map, "cwe_top_25": cwe25_map}


def group_findings_by(findings: list[dict], key: str) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        if key == "category":
            cwes = f.get("cwe", [])
            group_name = cwes[0] if cwes else "Uncategorized"
        elif key == "file":
            filepath = f.get("file", "unknown")
            group_name = os.path.dirname(filepath) or "."
        elif key == "severity":
            group_name = f.get("severity", "info").upper()
        elif key == "tool":
            group_name = f.get("tool", "unknown")
        else:
            group_name = str(f.get(key, "other"))
        groups[group_name].append(f)
    return dict(groups)


def generate_html_report(summary: dict, findings: list[dict], output_path: str) -> str:
    score, grade = compute_risk_score(findings)
    compliance = compute_compliance_mapping(findings)
    severity_counts = summary.get("severity_counts", {})
    total = sum(severity_counts.values())
    by_category = group_findings_by(findings, "category")
    by_file = group_findings_by(findings, "file")
    blocking = [f for f in findings if f.get("is_new") and not f.get("is_suppressed")]
    sorted_findings = sorted(blocking, key=_severity_sort_key, reverse=True)
    business_logic = [f for f in findings if f.get("tool") in ("dataflow-analyzer", "rbac-analyzer")
                      and not f.get("is_suppressed")]

    grade_color = _grade_color(grade)
    gate = summary.get("gate_result", {})

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAST Scan Report - {_esc(summary.get('target', ''))}</title>
<style>
:root {{
  --critical: #dc2626; --high: #ea580c; --medium: #d97706;
  --low: #2563eb; --info: #6b7280; --pass: #16a34a;
  --business: #7c3aed;
  --bg: #ffffff; --surface: #f8fafc; --border: #e2e8f0;
  --text: #1e293b; --text2: #64748b;
}}
@media print {{ .no-print {{ display: none; }} body {{ font-size: 12px; }} }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: var(--text); background: var(--surface); line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
h1 {{ font-size: 1.75rem; margin-bottom: 8px; }}
h2 {{ font-size: 1.25rem; margin: 32px 0 16px; padding-bottom: 8px; border-bottom: 2px solid var(--border); }}
h3 {{ font-size: 1rem; margin: 16px 0 8px; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; }}
.card {{ background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }}
.card-center {{ text-align: center; }}
.grade {{ font-size: 3rem; font-weight: 800; color: {grade_color}; line-height: 1; }}
.score {{ font-size: 1.5rem; font-weight: 600; color: {grade_color}; }}
.badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; color: #fff; }}
.badge-critical {{ background: var(--critical); }} .badge-high {{ background: var(--high); }}
.badge-medium {{ background: var(--medium); }} .badge-low {{ background: var(--low); }}
.badge-info {{ background: var(--info); }} .badge-pass {{ background: var(--pass); }}
.badge-business {{ background: var(--business); }}
.dataflow {{ background: #f5f3ff; border-left: 3px solid var(--business); padding: 10px 14px; margin: 8px 0; font-family: monospace; font-size: 0.8rem; overflow-x: auto; }}
.dataflow-step {{ margin: 2px 0; }} .dataflow-arrow {{ color: var(--business); margin: 0 4px; }}
.bar-chart {{ display: flex; align-items: flex-end; gap: 8px; height: 120px; padding-top: 8px; }}
.bar-item {{ flex: 1; display: flex; flex-direction: column; align-items: center; }}
.bar {{ width: 100%; border-radius: 4px 4px 0 0; min-height: 2px; }}
.bar-label {{ font-size: 0.7rem; color: var(--text2); margin-top: 4px; }}
.bar-value {{ font-size: 0.75rem; font-weight: 600; margin-bottom: 2px; }}
table {{ width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 0.875rem; }}
th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border); }}
th {{ background: var(--surface); font-weight: 600; color: var(--text2); text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }}
tr:hover {{ background: var(--surface); }}
code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; font-family: 'SF Mono', 'Fira Code', monospace; }}
.finding {{ background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 12px; }}
.finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
.finding-title {{ font-weight: 600; font-size: 0.95rem; }}
.finding-meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 4px 16px; font-size: 0.85rem; color: var(--text2); }}
.evidence {{ background: #f8fafc; border-left: 3px solid var(--medium); padding: 8px 12px; margin: 8px 0; font-family: monospace; font-size: 0.8rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
.filter-bar {{ display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }}
.filter-btn {{ padding: 4px 12px; border: 1px solid var(--border); border-radius: 16px; background: var(--bg); cursor: pointer; font-size: 0.8rem; }}
.filter-btn:hover {{ border-color: var(--text2); }}
.compliance-pass {{ color: var(--pass); }} .compliance-fail {{ color: var(--critical); }}
.gate-pass {{ color: var(--pass); font-size: 1.1rem; font-weight: 700; }}
.gate-fail {{ color: var(--critical); font-size: 1.1rem; font-weight: 700; }}
.tabs {{ display: flex; gap: 0; border-bottom: 2px solid var(--border); margin-bottom: 16px; }}
.tab {{ padding: 8px 20px; cursor: pointer; border-bottom: 2px solid transparent; margin-bottom: -2px; font-size: 0.9rem; color: var(--text2); }}
.tab:hover {{ color: var(--text); }} .tab.active {{ border-bottom-color: var(--text); color: var(--text); font-weight: 600; }}
.tab-content {{ display: none; }} .tab-content.active {{ display: block; }}
.summary-stat {{ text-align: center; }}
.summary-stat .value {{ font-size: 2rem; font-weight: 700; }}
.summary-stat .label {{ font-size: 0.8rem; color: var(--text2); text-transform: uppercase; letter-spacing: 0.05em; }}
.section {{ margin-top: 24px; }}
.footer {{ text-align: center; color: var(--text2); font-size: 0.8rem; margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border); }}
</style>
</head>
<body>
<div class="container">

<h1>SAST Security Scan Report</h1>
<p style="color:var(--text2)">Generated {_esc(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))} by OpenSAST</p>

<!-- Executive Summary -->
<h2>Executive Summary</h2>
<div class="grid">
  <div class="card card-center">
    <div class="label">Risk Grade</div>
    <div class="grade">{grade}</div>
    <div class="score">{score}/100</div>
  </div>
  <div class="card card-center">
    <div class="label">Total Findings</div>
    <div class="value" style="font-size:2rem;font-weight:700">{total}</div>
    <div style="color:var(--text2);font-size:0.85rem">{summary.get('new_findings', 0)} new, {summary.get('blocking_findings', 0)} blocking</div>
  </div>
  <div class="card card-center">
    <div class="label">CI Gate</div>
    <div class="{'gate-pass' if gate.get('passed') else 'gate-fail'}">{'PASS' if gate.get('passed') else 'FAIL'}</div>
    <div style="color:var(--text2);font-size:0.85rem">Threshold: {gate.get('fail_on', 'N/A')}</div>
  </div>
  <div class="card">
    <div class="label" style="font-size:0.8rem;color:var(--text2);text-transform:uppercase;letter-spacing:0.05em">Severity Distribution</div>
    <div class="bar-chart">
      {_bar(severity_counts.get('critical', 0), total, '--critical')}
      {_bar(severity_counts.get('high', 0), total, '--high')}
      {_bar(severity_counts.get('medium', 0), total, '--medium')}
      {_bar(severity_counts.get('low', 0), total, '--low')}
      {_bar(severity_counts.get('info', 0), total, '--info')}
    </div>
  </div>
</div>

<div class="grid" style="margin-top:12px">
  <div class="card summary-stat"><div class="value">{_esc(summary.get('target', 'N/A').split('/')[-1])}</div><div class="label">Target</div></div>
  <div class="card summary-stat"><div class="value">{_esc(summary.get('profile', 'N/A'))}</div><div class="label">Profile</div></div>
  <div class="card summary-stat"><div class="value">{_esc(summary.get('scan_time', 'N/A'))}</div><div class="label">Duration</div></div>
  <div class="card summary-stat"><div class="value">{', '.join(summary.get('languages', [])) or 'N/A'}</div><div class="label">Languages</div></div>
  <div class="card summary-stat"><div class="value">{', '.join(summary.get('tools_executed', [])) or 'N/A'}</div><div class="label">Tools</div></div>
</div>

<!-- Compliance Mapping -->
<h2>Compliance Mapping</h2>
<h3>OWASP Top 10 (2021)</h3>
<table>
<tr><th>Category</th><th>Status</th><th>Findings</th><th>Related CWEs</th></tr>
{_owasp_rows(compliance['owasp_top_10'])}
</table>

<h3>CWE Top 25 Coverage</h3>
<table>
<tr><th>CWE ID</th><th>Status</th><th>Findings</th></tr>
{_cwe25_rows(compliance['cwe_top_25'])}
</table>

<!-- Findings -->
<h2>Findings Dashboard</h2>

<div class="tabs no-print">
  <div class="tab active" onclick="switchTab('severity')">By Severity</div>
  <div class="tab" onclick="switchTab('category')">By Category</div>
  <div class="tab" onclick="switchTab('file')">By File</div>
  <div class="tab" onclick="switchTab('business')"><span class="badge badge-business" style="margin-right:4px">{len(business_logic)}</span>Business Logic</div>
  <div class="tab" onclick="switchTab('all')">All Findings</div>
</div>

<div id="tab-severity" class="tab-content active">
{_findings_by_severity(sorted_findings)}
</div>
<div id="tab-category" class="tab-content">
{_findings_by_group(by_category, "Category")}
</div>
<div id="tab-file" class="tab-content">
{_findings_by_group(by_file, "Directory")}
</div>
<div id="tab-business" class="tab-content">
{_business_logic_findings(business_logic)}
</div>
<div id="tab-all" class="tab-content">
{_all_findings(sorted_findings)}
</div>

<!-- Remediation Priority -->
<h2>Remediation Priority</h2>
{_remediation_table(sorted_findings)}

<!-- Tool Errors -->
{_tool_errors_html(summary.get('tool_errors', []))}

<div class="footer">
  Generated by <strong>OpenSAST</strong> &mdash; {_esc(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))}
</div>

</div>
<script>
function switchTab(id) {{
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + id).classList.add('active');
  event.target.classList.add('active');
}}
</script>
</body>
</html>"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return html


def generate_markdown_report(summary: dict, findings: list[dict], output_path: str) -> str:
    score, grade = compute_risk_score(findings)
    compliance = compute_compliance_mapping(findings)
    severity_counts = summary.get("severity_counts", {})
    blocking = [f for f in findings if f.get("is_new") and not f.get("is_suppressed")]
    sorted_findings = sorted(blocking, key=_severity_sort_key, reverse=True)
    by_category = group_findings_by(findings, "category")
    by_file = group_findings_by(findings, "file")
    gate = summary.get("gate_result", {})

    lines = [
        "# SAST Scan Report",
        "",
        "## Executive Summary",
        "",
        f"- **Risk Grade:** {grade} ({score}/100)",
        f"- **Target:** {summary.get('target', 'N/A')}",
        f"- **Profile:** {summary.get('profile', 'N/A')}",
        f"- **Scan time:** {summary.get('scan_time', 'N/A')}",
        f"- **Languages:** {', '.join(summary.get('languages', []))}",
        f"- **Tools executed:** {', '.join(summary.get('tools_executed', []))}",
        f"- **Total findings:** {summary.get('total_findings', 0)}",
        f"- **New findings:** {summary.get('new_findings', 0)}",
        f"- **Blocking findings:** {summary.get('blocking_findings', 0)}",
        f"- **CI Gate:** {'PASS' if gate.get('passed') else 'FAIL'} (threshold: {gate.get('fail_on', 'N/A')})",
        "",
        "## Risk Overview",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {sev.capitalize()} | {severity_counts.get(sev, 0)} |")
    lines.append("")

    lines.extend([
        "## OWASP Top 10 Compliance",
        "",
        "| Category | Status | Findings | CWEs |",
        "|---|---|---:|---|",
    ])
    for cat, info in compliance["owasp_top_10"].items():
        status = "PASS" if info["status"] == "pass" else "**FAIL**"
        cwes = ", ".join(info["matched_cwes"]) or "-"
        lines.append(f"| {cat} | {status} | {info['finding_count']} | {cwes} |")
    lines.append("")

    lines.extend([
        "## CWE Top 25 Coverage",
        "",
        "| CWE | Hit | Findings |",
        "|---|---|---:|",
    ])
    for cwe, info in compliance["cwe_top_25"].items():
        if info["hit"]:
            lines.append(f"| **{cwe}** | YES | {info['count']} |")
    lines.append("")

    # Trend section
    trend = summary.get("trend_analysis")
    if trend and trend.get("daily_data"):
        lines.extend([
            "## Trend Analysis",
            "",
            f"**Direction:** {trend['direction']} ({trend['total_delta']:+d} findings)",
        ])
        if trend.get("mttr_days") is not None:
            lines.append(f"**MTTR:** {trend['mttr_days']} days")
        if trend.get("fixed_findings"):
            lines.append(f"**Fixed:** {trend['fixed_findings']} | **New:** {trend['new_findings']}")
        lines.extend(["",
            "| Date | Total | Critical | High | Medium | Low |",
            "|------|-------|----------|------|--------|-----|",
        ])
        for day in trend["daily_data"]:
            lines.append(
                f"| {day['date']} | {day['total']} | {day['critical']} "
                f"| {day['high']} | {day['medium']} | {day['low']} |"
            )
        lines.append("")

    # Business Logic Findings
    bl_findings = [f for f in findings if f.get("tool") in ("dataflow-analyzer", "rbac-analyzer")
                   and not f.get("is_suppressed")]
    if bl_findings:
        lines.extend([
            "## Business Logic Findings",
            "",
            f"_{len(bl_findings)} cross-file authorization and RBAC scope issues detected._",
            "",
        ])
        for i, f in enumerate(sorted(bl_findings, key=_severity_sort_key, reverse=True), 1):
            lines.extend(_format_business_logic_md(i, f))
            lines.append("")

    lines.append("## Findings by Category")
    lines.append("")
    for cat, cat_findings in sorted(by_category.items()):
        cat_findings_sorted = sorted(cat_findings, key=_severity_sort_key, reverse=True)
        lines.append(f"### {cat} ({len(cat_findings)} findings)")
        lines.append("")
        for i, f in enumerate(cat_findings_sorted, 1):
            lines.append(f"{i}. [{f.get('severity', '?').upper()}] {f.get('title', '?')} — `{f.get('file', '?')}:{f.get('start_line', '?')}`")
        lines.append("")

    lines.append("## Findings by Severity")
    lines.append("")
    by_sev = group_findings_by(sorted_findings, "severity")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        sev_findings = by_sev.get(sev, [])
        if not sev_findings:
            continue
        lines.append(f"### {sev} ({len(sev_findings)})")
        lines.append("")
        for i, f in enumerate(sev_findings, 1):
            lines.extend(_format_finding_md(i, f))
            lines.append("")

    suppressed = [f for f in findings if f.get("is_suppressed")]
    if suppressed:
        lines.extend(["## Suppressed Findings", "", f"_{len(suppressed)} findings suppressed by baseline._", ""])

    tool_errors = summary.get("tool_errors", [])
    if tool_errors:
        lines.extend(["## Tool Errors", ""])
        for err in tool_errors:
            lines.append(f"- **{err.get('tool', 'unknown')}:** {err.get('error', 'unknown error')}")
        lines.append("")

    lines.append("## Remediation Priority")
    lines.append("")
    lines.append("| # | Severity | Title | File | CWE |")
    lines.append("|---:|---|---|---|---|")
    for i, f in enumerate(sorted_findings[:20], 1):
        cwe = ", ".join(f.get("cwe", [])[:1])
        lines.append(f"| {i} | {f.get('severity', '?').upper()} | {f.get('title', '?')} | `{f.get('file', '?')}:{f.get('start_line', '?')}` | {cwe} |")
    lines.append("")

    lines.append("---")
    lines.append(f"*Generated by OpenSAST — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*")

    content = "\n".join(lines)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return content


def generate_json_summary(summary: dict, findings: list[dict], output_path: str) -> dict:
    score, grade = compute_risk_score(findings)
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
        "risk_score": score,
        "risk_grade": grade,
        "compliance": compute_compliance_mapping(findings),
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
    blocking = [f for f in findings if f.get("is_new") and not f.get("is_suppressed")]
    sorted_blockers = sorted(blocking, key=_severity_sort_key, reverse=True)[:5]
    score, grade = compute_risk_score(findings)

    lines = [
        f"Scan complete: {summary.get('total_findings', 0)} total, "
        f"{summary.get('new_findings', 0)} new, "
        f"{summary.get('blocking_findings', 0)} blocking. "
        f"Risk grade: {grade} ({score}/100)",
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


# ── HTML helper functions ──────────────────────────────────────────

def _esc(text: str | None) -> str:
    if not text:
        return ""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _dataflow_html(steps: list[dict]) -> str:
    """Render dataflow steps as an HTML trace."""
    if not steps:
        return ""
    parts = []
    for i, step in enumerate(steps):
        label = step.get("label", "")
        file_ref = step.get("file", "")
        line = step.get("line", "")
        ref = f"<code>{_esc(file_ref)}:{line}</code> " if file_ref else ""
        parts.append(f'<div class="dataflow-step">{ref}{_esc(label)}</div>')
        if i < len(steps) - 1:
            parts.append('<div class="dataflow-arrow">↓</div>')
    return "\n".join(parts)


def _business_logic_findings(findings: list[dict]) -> str:
    """Render business logic findings with dataflow visualization."""
    if not findings:
        return '<p style="color:var(--text2)">No business logic findings.</p>'
    parts = [
        '<p style="color:var(--text2);margin-bottom:16px">'
        'Cross-file data flow and RBAC scope issues detected by deep analysis. '
        'These require manual review to confirm exploitability.</p>',
    ]
    for f in sorted(findings, key=_severity_sort_key, reverse=True):
        parts.append(_finding_card(f))
    return "\n".join(parts)


def _grade_color(grade: str) -> str:
    colors = {"A+": "#16a34a", "A": "#16a34a", "B": "#2563eb", "C": "#d97706", "D": "#ea580c", "F": "#dc2626"}
    return colors.get(grade, "#6b7280")


def _bar(count: int, total: int, color_var: str) -> str:
    height = (count / total * 100) if total > 0 else 0
    label = color_var.replace("--", "").capitalize()
    return f'<div class="bar-item"><div class="bar-value">{count}</div><div class="bar" style="height:{height}%;background:var({color_var})"></div><div class="bar-label">{label}</div></div>'


def _owasp_rows(owasp_map: dict) -> str:
    rows = []
    for cat, info in owasp_map.items():
        status_cls = "compliance-pass" if info["status"] == "pass" else "compliance-fail"
        status_text = "PASS" if info["status"] == "pass" else "FAIL"
        cwes = ", ".join(info["matched_cwes"]) or "-"
        rows.append(f'<tr><td>{_esc(cat)}</td><td class="{status_cls}"><strong>{status_text}</strong></td><td>{info["finding_count"]}</td><td style="font-size:0.8rem">{_esc(cwes)}</td></tr>')
    return "\n".join(rows)


def _cwe25_rows(cwe25_map: dict) -> str:
    rows = []
    for cwe, info in cwe25_map.items():
        if info["hit"]:
            rows.append(f'<tr><td><strong>{_esc(cwe)}</strong></td><td class="compliance-fail"><strong>HIT</strong></td><td>{info["count"]}</td></tr>')
    if not rows:
        rows.append('<tr><td colspan="3" style="text-align:center;color:var(--text2)">No CWE Top 25 findings</td></tr>')
    return "\n".join(rows)


def _findings_by_severity(findings: list[dict]) -> str:
    by_sev = group_findings_by(findings, "severity")
    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        sev_findings = by_sev.get(sev, [])
        if not sev_findings:
            continue
        badge_cls = f"badge-{sev.lower()}"
        parts.append(f'<h3><span class="badge {badge_cls}">{sev}</span> {len(sev_findings)} findings</h3>')
        for f in sev_findings:
            parts.append(_finding_card(f))
    return "\n".join(parts) if parts else '<p style="color:var(--text2)">No findings.</p>'


def _findings_by_group(groups: dict, label: str) -> str:
    parts = []
    for name, group_findings in sorted(groups.items(), key=lambda x: -len(x[1])):
        sev_badges = []
        for sev in ("critical", "high", "medium", "low", "info"):
            count = sum(1 for f in group_findings if f.get("severity") == sev)
            if count:
                sev_badges.append(f'<span class="badge badge-{sev}">{count} {sev}</span>')
        parts.append(f'<h3>{_esc(name)} <span style="font-weight:normal;color:var(--text2)">({len(group_findings)})</span> {" ".join(sev_badges)}</h3>')
        for f in sorted(group_findings, key=_severity_sort_key, reverse=True)[:10]:
            parts.append(_finding_card(f))
        if len(group_findings) > 10:
            parts.append(f'<p style="color:var(--text2);font-size:0.85rem">... and {len(group_findings) - 10} more</p>')
    return "\n".join(parts) if parts else '<p style="color:var(--text2)">No findings.</p>'


def _all_findings(findings: list[dict]) -> str:
    if not findings:
        return '<p style="color:var(--text2)">No findings.</p>'
    return "\n".join(_finding_card(f) for f in findings)


def _finding_card(f: dict) -> str:
    sev = f.get("severity", "info").lower()
    badge_cls = f"badge-{sev}"
    cwe = ", ".join(f.get("cwe", []))
    owasp = ", ".join(f.get("owasp", []))
    evidence = f.get("evidence") or {}
    source = evidence.get("source") or ""
    sink = evidence.get("sink") or ""
    dataflow = evidence.get("dataflow") or []
    recommendation = f.get("recommendation") or ""
    confidence = f.get("confidence", "?")
    tool = f.get("tool", "")
    is_business = tool in ("dataflow-analyzer", "rbac-analyzer")

    card = f"""<div class="finding">
<div class="finding-header">
  <span class="finding-title">{_esc(f.get('title', 'Untitled'))}</span>
  <span><span class="badge {badge_cls}">{sev.upper()}</span>{' <span class="badge badge-business">Business Logic</span>' if is_business else ''} <span style="font-size:0.8rem;color:var(--text2)">conf: {confidence}</span></span>
</div>
<div class="finding-meta">
  <div><strong>File:</strong> <code>{_esc(f.get('file', '?'))}:{f.get('start_line', '?')}</div>
  <div><strong>Tool:</strong> {_esc(f.get('tool', '?'))}</div>"""
    if cwe:
        card += f'\n  <div><strong>CWE:</strong> {_esc(cwe)}</div>'
    if owasp:
        card += f'\n  <div><strong>OWASP:</strong> {_esc(owasp)}</div>'
    card += f'\n</div><p style="margin-top:8px;font-size:0.9rem">{_esc(f.get("message", ""))}</p>'
    if dataflow:
        steps_html = _dataflow_html(dataflow)
        card += f'\n<div class="dataflow">{steps_html}</div>'
    elif source:
        card += f'\n<div class="evidence">{_esc(source[:300])}</div>'
    if sink and not dataflow:
        card += f'\n<div class="evidence" style="border-left-color:var(--critical)"><strong>Sink:</strong> {_esc(sink[:300])}</div>'
    if recommendation:
        rec_short = recommendation[:200] + "..." if len(recommendation) > 200 else recommendation
        card += f'\n<p style="font-size:0.85rem;color:var(--text2)"><strong>Fix:</strong> {_esc(rec_short)}</p>'
    card += '\n</div>'
    return card


def _remediation_table(findings: list[dict]) -> str:
    if not findings:
        return '<p style="color:var(--text2)">No blocking findings to remediate.</p>'
    rows = []
    for i, f in enumerate(findings[:20], 1):
        sev = f.get("severity", "info").lower()
        badge_cls = f"badge-{sev}"
        cwe = ", ".join(f.get("cwe", [])[:1])
        rows.append(
            f'<tr><td>{i}</td><td><span class="badge {badge_cls}">{sev.upper()}</span></td>'
            f'<td>{_esc(f.get("title", "?"))}</td>'
            f'<td><code>{_esc(f.get("file", "?"))}:{f.get("start_line", "?")}</code></td>'
            f'<td>{_esc(cwe)}</td></tr>'
        )
    return f'<table><tr><th>#</th><th>Severity</th><th>Title</th><th>Location</th><th>CWE</th></tr>\n{chr(10).join(rows)}\n</table>'


def _tool_errors_html(errors: list[dict]) -> str:
    if not errors:
        return ""
    rows = [f'<tr><td>{_esc(e.get("tool","?"))}</td><td>{_esc(e.get("error","unknown"))}</td></tr>' for e in errors]
    return f'<h2>Tool Errors</h2><table><tr><th>Tool</th><th>Error</th></tr>\n{chr(10).join(rows)}\n</table>'


# ── Markdown helper ────────────────────────────────────────────────

def _format_finding_md(index: int, f: dict) -> list[str]:
    cwe = ", ".join(f.get("cwe", []))
    owasp = ", ".join(f.get("owasp", []))
    lines = [
        f"#### {index}. [{f.get('severity', '?').upper()}] {f.get('title', 'Untitled')}",
        "",
        f"- **File:** `{f.get('file', '?')}:{f.get('start_line', '?')}`",
        f"- **Tool:** {f.get('tool', '?')} | **Confidence:** {f.get('confidence', '?')}",
    ]
    if cwe:
        lines.append(f"- **CWE:** {cwe}")
    if owasp:
        lines.append(f"- **OWASP:** {owasp}")
    lines.append(f"- **Message:** {f.get('message', '')}")
    evidence = f.get("evidence", {})
    if evidence.get("source"):
        lines.append(f"- **Source:** `{evidence['source'][:120]}`")
    if f.get("recommendation"):
        lines.append(f"- **Fix:** {f['recommendation'][:200]}")
    lines.append("")
    return lines


def _format_business_logic_md(index: int, f: dict) -> list[str]:
    """Format a business logic finding with dataflow trace for Markdown."""
    cwe = ", ".join(f.get("cwe", []))
    tool = f.get("tool", "?")
    evidence = f.get("evidence", {})
    dataflow = evidence.get("dataflow", [])
    where_clause = evidence.get("where_clause", "")

    lines = [
        f"#### {index}. [{f.get('severity', '?').upper()}] {f.get('title', 'Untitled')}",
        "",
        f"- **File:** `{f.get('file', '?')}:{f.get('start_line', '?')}`",
        f"- **Analyzer:** {tool} | **CWE:** {cwe or 'N/A'}",
        f"- **Message:** {f.get('message', '')}",
    ]

    if dataflow:
        lines.append("")
        lines.append("**Data flow trace:**")
        lines.append("```")
        for step in dataflow:
            label = step.get("label", "")
            file_ref = step.get("file", "")
            line_no = step.get("line", "")
            if file_ref:
                lines.append(f"  {file_ref}:{line_no} — {label}")
            else:
                lines.append(f"  {label}")
        lines.append("```")

    if where_clause:
        lines.append(f"- **Where clause:** `{where_clause}`")

    if f.get("recommendation"):
        lines.append(f"- **Fix:** {f['recommendation'][:300]}")

    lines.append("")
    return lines
