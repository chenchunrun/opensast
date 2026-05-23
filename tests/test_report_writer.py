"""Tests for report generation."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from report_writer import (
    generate_claude_summary,
    generate_html_report,
    generate_json_summary,
    generate_markdown_report,
)


def _make_summary(**overrides) -> dict:
    base = {
        "target": "/test/project",
        "profile": "standard",
        "scan_time": "5.0s",
        "languages": ["python"],
        "tools_executed": ["semgrep"],
        "total_findings": 3,
        "new_findings": 2,
        "blocking_findings": 1,
        "severity_counts": {"critical": 0, "high": 1, "medium": 1, "low": 1, "info": 0},
        "tool_errors": [],
        "gate_result": {"passed": False, "fail_on": "high", "blocking_count": 1},
    }
    base.update(overrides)
    return base


def _make_findings() -> list[dict]:
    return [
        {
            "id": "f1", "tool": "semgrep", "rule_id": "R1",
            "title": "SQL Injection", "severity": "high",
            "confidence": "high", "language": "python",
            "file": "src/app.py", "start_line": 10, "end_line": 12,
            "cwe": ["CWE-89"], "owasp": ["A03:2021"],
            "message": "User input in SQL query",
            "evidence": {"source": "request.args", "sink": "execute()", "dataflow": []},
            "recommendation": "Use parameterized queries",
            "fingerprint": "fp1", "is_new": True, "is_suppressed": False,
        },
        {
            "id": "f2", "tool": "semgrep", "rule_id": "R2",
            "title": "Hardcoded password", "severity": "medium",
            "confidence": "medium", "language": "python",
            "file": "src/config.py", "start_line": 5, "end_line": 5,
            "cwe": ["CWE-798"], "owasp": [],
            "message": "Hardcoded secret found",
            "evidence": {"source": "", "sink": "", "dataflow": []},
            "recommendation": "Use env variable",
            "fingerprint": "fp2", "is_new": True, "is_suppressed": False,
        },
        {
            "id": "f3", "tool": "semgrep", "rule_id": "R3",
            "title": "Debug statement", "severity": "low",
            "confidence": "low", "language": "python",
            "file": "src/utils.py", "start_line": 20, "end_line": 20,
            "cwe": [], "owasp": [],
            "message": "print() in production code",
            "evidence": {"source": "", "sink": "", "dataflow": []},
            "recommendation": "Remove debug statement",
            "fingerprint": "fp3", "is_new": False, "is_suppressed": False,
        },
    ]


def test_generate_markdown_report():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "report.md")
        content = generate_markdown_report(_make_summary(), _make_findings(), path)
        assert os.path.isfile(path)
        assert "# SAST Scan Report" in content
        assert "SQL Injection" in content
        assert "Hardcoded password" in content
        assert "CI Gate" in content
        assert "FAIL" in content


def test_generate_markdown_empty():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "report.md")
        content = generate_markdown_report(_make_summary(total_findings=0, new_findings=0, blocking_findings=0), [], path)
        assert "Total findings:** 0" in content


def test_generate_json_summary():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "findings.json")
        data = generate_json_summary(_make_summary(), _make_findings(), path)
        assert os.path.isfile(path)
        assert data["total_findings"] == 3
        assert len(data["findings"]) == 3
        with open(path) as f:
            loaded = json.load(f)
        assert loaded["profile"] == "standard"


def test_generate_claude_summary():
    text = generate_claude_summary(_make_summary(), _make_findings())
    assert "3 total" in text
    assert "SQL Injection" in text
    assert "src/app.py:10" in text


def test_generate_markdown_with_suppressed():
    findings = _make_findings()
    findings[2]["is_suppressed"] = True
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "report.md")
        content = generate_markdown_report(_make_summary(), findings, path)
        assert "Suppressed" in content


def test_generate_markdown_with_tool_errors():
    summary = _make_summary(tool_errors=[{"tool": "gitleaks", "error": "not installed"}])
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "report.md")
        content = generate_markdown_report(summary, [], path)
        assert "Tool Errors" in content
        assert "gitleaks" in content


def test_risk_score():
    from report_writer import compute_risk_score
    findings = [
        {"severity": "critical", "confidence": "high", "is_suppressed": False},
    ]
    score, grade = compute_risk_score(findings)
    assert score < 90
    assert grade in ("B", "C", "D", "F")

    score2, grade2 = compute_risk_score([])
    assert score2 == 100
    assert grade2 == "A+"

    findings_low = [{"severity": "info", "confidence": "low", "is_suppressed": False}]
    score3, grade3 = compute_risk_score(findings_low)
    assert score3 >= 95
    assert grade3 == "A+"

    findings_suppressed = [{"severity": "critical", "confidence": "high", "is_suppressed": True}]
    score4, grade4 = compute_risk_score(findings_suppressed)
    assert score4 == 100
    assert grade4 == "A+"


def test_compliance_mapping():
    from report_writer import compute_compliance_mapping
    findings = [
        {"cwe": ["CWE-78"], "is_suppressed": False},
        {"cwe": ["CWE-89"], "is_suppressed": False},
    ]
    result = compute_compliance_mapping(findings)
    assert "owasp_top_10" in result
    assert "cwe_top_25" in result
    assert result["cwe_top_25"]["CWE-78"]["hit"] is True
    assert result["cwe_top_25"]["CWE-79"]["hit"] is False


def test_group_findings_by():
    from report_writer import group_findings_by
    findings = [
        {"file": "src/a.py", "severity": "high", "cwe": ["CWE-78"], "tool": "semgrep"},
        {"file": "src/b.py", "severity": "medium", "cwe": ["CWE-89"], "tool": "semgrep"},
    ]
    by_sev = group_findings_by(findings, "severity")
    assert "HIGH" in by_sev
    assert "MEDIUM" in by_sev

    by_file = group_findings_by(findings, "file")
    assert "src" in by_file


def test_generate_html_report():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "report.html")
        content = generate_html_report(_make_summary(), _make_findings(), path)
        assert os.path.isfile(path)
        assert "<!DOCTYPE html>" in content
        assert "Executive Summary" in content
        assert "Risk Grade" in content
        assert "OWASP Top 10" in content
        assert "CWE Top 25" in content
        assert "SQL Injection" in content
        assert "Remediation Priority" in content


def test_markdown_has_compliance_section():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "report.md")
        content = generate_markdown_report(_make_summary(), _make_findings(), path)
        assert "OWASP Top 10 Compliance" in content
        assert "CWE Top 25" in content
        assert "Risk Grade" in content
        assert "Findings by Category" in content
        assert "Remediation Priority" in content
