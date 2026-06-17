"""Tests for compliance coverage report generation."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from compliance_report import build_compliance_report, format_compliance_markdown


def _make_findings() -> list[dict]:
    return [
        {"rule_id": "python.security.sql-injection-string-concat", "severity": "high",
         "cwe": ["CWE-89"], "file": "src/app.py", "start_line": 42},
        {"rule_id": "python.security.command-injection-subprocess", "severity": "high",
         "cwe": ["CWE-78"], "file": "src/app.py", "start_line": 75},
        {"rule_id": "python.security.hardcoded-secret-string", "severity": "medium",
         "cwe": ["CWE-798"], "file": "src/app.py", "start_line": 10},
        {"rule_id": "python.security.weak-hash-md5", "severity": "medium",
         "cwe": ["CWE-328"], "file": "src/app.py", "start_line": 100},
        {"rule_id": "csharp.security.path-traversal-file", "severity": "high",
         "cwe": ["CWE-22"], "file": "src/service.cs", "start_line": 33},
    ]


def test_build_compliance_report():
    findings = _make_findings()
    report = build_compliance_report(findings)

    assert "frameworks" in report
    assert "overall" in report
    assert set(report["cwes_detected"]) == {22, 78, 89, 328, 798}

    # SOC 2 coverage: CWE-22 (access), CWE-78/89 (injection), CWE-798 (leakage)
    soc2 = report["frameworks"]["soc2"]
    assert soc2["coverage_pct"] >= 25  # CC6.1 (CWE-22) hits access control
    assert soc2["controls"]["CC6.1 — Access Control"]["status"] == "pass"

    # PCI-DSS should have 6.5.1 and 6.5.2 covered
    pci = report["frameworks"]["pci-dss"]
    assert pci["controls"]["6.5.1 — Injection Flaws"]["status"] == "pass"
    assert pci["controls"]["6.5.2 — Default Credentials"]["status"] == "pass"

    # NIST SC-13 covered by CWE-328
    nist = report["frameworks"]["nist800-53"]
    assert nist["controls"]["SC-13 — Cryptographic Protection"]["status"] == "pass"


def test_build_compliance_report_single_framework():
    report = build_compliance_report(_make_findings(), "pci-dss")
    assert len(report["frameworks"]) == 1
    assert "pci-dss" in report["frameworks"]


def test_build_compliance_report_empty():
    report = build_compliance_report([])
    assert report["total_findings"] == 0
    for fw in report["frameworks"].values():
        assert fw["coverage_pct"] == 0


def test_format_compliance_markdown():
    report = build_compliance_report(_make_findings())
    md = format_compliance_markdown(report)

    assert "# Compliance Coverage Report" in md
    assert "## Summary" in md
    assert "SOC 2" in md
    assert "PCI-DSS" in md
    assert "HIPAA" in md
    assert "ISO 27001" in md
    assert "NIST" in md
    assert "GB/T 35273" in md
    assert "✅" in md or "pass" in md.lower()
    assert "❌" in md or "gap" in md.lower()


def test_format_compliance_json():
    import json
    report = build_compliance_report(_make_findings())
    text = json.dumps(report, indent=2)
    data = json.loads(text)
    assert data["frameworks"]["hipaa"]["coverage_pct"] >= 0
