"""Tests for finding normalization."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from normalize_findings import (
    compute_fingerprint,
    deduplicate_findings,
    normalize_checkov,
    normalize_gitleaks,
    normalize_semgrep,
)


def _make_semgrep_sarif(results: list | None = None, include_default_results: bool = True) -> dict:
    default_results = [{
        "ruleId": "python.lang.security.subprocess-shell-true",
        "ruleIndex": 0,
        "level": "error",
        "message": {"text": "Possible command injection"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": "src/app.py"},
                "region": {"startLine": 42, "endLine": 45, "snippet": {"text": "subprocess.run(cmd, shell=True)"}},
            }
        }],
    }] if include_default_results else []
    actual_results = results if results is not None else default_results
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "semgrep", "version": "1.0",
                "rules": [{
                    "id": "python.lang.security.subprocess-shell-true",
                    "shortDescription": {"text": "Possible command injection"},
                    "properties": {"tags": ["CWE-78", "OWASP-A3"], "precision": "high"},
                    "help": {"text": "Avoid shell=True"},
                }],
            }},
            "results": actual_results,
        }],
    }


def _make_gitleaks_sarif() -> dict:
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gitleaks", "version": "8.0", "rules": []}},
            "results": [{
                "ruleId": "aws-access-key-id",
                "level": "error",
                "message": {"text": "AWS Access Key ID detected"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "config/settings.py"},
                        "region": {"startLine": 10, "endLine": 10, "snippet": {"text": "AKIAIOSFODNN7EXAMPLE"}},
                    }
                }],
            }],
        }],
    }


def test_normalize_semgrep():
    sarif = _make_semgrep_sarif()
    findings = normalize_semgrep(sarif)
    assert len(findings) == 1
    f = findings[0]
    assert f["tool"] == "semgrep"
    assert f["severity"] == "high"
    assert f["file"] == "src/app.py"
    assert f["start_line"] == 42
    assert "CWE-78" in f["cwe"]


def test_normalize_semgrep_empty():
    sarif = _make_semgrep_sarif(results=[], include_default_results=False)
    findings = normalize_semgrep(sarif)
    assert findings == []


def test_normalize_gitleaks():
    sarif = _make_gitleaks_sarif()
    findings = normalize_gitleaks(sarif)
    assert len(findings) == 1
    f = findings[0]
    assert f["tool"] == "gitleaks"
    assert f["severity"] in ("critical", "high")
    assert f["file"] == "config/settings.py"


def test_normalize_checkov_empty():
    findings = normalize_checkov({"version": "2.1.0", "runs": []})
    assert findings == []


def test_compute_fingerprint_deterministic():
    f = {"file": "app.py", "start_line": 10, "rule_id": "R1"}
    fp1 = compute_fingerprint(f)
    fp2 = compute_fingerprint(f)
    assert fp1 == fp2
    assert fp1.startswith("sha256:")


def test_compute_fingerprint_different():
    f1 = {"file": "a.py", "start_line": 10, "rule_id": "R1"}
    f2 = {"file": "b.py", "start_line": 10, "rule_id": "R1"}
    assert compute_fingerprint(f1) != compute_fingerprint(f2)


def test_deduplicate_merges_same_location():
    findings = [
        {"file": "app.py", "start_line": 10, "end_line": 10, "severity": "medium",
         "tool": "tool1", "rule_id": "R1", "cwe": ["CWE-78"], "owasp": [],
         "title": "A", "message": "", "evidence": {}, "recommendation": "",
         "fingerprint": "fp1", "id": "f1", "language": "", "confidence": "medium",
         "is_new": True, "is_suppressed": False, "suppression_reason": None},
        {"file": "app.py", "start_line": 10, "end_line": 10, "severity": "high",
         "tool": "tool2", "rule_id": "R2", "cwe": ["CWE-78"], "owasp": [],
         "title": "B", "message": "", "evidence": {}, "recommendation": "",
         "fingerprint": "fp2", "id": "f2", "language": "", "confidence": "high",
         "is_new": True, "is_suppressed": False, "suppression_reason": None},
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 1
    assert result[0]["severity"] == "high"
    assert "tool1" in result[0]["tool"]
    assert "tool2" in result[0]["tool"]


def test_deduplicate_keeps_different():
    findings = [
        {"file": "a.py", "start_line": 10, "end_line": 10, "severity": "high",
         "tool": "tool1", "rule_id": "R1", "cwe": [], "owasp": [],
         "title": "A", "message": "", "evidence": {}, "recommendation": "",
         "fingerprint": "fp1", "id": "f1", "language": "", "confidence": "medium",
         "is_new": True, "is_suppressed": False, "suppression_reason": None},
        {"file": "b.py", "start_line": 20, "end_line": 20, "severity": "medium",
         "tool": "tool1", "rule_id": "R1", "cwe": [], "owasp": [],
         "title": "B", "message": "", "evidence": {}, "recommendation": "",
         "fingerprint": "fp2", "id": "f2", "language": "", "confidence": "medium",
         "is_new": True, "is_suppressed": False, "suppression_reason": None},
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 2
