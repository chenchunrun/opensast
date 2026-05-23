"""Tests for finding normalization."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from normalize_findings import (
    NORMALIZERS,
    compute_fingerprint,
    compute_fingerprint_v1,
    deduplicate_findings,
    normalize_bandit,
    normalize_checkov,
    normalize_codeql,
    normalize_gitleaks,
    normalize_gosec,
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


def _make_finding(**overrides) -> dict:
    defaults = {
        "file": "app.py", "start_line": 10, "end_line": 10, "severity": "medium",
        "tool": "tool1", "rule_id": "R1", "cwe": [], "owasp": [],
        "title": "Test", "message": "msg", "fingerprint": "fp1", "id": "f1",
        "language": "", "confidence": "medium",
        "evidence": {"source": "snippet", "sink": "", "dataflow": []},
        "recommendation": "", "is_new": True, "is_suppressed": False,
        "suppression_reason": None, "fingerprint_v1": "fp1", "snippet_hash": "abc",
        "tools": ["tool1"], "rule_ids": ["R1"],
    }
    defaults.update(overrides)
    return defaults


def test_deduplicate_merges_same_location():
    findings = [
        _make_finding(
            tool="tool1", rule_id="R1", severity="medium", cwe=["CWE-78"],
            evidence={"source": "cmd", "sink": "", "dataflow": []},
            snippet_hash="h1", fingerprint="fp1", fingerprint_v1="fp1",
        ),
        _make_finding(
            tool="tool2", rule_id="R2", severity="high", cwe=["CWE-78"],
            evidence={"source": "cmd", "sink": "", "dataflow": [{"file": "a.py", "line": 1}]},
            snippet_hash="h1", fingerprint="fp2", fingerprint_v1="fp2",
        ),
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 1
    assert result[0]["severity"] == "high"
    assert "tool1" in result[0]["tool"]
    assert "tool2" in result[0]["tool"]
    assert "tool1" in result[0]["tools"]
    assert "tool2" in result[0]["tools"]


def test_deduplicate_keeps_different():
    findings = [
        _make_finding(file="a.py", start_line=10, rule_id="R1", cwe=[], snippet_hash="h1"),
        _make_finding(file="b.py", start_line=20, rule_id="R1", cwe=[], snippet_hash="h2"),
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 2


def test_compute_fingerprint_stable_on_line_shift():
    f1 = {"file": "app.py", "start_line": 10, "end_line": 10, "rule_id": "R1",
          "cwe": ["CWE-78"], "evidence": {"source": "os.system(cmd)", "sink": "", "dataflow": []}}
    f2 = {"file": "app.py", "start_line": 15, "end_line": 15, "rule_id": "R1",
          "cwe": ["CWE-78"], "evidence": {"source": "os.system(cmd)", "sink": "", "dataflow": []}}
    assert compute_fingerprint(f1) == compute_fingerprint(f2)


def test_compute_fingerprint_changes_on_content_change():
    f1 = {"file": "app.py", "start_line": 10, "end_line": 10, "rule_id": "R1",
          "cwe": ["CWE-78"], "evidence": {"source": "os.system(cmd)", "sink": "", "dataflow": []}}
    f2 = {"file": "app.py", "start_line": 10, "end_line": 10, "rule_id": "R1",
          "cwe": ["CWE-78"], "evidence": {"source": "subprocess.run(cmd)", "sink": "", "dataflow": []}}
    assert compute_fingerprint(f1) != compute_fingerprint(f2)


def test_compute_fingerprint_fallback_no_snippet():
    f = {"file": "app.py", "start_line": 10, "end_line": 12, "rule_id": "R1",
         "cwe": [], "evidence": {"source": "", "sink": "", "dataflow": []}}
    fp = compute_fingerprint(f)
    assert fp.startswith("sha256:")


def test_deduplicate_fuzzy_cross_tool():
    findings = [
        _make_finding(
            tool="semgrep", rule_id="R1", severity="medium", cwe=["CWE-78"],
            file="app.py", start_line=42, end_line=42,
            evidence={"source": "os.system(cmd)", "sink": "", "dataflow": []},
            snippet_hash="shared_hash", fingerprint="fp1", fingerprint_v1="fp1",
        ),
        _make_finding(
            tool="bandit", rule_id="B608", severity="low", cwe=["CWE-78"],
            file="app.py", start_line=43, end_line=43,
            evidence={"source": "os.system(cmd)", "sink": "", "dataflow": []},
            snippet_hash="shared_hash", fingerprint="fp2", fingerprint_v1="fp2",
        ),
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 1
    assert result[0]["severity"] == "medium"
    assert "semgrep" in result[0]["tools"]
    assert "bandit" in result[0]["tools"]


def test_deduplicate_preserves_highest_severity():
    findings = [
        _make_finding(severity="low", tool="t1", rule_id="R1", cwe=["CWE-89"],
                      snippet_hash="h1", fingerprint="fp1", fingerprint_v1="fp1"),
        _make_finding(severity="critical", tool="t2", rule_id="R2", cwe=["CWE-89"],
                      snippet_hash="h1", fingerprint="fp2", fingerprint_v1="fp2"),
    ]
    result = deduplicate_findings(findings)
    assert result[0]["severity"] == "critical"


def test_deduplicate_preserves_all_rule_ids():
    findings = [
        _make_finding(rule_id="R1", cwe=["CWE-78"], snippet_hash="h1",
                      fingerprint="fp1", fingerprint_v1="fp1"),
        _make_finding(rule_id="B608", cwe=["CWE-78"], snippet_hash="h1",
                      fingerprint="fp2", fingerprint_v1="fp2"),
    ]
    result = deduplicate_findings(findings)
    assert "R1" in result[0]["rule_ids"]
    assert "B608" in result[0]["rule_ids"]


def test_deduplicate_keeps_best_evidence():
    findings = [
        _make_finding(rule_id="R1", cwe=["CWE-78"], severity="high", snippet_hash="h1",
                      evidence={"source": "x", "sink": "", "dataflow": [{"file": "a.py", "line": 1}]},
                      fingerprint="fp1", fingerprint_v1="fp1"),
        _make_finding(rule_id="R2", cwe=["CWE-78"], severity="high", snippet_hash="h1",
                      evidence={"source": "x", "sink": "", "dataflow": [{"file": "a.py", "line": 1}, {"file": "b.py", "line": 2}]},
                      fingerprint="fp2", fingerprint_v1="fp2"),
    ]
    result = deduplicate_findings(findings)
    assert len(result[0]["evidence"]["dataflow"]) == 2


def test_deduplicate_different_vulns_stay_separate():
    findings = [
        _make_finding(rule_id="R1", cwe=["CWE-78"], snippet_hash="h1",
                      fingerprint="fp1", fingerprint_v1="fp1"),
        _make_finding(rule_id="R2", cwe=["CWE-89"], snippet_hash="h1",
                      fingerprint="fp2", fingerprint_v1="fp2"),
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 2


def test_deduplicate_empty():
    assert deduplicate_findings([]) == []


def test_fingerprint_v1_generated():
    f = {"file": "app.py", "start_line": 10, "rule_id": "R1",
         "evidence": {"source": "", "sink": "", "dataflow": []}}
    fp = compute_fingerprint_v1(f)
    assert fp.startswith("sha256:")
    assert fp != compute_fingerprint(f)


# --- Bandit normalizer ---


def _make_bandit_sarif(results: list | None = None) -> dict:
    default_results = [{
        "ruleId": "B608",
        "ruleIndex": 0,
        "level": "error",
        "message": {"text": "Possible SQL injection"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": "app.py"},
                "region": {"startLine": 15, "endLine": 15, "snippet": {"text": "cursor.execute(q)"}},
            }
        }],
    }]
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "bandit", "version": "1.7",
                "rules": [{
                    "id": "B608",
                    "shortDescription": {"text": "Possible SQL injection"},
                    "properties": {
                        "tags": ["security", "CWE-89", "OWASP-A1"],
                        "issue_severity": "LOW",
                        "issue_confidence": "MEDIUM",
                    },
                    "help": {"text": "Use parameterized queries"},
                }],
            }},
            "results": results if results is not None else default_results,
        }],
    }


def test_normalize_bandit():
    sarif = _make_bandit_sarif()
    findings = normalize_bandit(sarif)
    assert len(findings) == 1
    f = findings[0]
    assert f["tool"] == "bandit"
    assert f["rule_id"] == "B608"
    assert f["severity"] == "low"
    assert f["confidence"] == "medium"
    assert "CWE-89" in f["cwe"]
    assert f["file"] == "app.py"
    assert f["start_line"] == 15


def test_normalize_bandit_empty():
    sarif = _make_bandit_sarif(results=[])
    findings = normalize_bandit(sarif)
    assert findings == []


def test_normalize_bandit_severity_mapping():
    for raw, expected in [("HIGH", "high"), ("MEDIUM", "medium"), ("LOW", "low")]:
        sarif = _make_bandit_sarif()
        sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["issue_severity"] = raw
        findings = normalize_bandit(sarif)
        assert findings[0]["severity"] == expected, f"bandit {raw} should map to {expected}"


# --- GoSec normalizer ---


def _make_gosec_sarif(results: list | None = None) -> dict:
    default_results = [{
        "ruleId": "G204",
        "ruleIndex": 0,
        "level": "warning",
        "message": {"text": "Subprocess launched with variable"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": "main.go"},
                "region": {"startLine": 42, "endLine": 42, "snippet": {"text": "exec.Command(cmd)"}},
            }
        }],
    }]
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "gosec", "version": "2.18",
                "rules": [{
                    "id": "G204",
                    "shortDescription": {"text": "Subprocess launched with variable"},
                    "properties": {
                        "tags": ["security", "CWE-78"],
                        "issue_severity": "MEDIUM",
                    },
                    "help": {"text": "Validate input before passing to exec"},
                }],
            }},
            "results": results if results is not None else default_results,
        }],
    }


def test_normalize_gosec():
    sarif = _make_gosec_sarif()
    findings = normalize_gosec(sarif)
    assert len(findings) == 1
    f = findings[0]
    assert f["tool"] == "gosec"
    assert f["rule_id"] == "G204"
    assert f["severity"] == "medium"
    assert "CWE-78" in f["cwe"]
    assert f["file"] == "main.go"


def test_normalize_gosec_severity_from_level():
    sarif = _make_gosec_sarif()
    del sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["issue_severity"]
    sarif["runs"][0]["results"][0]["level"] = "error"
    findings = normalize_gosec(sarif)
    assert findings[0]["severity"] == "high"


# --- CodeQL normalizer ---


def _make_codeql_sarif(results: list | None = None) -> dict:
    default_results = [{
        "ruleId": "py/command-line-injection",
        "ruleIndex": 0,
        "level": "error",
        "message": {"text": "Command injection through shell command construction"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": "server.py"},
                "region": {"startLine": 30, "endLine": 32, "snippet": {"text": "os.system(cmd)"}},
            }
        }],
        "codeFlows": [{
            "threadFlows": [{
                "locations": [
                    {"location": {"physicalLocation": {
                        "artifactLocation": {"uri": "server.py"},
                        "region": {"startLine": 25, "snippet": {"text": "cmd = request.args['cmd']"}},
                    }, "message": {"text": "User input"}}},
                    {"location": {"physicalLocation": {
                        "artifactLocation": {"uri": "server.py"},
                        "region": {"startLine": 30, "snippet": {"text": "os.system(cmd)"}},
                    }, "message": {"text": "Dangerous call"}}},
                ],
            }],
        }],
    }]
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "CodeQL", "version": "2.15",
                "rules": [{
                    "id": "py/command-line-injection",
                    "shortDescription": {"text": "Command line injection"},
                    "properties": {
                        "tags": ["security", "CWE-78", "external/cwe/cwe-78"],
                        "security-severity": "9.8",
                    },
                    "help": {"text": "Do not pass user input to shell commands"},
                }],
            }},
            "results": results if results is not None else default_results,
        }],
    }


def test_normalize_codeql():
    sarif = _make_codeql_sarif()
    findings = normalize_codeql(sarif)
    assert len(findings) == 1
    f = findings[0]
    assert f["tool"] == "codeql"
    assert f["rule_id"] == "py/command-line-injection"
    assert f["severity"] == "critical"
    assert f["confidence"] == "high"
    assert "CWE-78" in f["cwe"]
    assert f["file"] == "server.py"
    assert f["start_line"] == 30


def test_normalize_codeql_taint_tracking():
    sarif = _make_codeql_sarif()
    findings = normalize_codeql(sarif)
    f = findings[0]
    assert len(f["evidence"]["dataflow"]) == 2
    assert f["evidence"]["dataflow"][0]["file"] == "server.py"
    assert f["evidence"]["dataflow"][0]["line"] == 25
    assert f["evidence"]["dataflow"][0]["message"] == "User input"
    assert f["evidence"]["dataflow"][1]["message"] == "Dangerous call"


def test_normalize_codeql_no_numeric_severity():
    sarif = _make_codeql_sarif()
    del sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
    sarif["runs"][0]["results"][0]["level"] = "warning"
    findings = normalize_codeql(sarif)
    assert findings[0]["severity"] == "medium"
    assert findings[0]["confidence"] == "medium"


# --- Dispatcher ---


def test_normalizers_dict_contains_all_tools():
    assert "semgrep" in NORMALIZERS
    assert "gitleaks" in NORMALIZERS
    assert "checkov" in NORMALIZERS
    assert "bandit" in NORMALIZERS
    assert "gosec" in NORMALIZERS
    assert "codeql" in NORMALIZERS


def test_normalizers_unknown_tool_falls_through():
    assert NORMALIZERS.get("unknown-tool", normalize_semgrep) is normalize_semgrep
