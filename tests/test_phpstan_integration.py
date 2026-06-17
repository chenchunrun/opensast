"""Test PHPStan JSON normalization end-to-end.

Validates the normalize_findings -> PHPStan pipe by running a realistic
PHPStan output JSON through the full normalization pipeline and verifying
schema compliance, severity assignment, and path sanitization.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from normalize_findings import normalize_phpstan_json


PHPSTAN_FIXTURE = {
    "totals": {"errors": 2, "file_errors": 2},
    "files": {
        "src/UserController.php": {
            "errors": 1,
            "messages": [
                {
                    "message": "Cannot call method query() on mixed.",
                    "line": 42,
                    "ignorable": True,
                    "identifier": "phpstan.dynamicMethod",
                }
            ],
        },
        "src/AuthService.php": {
            "errors": 1,
            "messages": [
                {
                    "message": "eval() is a dangerous function and should not be used.",
                    "line": 87,
                    "ignorable": True,
                    "identifier": "security.eval",
                }
            ],
        },
        "src/Database.php": {
            "errors": 1,
            "messages": [
                {
                    "message": "Shell command injection via exec().",
                    "line": 120,
                    "ignorable": False,
                    "identifier": "security.shellExec",
                }
            ],
        },
    },
}

PHPSTAN_FIXTURE_PATH_TRAVERSAL = {
    "totals": {"errors": 0, "file_errors": 0},
    "files": {
        "../../etc/passwd": {
            "errors": 1,
            "messages": [
                {
                    "message": "Sensitive file inclusion detected.",
                    "line": 5,
                    "ignorable": False,
                    "identifier": "security.fileInclusion",
                }
            ],
        },
    },
}


def test_normalize_phpstan_basic():
    findings = normalize_phpstan_json(PHPSTAN_FIXTURE)
    assert len(findings) == 3, f"Expected 3 findings, got {len(findings)}"

    # phpstan.dynamicMethod — low (non-security, ignorable=True → low)
    f0 = findings[0]
    assert f0["severity"] == "low", f"Expected 'low' for non-security ignorable, got '{f0['severity']}'"
    assert f0["rule_id"] == "phpstan.dynamicMethod"
    assert f0["file"] == "src/UserController.php"
    assert f0["start_line"] == 42

    # security.eval — high (security keyword), ignorable but security. → NOT downgraded
    f1 = findings[1]
    assert f1["severity"] == "high", (
        f"security.eval should stay 'high' even when ignorable, got '{f1['severity']}'"
    )
    assert f1["rule_id"] == "security.eval"

    # security.shellExec — high (security keyword), NOT ignorable
    f2 = findings[2]
    assert f2["severity"] == "high"
    assert f2["rule_id"] == "security.shellExec"


def test_normalize_phpstan_path_traversal():
    """Paths containing ../ must be sanitized."""
    findings = normalize_phpstan_json(PHPSTAN_FIXTURE_PATH_TRAVERSAL)
    assert len(findings) == 1
    fp = findings[0]["file"]
    # After normpath + lstrip, "../../etc/passwd" → "etc/passwd" per our logic
    # but os.path.normpath("../../etc/passwd") = "../../etc/passwd" on macOS
    # The sanitizer ensures no leading ".." and no absolute path
    assert not fp.startswith(".."), f"Path not sanitized: {fp}"
    assert not fp.startswith("/"), f"Path is absolute after sanitization: {fp}"


def test_normalize_phpstan_empty():
    assert normalize_phpstan_json({}) == []
    assert normalize_phpstan_json({"files": {}}) == []
    assert normalize_phpstan_json({"files": "not-a-dict"}) == []


def test_normalize_phpstan_required_fields():
    findings = normalize_phpstan_json(PHPSTAN_FIXTURE)
    required = ["tool", "rule_id", "title", "severity", "file", "start_line", "message"]
    for f in findings:
        for key in required:
            assert key in f, f"Missing required field '{key}' in finding: {f.get('rule_id')}"
    # Verify all findings have 'phpstan' as tool
    for f in findings:
        assert f["tool"] == "phpstan"


def test_normalize_phpstan_severity_assignment():
    """Verify security keyword → severity mapping."""
    cases = [
        # (identifier, ignorable, expected_severity)
        ("security.remoteCodeExecution", True, "high"),  # security.* NOT downgraded
        ("phpstan.missingReturnType", True, "low"),  # non-security + ignorable → low
        ("unsafe.unserialize", False, "high"),  # unsafe keyword → high
        ("eval.direct", False, "high"),  # eval keyword → high
        ("shell.cmd", False, "high"),  # shell keyword → high
        ("xss.reflected", False, "high"),  # xss keyword → high
        ("path.traversal", False, "high"),  # path keyword → high
        ("sql.injection", False, "high"),  # sql keyword → high
        ("unknown.rule", False, "medium"),  # no security token → medium
    ]
    for identifier, ignorable, expected in cases:
        fixture = {
            "files": {"test.php": {"errors": 1, "messages": [
                {"message": "test", "line": 1, "ignorable": ignorable, "identifier": identifier}
            ]}},
        }
        findings = normalize_phpstan_json(fixture)
        assert findings, f"No finding for {identifier}"
        assert findings[0]["severity"] == expected, (
            f"{identifier} (ignorable={ignorable}): expected {expected}, got {findings[0]['severity']}"
        )


# Allow standalone run
if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
