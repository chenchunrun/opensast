"""Tests for fix_finding helper."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from fix_finding import (
    build_fix_report,
    find_finding,
    render_markdown,
    rerun_targeted_scan,
)


def _finding() -> dict:
    return {
        "id": "finding-1",
        "fingerprint": "fp-1",
        "rule_id": "python.sql.injection",
        "title": "SQL Injection",
        "severity": "high",
        "confidence": "high",
        "language": "python",
        "file": "src/app.py",
        "start_line": 3,
        "message": "User input flows into SQL query",
    }


def test_find_finding_matches_id_and_fingerprint():
    finding = _finding()
    findings = [finding]
    assert find_finding(findings, "finding-1") == finding
    assert find_finding(findings, "fp-1") == finding
    assert find_finding(findings, "missing") is None


def test_build_fix_report_reads_context_and_template():
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, "src"), exist_ok=True)
        file_path = os.path.join(tmpdir, "src", "app.py")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("def run(user_id):\n")
            f.write("    query = 'SELECT 1'\n")
            f.write("    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n")
            f.write("    return True\n")

        report = build_fix_report(_finding(), tmpdir)
        assert "parameterized queries" in report["fix_summary"].lower()
        assert report["context"]["lines"]
        assert any(item["highlight"] for item in report["context"]["lines"])


def test_render_markdown_includes_validation_and_context():
    report = {
        "finding_id": "finding-1",
        "fingerprint": "fp-1",
        "title": "SQL Injection",
        "rule_id": "python.sql.injection",
        "severity": "high",
        "confidence": "high",
        "location": "src/app.py:3",
        "message": "User input flows into SQL query",
        "apply_requested": False,
        "apply_supported": False,
        "fix_summary": "Replace string-built queries with parameterized queries.",
        "fix_steps": ["Use parameter binding."],
        "example_before": "bad()",
        "example_after": "good()",
        "context": {"lines": [{"line": 3, "text": "cursor.execute(...)", "highlight": True}]},
        "rerun": None,
    }
    content = render_markdown(report)
    assert "# Fix for finding: fp-1" in content
    assert "Local context" in content
    assert "Validation" in content


def test_rerun_targeted_scan_uses_runner(monkeypatch):
    calls = {}

    class FakeResult:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(cmd, capture_output, text):
        calls["cmd"] = cmd
        return FakeResult()

    monkeypatch.setattr("fix_finding.subprocess.run", fake_run)

    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, "src"), exist_ok=True)
        with open(os.path.join(tmpdir, "src", "app.py"), "w", encoding="utf-8") as f:
            f.write("print('x')\n")

        result = rerun_targeted_scan(tmpdir, _finding())

    assert result["returncode"] == 0
    assert calls["cmd"][1].endswith("sast_runner.py")
    assert "--profile" in calls["cmd"]
    assert "--lang" in calls["cmd"]
