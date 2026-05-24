"""Tests for the taint tracking engine."""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from taint_tracker import track_taint, track_project, _extract_tainted_vars

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples", "taint")


class TestExtractTaintedVars:
    def test_nextjs_search_params(self):
        line = '    const name = request.nextUrl.searchParams.get("name")'
        results = _extract_tainted_vars(line, 5, "typescript")
        assert len(results) > 0
        var_names = [r[0] for r in results]
        assert "name" in var_names

    def test_python_request_args(self):
        line = "    host = request.args.get('host')"
        results = _extract_tainted_vars(line, 3, "python")
        assert len(results) > 0
        var_names = [r[0] for r in results]
        assert "host" in var_names

    def test_no_tainted_vars(self):
        line = "    const result = await db.query('SELECT 1')"
        results = _extract_tainted_vars(line, 7, "typescript")
        assert len(results) == 0


class TestTrackTaint:
    def test_detects_sql_injection_in_nextjs(self):
        file_path = os.path.join(SAMPLES_DIR, "nextjs-sql-inject.ts")
        if not os.path.isfile(file_path):
            pytest.skip("Sample file not found")
        findings = track_taint(file_path, "typescript")
        sql_findings = [f for f in findings if f["rule_id"] == "taint.sql"]
        assert len(sql_findings) >= 1
        assert "CWE-89" in sql_findings[0]["cwe"]
        assert sql_findings[0]["tool"] == "taint-tracker"
        assert sql_findings[0]["evidence"]["source"] != ""
        assert sql_findings[0]["evidence"]["sink"] != ""

    def test_no_finding_for_sanitized_input(self):
        file_path = os.path.join(SAMPLES_DIR, "nextjs-safe.ts")
        if not os.path.isfile(file_path):
            pytest.skip("Sample file not found")
        findings = track_taint(file_path, "typescript")
        assert len(findings) == 0

    def test_detects_command_injection_in_python(self):
        file_path = os.path.join(SAMPLES_DIR, "python-cmd-inject.py")
        if not os.path.isfile(file_path):
            pytest.skip("Sample file not found")
        findings = track_taint(file_path, "python")
        cmd_findings = [f for f in findings if f["rule_id"] == "taint.command"]
        assert len(cmd_findings) >= 1
        assert "CWE-78" in cmd_findings[0]["cwe"]

    def test_empty_file(self, tmp_path):
        p = tmp_path / "empty.ts"
        p.write_text("")
        findings = track_taint(str(p), "typescript")
        assert findings == []

    def test_no_source_file(self, tmp_path):
        p = tmp_path / "safe.ts"
        p.write_text('const x = "hello"\nconsole.log(x)\n')
        findings = track_taint(str(p), "typescript")
        assert findings == []

    def test_finding_has_dataflow(self):
        file_path = os.path.join(SAMPLES_DIR, "nextjs-sql-inject.ts")
        if not os.path.isfile(file_path):
            pytest.skip("Sample file not found")
        findings = track_taint(file_path, "typescript")
        if findings:
            df = findings[0]["evidence"]["dataflow"]
            assert len(df) >= 2  # source + sink at minimum
            assert any("source" in step.get("message", "") for step in df)
            assert any("sink" in step.get("message", "") for step in df)


class TestTrackProject:
    def test_project_scan(self):
        findings = track_project(SAMPLES_DIR, {"languages": {"typescript": 1, "python": 1}})
        assert len(findings) >= 2  # SQL + command injection
        tools = {f["tool"] for f in findings}
        assert "taint-tracker" in tools

    def test_empty_project(self, tmp_path):
        d = tmp_path / "empty_project"
        d.mkdir()
        findings = track_project(str(d), {"languages": {}})
        assert findings == []
