"""Tests for fix_finding three-tier fix workflow."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from fix_finding import (
    apply_fix,
    build_fix_report,
    commit_fix,
    create_fix_branch,
    find_finding,
    generate_llm_fix_prompt,
    generate_test_stub,
    load_findings,
    render_markdown,
    rerun_targeted_scan,
    rollback_fix,
    validate_fix,
    _fix_template,
    FIX_TEMPLATES,
    GENERIC_TEMPLATE,
)


def _finding(**overrides) -> dict:
    base = {
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
        "cwe": ["CWE-89"],
    }
    base.update(overrides)
    return base


def _write_file(tmpdir: str, rel_path: str, content: str) -> str:
    abs_path = os.path.join(tmpdir, rel_path)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(content)
    return abs_path


# ---------------------------------------------------------------------------
# Phase A: Template matching
# ---------------------------------------------------------------------------

class TestFindFinding:
    def test_matches_id(self):
        finding = _finding()
        assert find_finding([finding], "finding-1") == finding

    def test_matches_fingerprint(self):
        finding = _finding()
        assert find_finding([finding], "fp-1") == finding

    def test_matches_fingerprint_v1(self):
        finding = _finding(fingerprint_v1="fp-v1")
        assert find_finding([finding], "fp-v1") == finding

    def test_returns_none_for_missing(self):
        assert find_finding([_finding()], "missing") is None


class TestFixTemplate:
    def test_sql_injection_template(self):
        template = _fix_template(_finding(title="SQL Injection", message="queryRaw"))
        assert "parameterized" in template["summary"].lower()

    def test_command_injection_template(self):
        template = _fix_template(_finding(title="Command Injection", rule_id="python.command-injection", cwe=["CWE-78"], message="subprocess"))
        assert "argument" in template["summary"].lower() or "shell" in template["summary"].lower()

    def test_ssrf_template(self):
        template = _fix_template(_finding(title="SSRF", cwe=["CWE-918"], message="server-side request", rule_id="ssrf"))
        assert "request" in template["summary"].lower()

    def test_csrf_template(self):
        template = _fix_template(_finding(title="CSRF Protection Missing", cwe=["CWE-352"], message="anti-forgery", rule_id="csrf"))
        assert "csrf" in template["summary"].lower() or "token" in template["summary"].lower()

    def test_rate_limiting_template(self):
        template = _fix_template(_finding(title="Rate Limiting Missing", cwe=["CWE-770"], message="throttle brute force", rule_id="rate-limit"))
        assert "limit" in template["summary"].lower() or "rate" in template["summary"].lower()

    def test_mass_assignment_template(self):
        template = _fix_template(_finding(title="Mass Assignment", cwe=["CWE-915"], message="field binding whitelist", rule_id="mass-assign"))
        assert "whitelist" in template["summary"].lower() or "allowlist" in template["summary"].lower() or "field" in template["summary"].lower()

    def test_crypto_template(self):
        template = _fix_template(_finding(title="Weak Crypto", message="encrypt decrypt aes salt", cwe=["CWE-321"], rule_id="crypto"))
        assert "crypto" in template["summary"].lower() or "key" in template["summary"].lower()

    def test_timing_template(self):
        template = _fix_template(_finding(title="Timing Attack", cwe=["CWE-208"], message="timing-safe constant time comparison", rule_id="timing"))
        assert "comparison" in template["summary"].lower() or "timing" in template["summary"].lower() or "constant" in template["summary"].lower()

    def test_config_template(self):
        template = _fix_template(_finding(title="Config Security", message="placeholder change-me default secret cors", cwe=["CWE-426"], rule_id="config"))
        assert "secret" in template["summary"].lower() or "config" in template["summary"].lower() or "default" in template["summary"].lower()

    def test_generic_fallback(self):
        template = _fix_template(_finding(title="Totally Unknown Custom Vuln XYZ", rule_id="custom.xyz", cwe=[], message="nothing matches here"))
        assert template["summary"] == GENERIC_TEMPLATE["summary"]

    def test_all_templates_have_required_fields(self):
        for keywords, template in FIX_TEMPLATES:
            assert "summary" in template
            assert "fix_steps" in template
            assert len(template["fix_steps"]) >= 2


class TestBuildFixReport:
    def test_includes_template_and_context(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_file(tmpdir, "src/app.py",
                        "def run(user_id):\n"
                        "    query = 'SELECT 1'\n"
                        "    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
                        "    return True\n")

            report = build_fix_report(_finding(), tmpdir)
            assert "parameterized" in report["fix_summary"].lower()
            assert report["context"]["lines"]
            assert any(item["highlight"] for item in report["context"]["lines"])
            assert report["phase"] == "A"
            assert report["apply_supported"] is True
            assert report["cwe"] == ["CWE-89"]

    def test_missing_file_returns_empty_context(self):
        report = build_fix_report(_finding(file="nonexistent.py"), "/tmp")
        assert report["context"]["lines"] == []


class TestRenderMarkdown:
    def test_includes_all_sections(self):
        report = {
            "finding_id": "finding-1",
            "fingerprint": "fp-1",
            "title": "SQL Injection",
            "rule_id": "python.sql.injection",
            "severity": "high",
            "confidence": "high",
            "location": "src/app.py:3",
            "message": "User input flows into SQL query",
            "cwe": ["CWE-89"],
            "apply_requested": False,
            "apply_supported": True,
            "phase": "A",
            "fix_summary": "Replace string-built queries with parameterized queries.",
            "fix_steps": ["Use parameter binding."],
            "example_before": "bad()",
            "example_after": "good()",
            "context": {"lines": [{"line": 3, "text": "cursor.execute(...)", "highlight": True}]},
            "rerun": None,
        }
        content = render_markdown(report)
        assert "# Fix for finding: fp-1" in content
        assert "CWE-89" in content
        assert "Phase: A" in content
        assert "Local context" in content
        assert "Validation" in content

    def test_includes_apply_info(self):
        report = {
            "finding_id": "f1",
            "fingerprint": "fp1",
            "title": "Test",
            "rule_id": "r1",
            "severity": "high",
            "confidence": "high",
            "location": "a.py:1",
            "message": "",
            "cwe": [],
            "apply_requested": True,
            "apply_supported": True,
            "phase": "A",
            "fix_summary": "Fix it",
            "fix_steps": [],
            "example_before": None,
            "example_after": None,
            "context": {"lines": []},
            "rerun": None,
            "apply_info": {"applied": True, "file": "/a.py", "backup": "/a.py.bak", "original_size": 10, "fixed_size": 15},
        }
        content = render_markdown(report)
        assert "Applied" in content
        assert "/a.py.bak" in content

    def test_includes_test_stub(self):
        report = {
            "finding_id": "f1",
            "fingerprint": "fp1",
            "title": "Test",
            "rule_id": "r1",
            "severity": "high",
            "confidence": "high",
            "location": "a.py:1",
            "message": "",
            "cwe": [],
            "apply_requested": False,
            "apply_supported": True,
            "phase": "A",
            "fix_summary": "Fix",
            "fix_steps": [],
            "example_before": None,
            "example_after": None,
            "context": {"lines": []},
            "rerun": None,
            "test_stub": "def test_something(): pass",
        }
        content = render_markdown(report)
        assert "Generated test stub" in content
        assert "def test_something" in content


# ---------------------------------------------------------------------------
# Phase B: LLM prompt generation
# ---------------------------------------------------------------------------

class TestGenerateLLMFixPrompt:
    def test_prompt_contains_finding_and_context(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_file(tmpdir, "src/app.py",
                        "line1\nline2\ncursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\nline4\n")

            prompt = generate_llm_fix_prompt(_finding(), tmpdir)
            assert prompt["finding"]["id"] == "finding-1"
            assert prompt["template_hint"]["summary"]
            assert prompt["code_context"]["lines"]
            assert "instructions" in prompt


# ---------------------------------------------------------------------------
# Phase C: Verification
# ---------------------------------------------------------------------------

class TestRerunTargetedScan:
    def test_uses_runner(self, monkeypatch):
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
            _write_file(tmpdir, "src/app.py", "print('x')\n")
            result = rerun_targeted_scan(tmpdir, _finding())

        assert result["returncode"] == 0
        assert calls["cmd"][1].endswith("sast_runner.py")
        assert "--profile" in calls["cmd"]


class TestValidateFix:
    def test_resolved_when_finding_removed(self):
        before = [_finding(fingerprint="fp-1")]
        after = [_finding(fingerprint="fp-2")]
        result = validate_fix(before, after, "fp-1")
        assert result["resolved"] is True
        assert result["new_findings_count"] == 1

    def test_not_resolved_when_finding_still_present(self):
        before = [_finding(fingerprint="fp-1")]
        after = [_finding(fingerprint="fp-1")]
        result = validate_fix(before, after, "fp-1")
        assert result["resolved"] is False

    def test_no_new_findings(self):
        before = [_finding(fingerprint="fp-1"), _finding(fingerprint="fp-2")]
        after = [_finding(fingerprint="fp-2")]
        result = validate_fix(before, after, "fp-1")
        assert result["resolved"] is True
        assert result["new_findings_count"] == 0


# ---------------------------------------------------------------------------
# Apply and rollback
# ---------------------------------------------------------------------------

class TestApplyFix:
    def test_creates_backup_and_writes_fix(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            original = "def vulnerable():\n    pass\n"
            _write_file(tmpdir, "src/app.py", original)
            finding = _finding(file="src/app.py")
            fixed = "def safe():\n    pass\n"

            result = apply_fix(tmpdir, finding, fixed)
            assert result["applied"] is True
            assert os.path.isfile(result["backup"])
            assert result["original_size"] == len(original)
            assert result["fixed_size"] == len(fixed)

            with open(os.path.join(tmpdir, "src", "app.py")) as f:
                assert f.read() == fixed

    def test_no_file_path_returns_error(self):
        result = apply_fix("/tmp", {"file": ""}, "fixed")
        assert result["applied"] is False

    def test_missing_file_returns_error(self):
        result = apply_fix("/tmp", {"file": "nonexistent.py"}, "fixed")
        assert result["applied"] is False


class TestRollbackFix:
    def test_restores_original_and_removes_backup(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            original = "original content\n"
            _write_file(tmpdir, "src/app.py", original)
            finding = _finding(file="src/app.py")
            apply_fix(tmpdir, finding, "fixed content\n")

            result = rollback_fix(tmpdir, finding)
            assert result["rolled_back"] is True

            with open(os.path.join(tmpdir, "src", "app.py")) as f:
                assert f.read() == original
            assert not os.path.isfile(os.path.join(tmpdir, "src", "app.py.opensast-bak"))

    def test_no_backup_returns_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_file(tmpdir, "src/app.py", "content\n")
            result = rollback_fix(tmpdir, _finding(file="src/app.py"))
            assert result["rolled_back"] is False


# ---------------------------------------------------------------------------
# Git branch
# ---------------------------------------------------------------------------

class TestCreateFixBranch:
    def test_creates_branch(self, monkeypatch):
        calls = {}

        def fake_run(cmd, **kwargs):
            calls["cmd"] = cmd
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

        import fix_finding
        monkeypatch.setattr(fix_finding.subprocess, "run", fake_run)
        result = create_fix_branch("sha256:abcdef123456789")
        assert result["created"] is True
        assert result["branch"] == "sast-fix/sha256:abcde"


# ---------------------------------------------------------------------------
# Test generation
# ---------------------------------------------------------------------------

class TestGenerateTestStub:
    def test_python_stub(self):
        stub = generate_test_stub(_finding(language="python", title="SQL Injection"), "/tmp")
        assert "import pytest" in stub["test_code"]
        assert "def test_" in stub["test_code"]

    def test_typescript_stub(self):
        stub = generate_test_stub(_finding(language="typescript", title="XSS"), "/tmp")
        assert "describe(" in stub["test_code"]
        assert "it(" in stub["test_code"]

    def test_go_stub(self):
        stub = generate_test_stub(_finding(language="go", title="Command Injection"), "/tmp")
        assert "func Test" in stub["test_code"]
        assert "testing" in stub["test_code"]

    def test_java_stub(self):
        stub = generate_test_stub(_finding(language="java", title="Path Traversal"), "/tmp")
        assert "public class" in stub["test_code"]

    def test_unknown_language_stub(self):
        stub = generate_test_stub(_finding(language="rust"), "/tmp")
        assert "TODO" in stub["test_code"] or "test" in stub["test_code"].lower()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class TestFixResultArtifact:
    def test_main_writes_fix_result_json(self, monkeypatch, tmp_path):
        findings_path = tmp_path / "findings.json"
        findings_path.write_text(json.dumps({"findings": [_finding()]}), encoding="utf-8")
        results_dir = tmp_path / ".claude" / "sast" / "results"
        results_dir.mkdir(parents=True)

        import fix_finding as ff

        monkeypatch.setattr(
            ff,
            "rerun_targeted_scan",
            lambda *a, **k: {"command": ["scan"], "returncode": 0, "output_dir": str(results_dir)},
        )

        exit_code = ff.main([
            "fp-1",
            "--findings", str(findings_path),
            "--repo-root", str(tmp_path),
            "--test",
            "--output", "json",
        ])
        assert exit_code == 0
        fix_result_path = results_dir / "fix-result.json"
        assert fix_result_path.is_file()
        data = json.loads(fix_result_path.read_text(encoding="utf-8"))
        assert data["fingerprint"] == "fp-1"
        assert "rescan_suggestion" in data
        assert "changed-only" in data["rescan_suggestion"]


class TestLoadFindings:
    def test_loads_from_dict(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "f.json")
            with open(path, "w") as f:
                json.dump({"findings": [_finding()]}, f)
            assert len(load_findings(path)) == 1

    def test_loads_from_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "f.json")
            with open(path, "w") as f:
                json.dump([_finding()], f)
            assert len(load_findings(path)) == 1
