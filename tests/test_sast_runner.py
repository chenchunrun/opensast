"""Tests for scanner wrappers and runner helpers."""

import json
import os
import sys
import tempfile
from argparse import Namespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from run_bandit import run_bandit
from run_checkov import run_checkov
from run_codeql import run_codeql
from run_gitleaks import run_gitleaks
from run_gosec import run_gosec
from run_semgrep import run_semgrep
import sast_runner as runner
from sast_runner import _filter_files_by_languages, _load_llm_findings, _resolve_language_filter, load_config, parse_args


def _assert_tool_result(result: dict, tool_name: str):
    assert result["tool"] == tool_name
    assert "version" in result
    assert "exit_code" in result
    assert "sarif_path" in result
    assert "error_message" in result
    assert "success" in result


def test_semgrep_not_installed_or_runs():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = run_semgrep("/nonexistent", tmpdir)
        _assert_tool_result(result, "semgrep")
        if not result["success"]:
            assert result["error_message"] is not None


def test_gitleaks_not_installed():
    result = run_gitleaks("/nonexistent", "/tmp")
    _assert_tool_result(result, "gitleaks")
    if "not installed" in (result.get("error_message") or ""):
        assert "not installed" in (result.get("error_message") or "")
    else:
        assert "does not exist" in (result.get("error_message") or "")


def test_checkov_not_installed():
    result = run_checkov("/nonexistent", "/tmp")
    _assert_tool_result(result, "checkov")
    if not result["success"]:
        assert result["error_message"] is not None


def test_codeql_not_installed():
    result = run_codeql("/nonexistent", "/tmp")
    _assert_tool_result(result, "codeql")
    if "not installed" in (result.get("error_message") or ""):
        assert "not installed" in (result.get("error_message") or "")
    else:
        assert "does not exist" in (result.get("error_message") or "")


def test_bandit_not_installed():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = run_bandit("/nonexistent", tmpdir)
        _assert_tool_result(result, "bandit")
        if not result["success"]:
            assert "not installed" in (result.get("error_message") or "")


def test_gosec_not_installed():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = run_gosec("/nonexistent", tmpdir)
        _assert_tool_result(result, "gosec")
        if not result["success"]:
            assert "not installed" in (result.get("error_message") or "")


def test_semgrep_scan_on_fixture():
    fixture = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable-python")
    if not os.path.isdir(fixture):
        return
    with tempfile.TemporaryDirectory() as tmpdir:
        result = run_semgrep(fixture, tmpdir)
        if result["success"]:
            assert result["sarif_path"] is not None
            assert os.path.isfile(result["sarif_path"])
            with open(result["sarif_path"]) as f:
                sarif = json.load(f)
            assert sarif["version"] == "2.1.0"
            assert len(sarif["runs"]) > 0


def test_language_filter_resolution():
    detected = {"python", "javascript", "go"}
    assert _resolve_language_filter("auto", detected) == detected
    assert _resolve_language_filter("py", detected) == {"python"}
    assert _resolve_language_filter("js", detected) == {"javascript"}
    assert _resolve_language_filter("java", detected) == set()


def test_filter_files_by_languages():
    files = ["app.py", "web.ts", "cmd/main.go", "README.md"]
    assert _filter_files_by_languages(files, {"python", "go"}) == ["app.py", "cmd/main.go"]


def test_load_config_precedence():
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, ".claude", "sast"), exist_ok=True)
        explicit = os.path.join(tmpdir, "explicit.yml")
        user_cfg = os.path.join(tmpdir, ".claude", "sast", "config.yml")

        with open(user_cfg, "w", encoding="utf-8") as fh:
            fh.write("profiles:\n  standard:\n    fail_on: medium\n")
        with open(explicit, "w", encoding="utf-8") as fh:
            fh.write("profiles:\n  standard:\n    fail_on: low\n")

        old_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)
            config = load_config(explicit)
        finally:
            os.chdir(old_cwd)

        assert config["profiles"]["standard"]["fail_on"] == "low"


def test_load_config_keeps_review_gate_default():
    config = load_config(None)
    assert config["gate"]["review_findings_blocking"] is False


def test_load_llm_findings_imports_and_normalizes():
    with tempfile.TemporaryDirectory() as tmpdir:
        llm_path = os.path.join(tmpdir, "llm-findings.json")
        with open(llm_path, "w", encoding="utf-8") as fh:
            json.dump([
                {
                    "tool": "llm-analyzer",
                    "rule_id": "llm.idor-risk",
                    "title": "Potential IDOR",
                    "severity": "high",
                    "file": os.path.join(tmpdir, "api.py"),
                    "start_line": 12,
                    "message": "Ownership check missing",
                    "evidence": {"source": "req.id", "sink": "query()", "dataflow": []},
                    "triage": {"status": "likely", "rationale": "Needs ownership validation"},
                }
            ], fh)

        findings = _load_llm_findings(llm_path, tmpdir)
        assert len(findings) == 1
        assert findings[0]["tool"] == "llm-analyzer"
        assert findings[0]["file"] == "api.py"
        assert findings[0]["triage"]["status"] == "likely"


def test_load_llm_findings_rejects_invalid_payload():
    with tempfile.TemporaryDirectory() as tmpdir:
        llm_path = os.path.join(tmpdir, "llm-findings.json")
        with open(llm_path, "w", encoding="utf-8") as fh:
            json.dump([
                {
                    "tool": "llm-analyzer",
                    "rule_id": "llm.idor-risk",
                    "title": "Potential IDOR",
                    "severity": "severe",
                    "file": "api.py",
                    "message": "bad severity",
                }
            ], fh)

        findings = _load_llm_findings(llm_path, tmpdir)
        assert findings == []


def test_parse_args_accepts_llm_findings():
    args = parse_args([".", "--llm-findings", "llm-findings.json"])
    assert args.llm_findings == "llm-findings.json"


def test_run_merges_external_llm_findings_end_to_end(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        target_dir = os.path.join(tmpdir, "repo")
        output_dir = os.path.join(tmpdir, "results")
        os.makedirs(target_dir, exist_ok=True)

        with open(os.path.join(target_dir, "app.py"), "w", encoding="utf-8") as fh:
            fh.write("print('hello')\n")

        semgrep_sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "semgrep",
                    "rules": [{
                        "id": "python.lang.security.eval",
                        "shortDescription": {"text": "Eval usage"},
                        "properties": {"tags": ["CWE-94"], "precision": "high"},
                        "help": {"text": "Avoid eval"},
                    }],
                }},
                "results": [{
                    "ruleId": "python.lang.security.eval",
                    "ruleIndex": 0,
                    "level": "error",
                    "message": {"text": "Eval on user input"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "app.py"},
                            "region": {"startLine": 1, "endLine": 1, "snippet": {"text": "eval(user_input)"}},
                        }
                    }],
                }],
            }],
        }

        llm_path = os.path.join(tmpdir, "llm-findings.json")
        with open(llm_path, "w", encoding="utf-8") as fh:
            json.dump([
                {
                    "tool": "llm-analyzer",
                    "rule_id": "llm.idor-risk",
                    "title": "Potential IDOR",
                    "severity": "high",
                    "confidence": "medium",
                    "file": "app.py",
                    "start_line": 3,
                    "end_line": 3,
                    "message": "Ownership check missing",
                    "cwe": ["CWE-639"],
                    "owasp": ["A01:2021-Broken Access Control"],
                    "evidence": {"source": "request.args['id']", "sink": "db.get()", "dataflow": []},
                    "recommendation": "Verify resource ownership",
                    "language": "python",
                    "triage": {"status": "likely", "rationale": "Needs ownership validation"},
                    "analysis_enrichment": {"origin": "llm-discovery", "evidence_strength": "source-sink"},
                    "llm_analysis_notes": "Likely exploitable",
                }
            ], fh)

        def fake_detect_project(target):
            return {"repo_root": target, "languages": {"python": 100}, "frameworks": [], "archetype": "web-app"}

        def fake_run_semgrep(scan_target, out_dir, **kwargs):
            sarif_path = os.path.join(out_dir, "semgrep.sarif")
            with open(sarif_path, "w", encoding="utf-8") as fh:
                json.dump(semgrep_sarif, fh)
            return {
                "tool": "semgrep",
                "version": "1.0",
                "exit_code": 0,
                "sarif_path": sarif_path,
                "json_path": None,
                "error_message": None,
                "success": True,
            }

        def fake_run_bandit(scan_target, out_dir, **kwargs):
            return {
                "tool": "bandit",
                "version": "1.7",
                "exit_code": 0,
                "sarif_path": None,
                "json_path": None,
                "error_message": None,
                "success": True,
            }

        def fake_generate_analysis_plan(**kwargs):
            return {
                "project_archetype": "web-app",
                "analysis_targets": [{"target_id": "T-001"}],
                "discover_targets": [{"file": "app.py", "risks": ["idor-risk"]}],
            }

        def fake_save_analysis_plan(plan, out_dir):
            path = os.path.join(out_dir, "llm-analysis-plan.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(plan, fh)
            return path

        monkeypatch.setattr(runner, "detect_project", fake_detect_project)
        monkeypatch.setattr(runner, "run_semgrep", fake_run_semgrep)
        monkeypatch.setattr(runner, "run_bandit", fake_run_bandit)
        monkeypatch.setattr(runner, "generate_analysis_plan", fake_generate_analysis_plan)
        monkeypatch.setattr(runner, "save_analysis_plan", fake_save_analysis_plan)

        args = Namespace(
            target=target_dir,
            profile="standard",
            changed_only=False,
            lang="auto",
            format="json",
            output_dir=output_dir,
            fail_on="high",
            baseline=None,
            config=None,
            tool_timeout=None,
            llm_findings=llm_path,
            pr_comment=False,
        )

        exit_code = runner.run(args)
        assert exit_code == 1

        findings_path = os.path.join(output_dir, "findings.json")
        summary_path = os.path.join(output_dir, "summary.json")
        assert os.path.isfile(findings_path)
        assert os.path.isfile(summary_path)

        with open(findings_path, encoding="utf-8") as fh:
            findings_json = json.load(fh)
        with open(summary_path, encoding="utf-8") as fh:
            summary_json = json.load(fh)

        assert findings_json["total_findings"] == 2
        assert len(findings_json["findings"]) == 2
        assert findings_json["analysis_enrichment"]["by_origin"]["llm-discovery"] == 1
        assert findings_json["analysis_enrichment"]["by_origin"]["rule-engine"] == 1
        assert summary_json["llm_analysis_targets"] == 1
        assert summary_json["llm_discovery_targets"] == 1
        assert summary_json["project_archetype"] == "web-app"
