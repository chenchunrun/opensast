"""Tests for scanner wrappers and runner helpers."""

import json
import logging
import os
import sys
import tempfile
from argparse import Namespace
from unittest.mock import Mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from run_bandit import run_bandit
from run_checkov import run_checkov
from run_codeql import run_codeql
from run_gitleaks import run_gitleaks
from run_gosec import run_gosec
from run_semgrep import get_semgrep_binary, run_semgrep
import sast_runner as runner
from sast_runner import _filter_files_by_languages, _load_llm_findings, _resolve_language_filter, load_config, parse_args


@pytest.fixture
def runner_probe(monkeypatch, tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    (target / "app.py").write_text("print('hello')\n")
    config = {
        "profiles": {"standard": {"tools": {"semgrep": True, "gitleaks": False}},
                     "quick": {"changed_only": True, "tools": {"semgrep": True, "gitleaks": False}}},
        "baseline": {"enabled": False}, "history": {"enabled": False},
    }
    monkeypatch.setattr(runner, "load_config", lambda _: config)
    monkeypatch.setattr(runner, "save_scan_result", lambda *a: "probe")
    semgrep = Mock(return_value={"tool": "semgrep", "success": True, "exit_code": 0})
    monkeypatch.setattr(runner, "run_semgrep", semgrep)
    bandit = Mock(return_value={"tool": "bandit", "success": False, "error_message": "not installed"})
    monkeypatch.setattr(runner, "run_bandit", bandit)
    args = parse_args(["--target", str(target), "--profile", "standard", "--format", "all",
                       "--output-dir", str(tmp_path / "results")])
    return args, semgrep, bandit


@pytest.mark.parametrize("ci", [False, True])
@pytest.mark.parametrize("error", ["scanner crashed", "query file not found"])
@pytest.mark.parametrize("reported_success", [False, True])
def test_scanner_failure_never_passes_gate(runner_probe, ci, error, reported_success):
    args, scanner, _ = runner_probe
    args.ci = ci
    scanner.return_value = {"tool": "semgrep", "success": reported_success, "exit_code": 2, "error_message": error}
    assert runner.run(args) == runner.EXIT_SCAN_FAILURE
    with open(os.path.join(args.output_dir, "summary.json")) as f:
        summary = json.load(f)
    assert summary["gate_result"]["passed"] is False
    assert summary["scan_status"] == "failed"
    assert summary["gate_result"]["tool_failures"]


def test_missing_primary_scanner_is_error(runner_probe):
    args, scanner, _ = runner_probe
    scanner.return_value = {"tool": "semgrep", "success": False, "exit_code": None,
                            "error_message": "semgrep is not installed"}
    assert runner.run(args) == runner.EXIT_TOOL_MISSING


def test_missing_optional_scanner_is_advisory(runner_probe):
    args, _, _ = runner_probe
    assert runner.run(args) == 0


@pytest.mark.parametrize("profile", ["standard", "quick"])
def test_empty_changes_skip_all_scanners(runner_probe, monkeypatch, profile):
    args, scanner, bandit = runner_probe
    args.profile = profile
    args.changed_only = True
    monkeypatch.setattr(runner, "get_changed_files", lambda _: [])
    assert runner.run(args) == 0
    scanner.assert_not_called()
    bandit.assert_not_called()
    with open(os.path.join(args.output_dir, "summary.json")) as f:
        assert json.load(f)["scan_status"] == "skipped"


def test_language_filtered_changes_skip_scanners(runner_probe, monkeypatch):
    args, scanner, _ = runner_probe
    args.changed_only = True
    args.lang = "python"
    monkeypatch.setattr(runner, "get_changed_files", lambda _: ["README.md"])
    assert runner.run(args) == 0
    scanner.assert_not_called()


def test_quick_can_explicitly_scan_all_files(runner_probe, monkeypatch):
    args, scanner, _ = runner_probe
    args.profile = "quick"
    args.changed_only = False
    monkeypatch.setattr(runner, "get_changed_files", lambda _: [])
    assert runner.run(args) == 0
    scanner.assert_called_once()


def test_parse_explicit_full_scan_override():
    assert parse_args(["--profile", "quick", "--no-changed-only"]).changed_only is False
    assert parse_args(["--profile", "quick"]).changed_only is None


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


@pytest.mark.skipif(not get_semgrep_binary(), reason="Semgrep not installed")
def test_semgrep_scan_on_fixture():
    fixture = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable-python")
    if not os.path.isdir(fixture):
        return
    with tempfile.TemporaryDirectory() as tmpdir:
        rules = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".claude", "skills",
                                             "sast-scan", "rules", "semgrep"))
        result = run_semgrep(fixture, tmpdir, config_paths=[rules], timeout=30)
        assert result["success"], result["error_message"]
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


def test_is_ci_environment_detects_ci(monkeypatch):
    # Under a recognized CI env var, the runner knows it is in CI.
    for var in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_HOME"):
        monkeypatch.delenv(var, raising=False)
    assert runner.is_ci_environment() is False

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert runner.is_ci_environment() is True
    monkeypatch.delenv("GITHUB_ACTIONS")

    monkeypatch.setenv("CI", "1")
    assert runner.is_ci_environment() is True
    monkeypatch.delenv("CI")


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


# ---------------------------------------------------------------------------
# changed-only scoping + staged-subset path handling
# ---------------------------------------------------------------------------

import pathlib
import subprocess as sp

_CLT_ROOT = "/Library/Developer/CommandLineTools"


def _ensure_usable_git(monkeypatch) -> None:
    """Make `git` usable for subprocesses, or skip the test.

    On macOS without a selected developer directory, /usr/bin/git is a shim
    that fails. CommandLineTools usually exists on disk; pointing
    DEVELOPER_DIR at it restores the shim without touching the system config.
    """
    probe = sp.run(["git", "--version"], capture_output=True)
    if probe.returncode == 0:
        return
    if os.path.isfile(os.path.join(_CLT_ROOT, "usr", "bin", "git")):
        monkeypatch.setenv("DEVELOPER_DIR", _CLT_ROOT)
        return
    pytest.skip("no usable git binary on this machine")


def _init_git_repo(repo):
    def git(*args):
        sp.run(
            ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args],
            check=True, capture_output=True,
        )

    (repo / "examples" / "demo").mkdir(parents=True, exist_ok=True)
    (repo / "app.py").write_text("x = 1\n")
    (repo / "examples" / "demo" / "vuln.py").write_text("y = 2\n")
    git("init", "-q")
    git("add", "-A")
    git("commit", "-q", "-m", "init")
    (repo / "app.py").write_text("x = 2\n")
    (repo / "examples" / "demo" / "vuln.py").write_text("y = 3\n")
    return repo


def test_get_changed_files_scoped_to_target(tmp_path, monkeypatch):
    _ensure_usable_git(monkeypatch)
    repo = _init_git_repo(tmp_path / "repo")

    from_root = runner.get_changed_files(str(repo))
    assert "app.py" in from_root
    assert "examples/demo/vuln.py" in from_root

    from_subdir = runner.get_changed_files(str(repo / "examples" / "demo"))
    # Paths stay repo-root-relative so staging/reporting keep one coordinate system.
    assert from_subdir == ["examples/demo/vuln.py"]


def test_get_changed_files_outside_git_repo(tmp_path):
    plain = tmp_path / "not-a-repo"
    plain.mkdir()
    (plain / "app.py").write_text("x = 1\n")
    assert runner.get_changed_files(str(plain)) == []


def test_changed_only_subdir_target_falls_back_to_full_scan(runner_probe, monkeypatch, tmp_path):
    args, scanner, _ = runner_probe
    sub = tmp_path / "pkg"
    sub.mkdir()
    (sub / "app.py").write_text("x = 1\n")
    args.target = str(sub)
    args.profile = "quick"
    args.changed_only = True
    monkeypatch.setattr(runner, "detect_project", lambda _: {
        "languages": {"python": 100}, "frameworks": [], "repo_root": str(tmp_path),
        "is_git_repo": True, "iac_files": [],
    })
    monkeypatch.setattr(runner, "get_changed_files", lambda _: [])

    assert runner.run(args) == 0
    scanner.assert_called_once()
    with open(os.path.join(args.output_dir, "summary.json")) as f:
        assert json.load(f)["scan_status"] == "completed"


def _make_fake_semgrep_sarif(target: str) -> dict:
    """One finding per .py file actually present under *target* (absolute URIs).

    Each result carries a codeFlow pointing back into the same tree so the
    evidence-dataflow path remapping is exercised too.
    """
    py_files = sorted(str(p) for p in pathlib.Path(target).rglob("*.py"))
    results = [{
        "ruleId": "python.sql-injection",
        "level": "error",
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": 1, "endLine": 1},
            }
        }],
        "codeFlows": [{
            "threadFlows": [{
                "locations": [{
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": 1},
                        }
                    }
                }]
            }]
        }],
    } for uri in py_files]
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "semgrep", "version": "1.0", "rules": []}},
            "results": results,
        }],
    }


def _probe_run(monkeypatch, tmp_path, *, profile, changed_only, exclude=None):
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "app.py").write_text("cursor.execute(f'...')\n")
    config = {
        "profiles": {
            "standard": {"tools": {"semgrep": True, "gitleaks": False}},
            "quick": {"changed_only": True, "tools": {"semgrep": True, "gitleaks": False}},
        },
        "baseline": {"enabled": False}, "history": {"enabled": False},
    }
    if exclude is not None:
        config["targets"] = {"exclude": exclude}
    monkeypatch.setattr(runner, "load_config", lambda _: config)
    monkeypatch.setattr(runner, "save_scan_result", lambda *a: "probe")
    monkeypatch.setattr(runner, "detect_project", lambda target: {
        "languages": {"python": 100}, "frameworks": [], "repo_root": str(repo),
        "is_git_repo": True, "iac_files": [],
    })

    def fake_semgrep(target, output_dir, **kwargs):
        sarif_path = os.path.join(output_dir, "semgrep.sarif")
        with open(sarif_path, "w") as fh:
            json.dump(_make_fake_semgrep_sarif(target), fh)
        return {"tool": "semgrep", "success": True, "exit_code": 0,
                "sarif_path": sarif_path, "json_path": None, "error_message": None}

    semgrep = Mock(side_effect=fake_semgrep)
    monkeypatch.setattr(runner, "run_semgrep", semgrep)
    monkeypatch.setattr(runner, "run_bandit", Mock(return_value={
        "tool": "bandit", "success": False, "error_message": "not installed"}))
    return repo, semgrep


def test_staged_subset_findings_map_back_to_repo_paths(monkeypatch, tmp_path):
    repo, semgrep = _probe_run(monkeypatch, tmp_path, profile="quick", changed_only=True)
    monkeypatch.setattr(runner, "get_changed_files", lambda _: ["pkg/app.py"])

    out = tmp_path / "results"
    args = parse_args(["--target", str(repo / "pkg"), "--profile", "quick",
                       "--format", "json", "--output-dir", str(out)])
    args.changed_only = True
    assert runner.run(args) == 0

    semgrep.assert_called_once()
    staged_root = semgrep.call_args[0][0]
    assert "opensast-scan-" in staged_root  # scanned the staged copy, not the repo

    with open(os.path.join(out, "merged.sarif")) as f:
        merged = json.load(f)
    uri = merged["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "pkg/app.py"
    assert "opensast-scan-" not in uri
    with open(os.path.join(out, "findings.json")) as f:
        report = json.load(f)
    assert report["total_findings"] == 1
    dataflow = report["findings"][0].get("evidence", {}).get("dataflow", [])
    assert dataflow and dataflow[0]["file"] == "pkg/app.py"


def test_exclude_ancestor_not_applied_when_target_inside(monkeypatch, tmp_path):
    repo, _ = _probe_run(monkeypatch, tmp_path, profile="standard",
                         changed_only=False, exclude=["examples", "tests"])
    # Layout: findings live at <repo>/examples/demo/pkg/app.py; target sits
    # inside the excluded `examples` subtree, so the user's explicit target
    # must override that exclusion.
    demo = repo / "examples" / "demo" / "pkg"
    demo.mkdir(parents=True)
    (demo / "app.py").write_text("cursor.execute(f'...')\n")

    out = tmp_path / "results"
    args = parse_args(["--target", str(demo), "--profile", "standard",
                       "--format", "json", "--output-dir", str(out)])
    args.changed_only = False
    assert runner.run(args) == 0
    with open(os.path.join(out, "findings.json")) as f:
        assert json.load(f)["total_findings"] == 1


def test_exclude_still_applied_for_repo_root_scan(monkeypatch, tmp_path):
    repo, _ = _probe_run(monkeypatch, tmp_path, profile="standard",
                         changed_only=False, exclude=["examples"])
    (repo / "examples" / "pkg").mkdir(parents=True)
    (repo / "examples" / "pkg" / "app.py").write_text("cursor.execute(f'...')\n")

    out = tmp_path / "results"
    args = parse_args(["--target", str(repo), "--profile", "standard",
                       "--format", "json", "--output-dir", str(out)])
    args.changed_only = False
    assert runner.run(args) == 0
    # pkg/app.py survives; the copy under the excluded examples/ dir is dropped.
    with open(os.path.join(out, "findings.json")) as f:
        assert json.load(f)["total_findings"] == 1
    with open(os.path.join(out, "merged.sarif")) as f:
        uris = [res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                for res in json.load(f)["runs"][0]["results"]]
    assert uris == ["pkg/app.py"]


def test_effective_exclude_dirs_drops_target_ancestors():
    from sast_runner import _effective_exclude_dirs
    assert _effective_exclude_dirs(["examples", "tests"], "examples/python-sqli") == ["tests"]
    assert _effective_exclude_dirs(["examples", "tests"], ".") == ["examples", "tests"]
    assert _effective_exclude_dirs(["examples"], "examples") == []
    assert _effective_exclude_dirs(["pkg/tests"], "pkg") == ["pkg/tests"]
    assert _effective_exclude_dirs(["node_modules"], "pkg") == ["node_modules"]


def test_remap_staged_path_handles_file_uri_and_pass_throughs():
    from scan_scope import remap_staged_path
    staged = os.path.join(tempfile.gettempdir(), "opensast-scan-x")
    repo = os.path.join(tempfile.gettempdir(), "repo")
    assert remap_staged_path(f"file://{staged}/pkg/app.py", staged, repo) == f"{repo}/pkg/app.py"
    assert remap_staged_path(os.path.join(staged, "a.py"), staged, repo) == os.path.join(repo, "a.py")
    assert remap_staged_path("pkg/app.py", staged, repo) == "pkg/app.py"  # relative passes through
    assert remap_staged_path("/elsewhere/a.py", staged, repo) == "/elsewhere/a.py"


def test_effective_exclude_dirs_strips_entries_for_repo_root():
    from sast_runner import _effective_exclude_dirs
    assert _effective_exclude_dirs(["examples/", "", "tests"], ".") == ["examples", "tests"]


def test_language_filtered_changes_warn_instead_of_silent_zero(runner_probe, monkeypatch, caplog):
    args, scanner, _ = runner_probe
    args.changed_only = True
    args.lang = "python"
    monkeypatch.setattr(runner, "get_changed_files", lambda _: ["README.md", "docs/guide.md"])
    with caplog.at_level(logging.WARNING, logger="sast_runner"):
        assert runner.run(args) == 0
    scanner.assert_not_called()
    assert any("none match the --lang filter" in rec.message for rec in caplog.records)


def test_staged_subset_gets_target_aware_excludes(monkeypatch, tmp_path):
    """Staged trees mirror repo paths (e.g. examples/...); semgrep's basename
    pruning must not receive ancestor excludes of the explicit target, or the
    whole staged subset gets pruned and the scan silently reports zero."""
    repo, semgrep = _probe_run(monkeypatch, tmp_path, profile="quick",
                               changed_only=True, exclude=["examples", "tests"])
    demo = repo / "examples" / "demo"
    (demo / "pkg").mkdir(parents=True)
    (demo / "pkg" / "app.py").write_text("cursor.execute(f'...')\n")
    monkeypatch.setattr(runner, "get_changed_files", lambda _: ["examples/demo/pkg/app.py"])

    out = tmp_path / "results"
    args = parse_args(["--target", str(demo), "--profile", "quick",
                       "--format", "json", "--output-dir", str(out)])
    args.changed_only = True
    assert runner.run(args) == 0

    semgrep.assert_called_once()
    passed_excludes = semgrep.call_args.kwargs.get("exclude_dirs")
    assert "examples" not in (passed_excludes or [])
    assert "tests" in (passed_excludes or [])  # non-ancestor excludes still passed
