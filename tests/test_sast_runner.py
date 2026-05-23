"""Tests for scanner wrappers - graceful handling when tools are not installed."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from run_bandit import run_bandit
from run_checkov import run_checkov
from run_codeql import run_codeql
from run_gitleaks import run_gitleaks
from run_gosec import run_gosec
from run_semgrep import run_semgrep


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
    if not result["success"]:
        assert "not installed" in (result.get("error_message") or "")


def test_checkov_not_installed():
    result = run_checkov("/nonexistent", "/tmp")
    _assert_tool_result(result, "checkov")
    if not result["success"]:
        assert result["error_message"] is not None


def test_codeql_not_installed():
    result = run_codeql("/nonexistent", "/tmp")
    _assert_tool_result(result, "codeql")
    if not result["success"]:
        assert "not installed" in (result.get("error_message") or "")


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
