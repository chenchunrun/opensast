"""Tests for tool_diagnostics.py."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from tool_diagnostics import collect_tool_outcomes, normalize_tool_outcome


@pytest.mark.parametrize("reason", ["query pack not found", "analysis requires more memory"])
def test_runtime_errors_are_not_optional_skips(reason):
    outcome = normalize_tool_outcome({"tool": "codeql", "success": False, "error_message": reason})
    assert outcome["status"] == "failed"


@pytest.mark.parametrize("tool", ["eslint", "phpstan", "brakeman"])
def test_output_presence_does_not_override_fatal_exit(tool):
    outcome = normalize_tool_outcome({"tool": tool, "success": True, "exit_code": 2})
    assert outcome["status"] == "failed"


def test_swiftlint_violation_exit_is_a_successful_scan():
    assert normalize_tool_outcome({"tool": "swiftlint", "success": True, "exit_code": 2}) is None


def test_brakeman_warnings_are_successful_scan():
    assert normalize_tool_outcome({"tool": "brakeman", "success": True, "exit_code": 3}) is None


def test_brakeman_exception_is_failure_even_with_output():
    outcome = normalize_tool_outcome({"tool": "brakeman", "success": True, "exit_code": 1})
    assert outcome["status"] == "failed"


def test_normalize_skip_with_install_hint():
    outcome = normalize_tool_outcome({
        "tool": "bandit",
        "success": False,
        "error_message": "bandit is not installed. Install: pip install bandit",
    })
    assert outcome is not None
    assert outcome["status"] == "skipped"
    assert outcome["fix_command"] == "pip install bandit"


def test_normalize_gosec_changed_only_skip():
    outcome = normalize_tool_outcome({
        "tool": "gosec",
        "success": False,
        "error_message": "gosec skipped for changed-only scan because staged files do not preserve Go module context",
    })
    assert outcome["status"] == "skipped"
    assert "changed-only" in outcome["fix_command"].lower()


def test_collect_tool_outcomes_ignores_success():
    results = [
        {"tool": "semgrep", "success": True, "error_message": None},
        {"tool": "eslint", "success": False, "error_message": "no package.json found; skipping eslint security scan"},
    ]
    outcomes = collect_tool_outcomes(results)
    assert len(outcomes) == 1
    assert outcomes[0]["tool"] == "eslint"
    assert outcomes[0]["status"] == "skipped"
