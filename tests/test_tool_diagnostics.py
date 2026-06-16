"""Tests for tool_diagnostics.py."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from tool_diagnostics import collect_tool_outcomes, normalize_tool_outcome


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
