"""Tests for CI gate functionality."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from ci_gate import SEVERITY_ORDER, evaluate_gate, get_exit_code


def _make_findings(severities: list[str]) -> list[dict]:
    return [
        {"severity": sev, "is_new": True, "is_suppressed": False}
        for sev in severities
    ]


def test_gate_passes_no_findings():
    result = evaluate_gate([], fail_on="high")
    assert result["passed"] is True
    assert result["blocking_count"] == 0


def test_gate_passes_below_threshold():
    findings = _make_findings(["low", "info"])
    result = evaluate_gate(findings, fail_on="high")
    assert result["passed"] is True


def test_gate_fails_at_threshold():
    findings = _make_findings(["high", "medium", "low"])
    result = evaluate_gate(findings, fail_on="high")
    assert result["passed"] is False
    assert result["blocking_count"] == 1


def test_gate_fails_critical():
    findings = _make_findings(["critical", "high", "medium"])
    result = evaluate_gate(findings, fail_on="critical")
    assert result["passed"] is False
    assert result["blocking_count"] == 1


def test_gate_counts_by_severity():
    findings = _make_findings(["critical", "critical", "high", "medium", "low", "info"])
    result = evaluate_gate(findings, fail_on="medium")
    assert result["passed"] is False
    assert result["blocking_count"] == 4  # 2 critical + 1 high + 1 medium
    assert result["severity_counts"]["critical"] == 2


def test_gate_ignores_suppressed():
    findings = [
        {"severity": "critical", "is_new": True, "is_suppressed": True},
        {"severity": "high", "is_new": True, "is_suppressed": False},
    ]
    result = evaluate_gate(findings, fail_on="high")
    assert result["passed"] is False
    assert result["blocking_count"] == 1


def test_gate_ignores_non_new():
    findings = [
        {"severity": "critical", "is_new": False, "is_suppressed": False},
    ]
    result = evaluate_gate(findings, fail_on="critical")
    assert result["passed"] is True


def test_gate_review_findings_not_blocking_by_default():
    findings = [
        {"severity": "high", "is_new": True, "is_suppressed": False, "triage": {"status": "needs-review"}},
    ]
    result = evaluate_gate(findings, fail_on="high")
    assert result["passed"] is True
    assert result["blocking_count"] == 0
    assert result["review_only_count"] == 1


def test_gate_review_findings_can_block_when_enabled():
    findings = [
        {"severity": "high", "is_new": True, "is_suppressed": False, "triage": {"status": "needs-review"}},
    ]
    result = evaluate_gate(findings, fail_on="high", review_findings_blocking=True)
    assert result["passed"] is False
    assert result["blocking_count"] == 1
    assert result["review_only_count"] == 1
    assert result["review_findings_blocking"] is True


def test_get_exit_code_pass():
    assert get_exit_code({"passed": True}) == 0


def test_get_exit_code_fail():
    assert get_exit_code({"passed": False}) == 1


def test_severity_order():
    assert SEVERITY_ORDER["critical"] > SEVERITY_ORDER["high"]
    assert SEVERITY_ORDER["high"] > SEVERITY_ORDER["medium"]
    assert SEVERITY_ORDER["medium"] > SEVERITY_ORDER["low"]
    assert SEVERITY_ORDER["low"] > SEVERITY_ORDER["info"]
