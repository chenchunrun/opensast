"""Tests for GitHub PR integration."""

import importlib.util
import os

_spec = importlib.util.spec_from_file_location(
    "github_integration",
    os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools", "github_integration.py"),
)
_gh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gh)

format_pr_comment = _gh.format_pr_comment
is_github_actions = _gh.is_github_actions
get_pr_changed_files = _gh.get_pr_changed_files


def test_format_pr_comment_passed():
    summary = {
        "total_findings": 5,
        "new_findings": 2,
        "blocking_findings": 0,
        "review_findings": 1,
        "severity_counts": {"critical": 0, "high": 1, "medium": 2, "low": 2, "info": 0},
        "gate_result": {"passed": True, "blocking_count": 0, "review_findings_blocking": False},
        "project_archetype": "web-app",
        "llm_analysis_targets": 3,
        "llm_discovery_targets": 1,
        "analysis_enrichment": {
            "by_origin": {"rule-engine": 1, "llm-discovery": 1},
            "by_triage": {"active": 1, "likely": 1},
            "llm_discovery_categories": {"idor-risk": 1},
        },
    }
    findings = [
        {
            "severity": "high", "file": "app.py", "start_line": 10, "title": "SQL injection",
            "is_new": True, "is_suppressed": False, "triage": {"status": "likely"},
        },
        {
            "severity": "medium", "file": "helper.py", "start_line": 20, "title": "Review item",
            "is_new": True, "is_suppressed": False,
            "triage": {"status": "needs-review", "rationale": "Low confidence score after heuristic filtering"},
        },
    ]
    comment = format_pr_comment(summary, findings)
    assert "5 findings" in comment
    assert "PASSED" in comment
    assert "SQL injection" in comment
    assert "standard mode" in comment
    assert "Analysis Enrichment" in comment
    assert "Archetype" in comment
    assert "Origins:" in comment
    assert "LLM discovery categories" in comment
    assert "Needs Review" in comment


def test_format_pr_comment_failed():
    summary = {
        "total_findings": 3,
        "new_findings": 3,
        "blocking_findings": 1,
        "review_findings": 0,
        "severity_counts": {"critical": 1, "high": 0, "medium": 1, "low": 1, "info": 0},
        "gate_result": {"passed": False, "blocking_count": 1, "review_findings_blocking": True},
    }
    comment = format_pr_comment(summary, [])
    assert "FAILED" in comment
    assert "1 blocking" in comment
    assert "strict mode" in comment


def test_is_github_actions():
    original = os.environ.get("GITHUB_ACTIONS")
    try:
        os.environ.pop("GITHUB_ACTIONS", None)
        assert not is_github_actions()
        os.environ["GITHUB_ACTIONS"] = "true"
        assert is_github_actions()
    finally:
        if original is not None:
            os.environ["GITHUB_ACTIONS"] = original
        else:
            os.environ.pop("GITHUB_ACTIONS", None)


def test_get_pr_changed_files_no_gh():
    result = get_pr_changed_files("owner/repo", 123)
    # Returns empty set if gh not available or not in CI
    assert isinstance(result, set)


def test_format_pr_comment_no_findings():
    summary = {
        "total_findings": 0,
        "new_findings": 0,
        "blocking_findings": 0,
        "review_findings": 0,
        "severity_counts": {},
        "gate_result": {"passed": True, "review_findings_blocking": False},
    }
    comment = format_pr_comment(summary, [])
    assert "0 findings" in comment
    assert "PASSED" in comment
