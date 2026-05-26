"""Tests for structured findings triage."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from triage_findings import generate_markdown, triage_findings


def _findings() -> list[dict]:
    return [
        {
            "title": "SQL Injection",
            "severity": "high",
            "file": "src/app.py",
            "start_line": 10,
            "triage": {"status": "active"},
        },
        {
            "title": "Needs validation",
            "severity": "medium",
            "file": "src/auth.py",
            "start_line": 20,
            "triage": {"status": "needs-review", "rationale": "Ownership unclear"},
        },
        {
            "title": "Suppressed issue",
            "severity": "high",
            "file": "vendor/lib.js",
            "start_line": 1,
            "is_suppressed": True,
            "suppression_reason": "Generated code",
        },
        {
            "title": "Low signal",
            "severity": "low",
            "file": "src/debug.py",
            "start_line": 5,
        },
    ]


def test_triage_groups_findings():
    report = triage_findings(_findings())
    assert report["counts"]["priority"] == 1
    assert report["counts"]["important"] == 1
    assert report["counts"]["needs_review"] == 1
    assert report["counts"]["false_positive"] == 1


def test_triage_focus_filters_findings():
    report = triage_findings(_findings(), focus="high")
    assert report["total_findings"] == 2
    assert report["counts"]["priority"] == 1
    assert report["counts"]["false_positive"] == 1


def test_generate_markdown_contains_sections():
    content = generate_markdown(triage_findings(_findings()))
    assert "# SAST Triage Report" in content
    assert "Priority Fix List" in content
    assert "Needs Review" in content
    assert "False Positive / Suppressed" in content
