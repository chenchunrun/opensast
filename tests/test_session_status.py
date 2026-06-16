"""Tests for session_status.py."""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from session_status import compute_session_status, count_unfixed_high, format_markdown


def test_empty_results_dir(tmp_path):
    status = compute_session_status(str(tmp_path))
    assert status["scan_complete"] is False
    assert status["pending_discover"] == 0
    assert status["unfixed_high"] == 0
    assert status["completed_phases"] == []
    assert len(status["next_steps"]) >= 1
    assert "sast-scan" in status["next_steps"][0].lower()


def test_scan_only_summary(tmp_path):
    summary = {
        "profile": "quick",
        "total_findings": 2,
        "severity_counts": {"high": 1, "low": 1},
    }
    with open(tmp_path / "summary.json", "w", encoding="utf-8") as fh:
        json.dump(summary, fh)

    status = compute_session_status(str(tmp_path))
    assert status["scan_complete"] is True
    assert status["profile"] == "quick"
    assert "scan" in status["completed_phases"]
    assert status["pending_discover"] == 0


def test_full_session_with_plan_and_findings(tmp_path):
    plan = {
        "session_id": "sess-test123",
        "completed_phases": ["scan"],
        "discover_targets": [{"type": "discover_idor"}, {"type": "discover_csrf"}],
        "analysis_targets": [{"type": "validate_finding", "target_id": "T-001"}],
    }
    findings = {
        "findings": [
            {
                "severity": "high",
                "title": "SQL injection",
                "fingerprint": "fp-1",
                "triage": {"status": "needs-review"},
            },
            {
                "severity": "low",
                "title": "Info",
                "fingerprint": "fp-2",
            },
        ]
    }
    llm_findings = {
        "session_id": "sess-test123",
        "llm_analysis_complete": True,
        "validate_targets_analyzed": 1,
        "discover_targets_analyzed": 1,
        "findings_discovered": 2,
        "agent_review_complete": False,
    }

    for name, payload in (
        ("summary.json", {"profile": "standard", "total_findings": 2}),
        ("llm-analysis-plan.json", plan),
        ("findings.json", findings),
        ("llm-findings.json", llm_findings),
    ):
        with open(tmp_path / name, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)

    status = compute_session_status(str(tmp_path))
    assert status["session_id"] == "sess-test123"
    assert status["pending_discover"] == 1
    assert status["unfixed_high"] == 1
    assert "phase_a" in status["completed_phases"]
    assert "phase_b" in status["completed_phases"]
    assert status["llm_findings_present"] is True
    assert any("triage" in step.lower() for step in status["next_steps"])

    rendered = format_markdown(status)
    assert "Pending discover targets" in rendered
    assert "sess-test123" in rendered


def test_count_unfixed_high_skips_false_positives():
    findings = [
        {"severity": "high", "triage": {"status": "false-positive"}},
        {"severity": "critical", "is_suppressed": True},
        {"severity": "high", "triage": {"status": "confirmed"}},
    ]
    assert count_unfixed_high(findings) == 1


def test_save_plan_sets_session_fields(tmp_path, monkeypatch):
    import sys

    tools_dir = os.path.join(os.path.dirname(__file__), "..", ".claude/skills/sast-scan/tools")
    sys.path.insert(0, tools_dir)
    from llm_orchestrator import generate_analysis_plan, save_analysis_plan

    project = {"archetype": "library", "languages": {"python": {}}, "frameworks": []}
    plan = generate_analysis_plan([], project, str(tmp_path))
    path = save_analysis_plan(plan, str(tmp_path))

    with open(path, encoding="utf-8") as fh:
        saved = json.load(fh)

    assert saved["session_id"]
    assert saved["session_id"].startswith("sess-")
    assert "scan" in saved["completed_phases"]

    path2 = save_analysis_plan(
        generate_analysis_plan([], project, str(tmp_path)),
        str(tmp_path),
    )
    with open(path2, encoding="utf-8") as fh:
        saved2 = json.load(fh)
    assert saved2["session_id"] == saved["session_id"]
