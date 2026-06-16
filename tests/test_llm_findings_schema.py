"""Tests for llm_findings_schema.py."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from llm_findings_schema import (
    LLM_FINDINGS_SCHEMA_VERSION,
    extract_importable_findings,
    validate_agent_findings_envelope,
    validate_llm_findings_envelope,
)
from normalize_findings import normalize_llm_findings


def test_envelope_with_confirmed_findings():
    payload = {
        "schema_version": LLM_FINDINGS_SCHEMA_VERSION,
        "session_id": "sess-abc",
        "findings": [],
        "dismissed_targets": [{"target_id": "T-001", "reason": "expected CLI behavior"}],
        "confirmed_findings": [{
            "target_id": "D-002",
            "finding": {
                "rule_id": "llm.idor-risk",
                "title": "IDOR on user profile",
                "severity": "high",
                "file": "api/users.py",
                "start_line": 10,
                "message": "Missing ownership check",
            },
        }],
        "llm_analysis_complete": True,
    }
    valid, errors = validate_llm_findings_envelope(payload)
    assert valid is True, errors
    assert len(extract_importable_findings(payload)) == 1
    findings = normalize_llm_findings(payload)
    assert len(findings) == 1
    assert findings[0]["triage"]["status"] == "confirmed"


def test_rejects_bad_schema_version():
    payload = {
        "schema_version": "9.9",
        "findings": [{
            "rule_id": "llm.x",
            "title": "x",
            "severity": "high",
            "file": "a.py",
            "message": "m",
        }],
    }
    valid, errors = validate_llm_findings_envelope(payload)
    assert valid is False
    assert any("schema_version" in err for err in errors)


def test_agent_findings_requires_agent_flag():
    payload = {
        "schema_version": LLM_FINDINGS_SCHEMA_VERSION,
        "findings": [{
            "rule_id": "llm.agent",
            "title": "Cross-module chain",
            "severity": "high",
            "file": "a.py",
            "message": "m",
        }],
        "agent_review_complete": False,
    }
    valid, errors = validate_agent_findings_envelope(payload)
    assert valid is False
    assert any("agent_review_complete" in err for err in errors)


def test_legacy_list_payload_still_valid():
    payload = [{
        "rule_id": "llm.x",
        "title": "x",
        "severity": "medium",
        "file": "a.py",
        "message": "m",
    }]
    valid, errors = validate_llm_findings_envelope(payload)
    assert valid is True, errors
