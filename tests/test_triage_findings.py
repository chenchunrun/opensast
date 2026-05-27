"""Tests for structured findings triage (three-phase)."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from triage_findings import (
    apply_triage_verdicts,
    generate_markdown,
    triage_findings,
    triage_with_llm_context,
    bulk_triage,
)


def _findings() -> list[dict]:
    return [
        {
            "title": "SQL Injection",
            "severity": "high",
            "file": "src/app.py",
            "start_line": 10,
            "fingerprint": "fp-1",
            "triage": {"status": "active"},
        },
        {
            "title": "Needs validation",
            "severity": "medium",
            "file": "src/auth.py",
            "start_line": 20,
            "fingerprint": "fp-2",
            "triage": {"status": "needs-review", "rationale": "Ownership unclear"},
        },
        {
            "title": "Suppressed issue",
            "severity": "high",
            "file": "vendor/lib.js",
            "start_line": 1,
            "fingerprint": "fp-3",
            "is_suppressed": True,
            "suppression_reason": "Generated code",
        },
        {
            "title": "Low signal",
            "severity": "low",
            "file": "src/debug.py",
            "start_line": 5,
            "fingerprint": "fp-4",
        },
        {
            "title": "Critical RCE",
            "severity": "critical",
            "file": "src/exec.py",
            "start_line": 1,
            "fingerprint": "fp-5",
        },
    ]


# ---------------------------------------------------------------------------
# Phase A: Auto-bucket
# ---------------------------------------------------------------------------

class TestTriageFindings:
    def test_groups_findings_correctly(self):
        report = triage_findings(_findings())
        assert report["counts"]["priority"] == 2  # SQL Injection + Critical RCE
        assert report["counts"]["important"] == 1  # Low signal
        assert report["counts"]["needs_review"] == 1
        assert report["counts"]["false_positive"] == 1

    def test_focus_filters_findings(self):
        report = triage_findings(_findings(), focus="high")
        assert report["total_findings"] == 2
        assert report["counts"]["priority"] == 1
        assert report["counts"]["false_positive"] == 1

    def test_focus_critical(self):
        report = triage_findings(_findings(), focus="critical")
        assert report["total_findings"] == 1
        assert report["counts"]["priority"] == 1

    def test_counts_sum_to_total(self):
        report = triage_findings(_findings())
        total = sum(report["counts"].values())
        assert total == report["total_findings"]

    def test_priority_list_is_sorted_by_severity(self):
        report = triage_findings(_findings())
        priorities = report["priority_fix_list"]
        assert priorities[0]["severity"] == "critical"
        assert priorities[1]["severity"] == "high"


class TestGenerateMarkdown:
    def test_contains_all_sections(self):
        content = generate_markdown(triage_findings(_findings()))
        assert "# SAST Triage Report" in content
        assert "Priority Fix List" in content
        assert "Needs Review" in content
        assert "False Positive / Suppressed" in content

    def test_shows_confidence_when_present(self):
        findings = _findings()
        findings[0]["triage"] = {"status": "active", "confidence": 0.9}
        content = generate_markdown(triage_findings(findings))
        assert "0.9" in content


# ---------------------------------------------------------------------------
# Phase B: LLM validation
# ---------------------------------------------------------------------------

class TestTriageWithLLMContext:
    def test_enriches_findings_with_context(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            os.makedirs(os.path.join(tmpdir, "src"), exist_ok=True)
            with open(os.path.join(tmpdir, "src", "app.py"), "w") as f:
                f.write("line1\nline2\ndef run(user_id):\n    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\nline5\n")

            findings = [_findings()[0]]
            findings[0]["file"] = "src/app.py"
            findings[0]["start_line"] = 4
            enriched = triage_with_llm_context(findings, tmpdir)
            assert len(enriched) == 1
            assert enriched[0]["bucket"] == "priority"
            assert enriched[0]["code_context"]["lines"]
            assert "TRUE POSITIVE" in enriched[0]["validation_prompt"]


class TestApplyTriageVerdicts:
    def test_applies_tp_verdict(self):
        findings = _findings()[:2]
        verdicts = [
            {"fingerprint": "fp-1", "verdict": "TP", "confidence": 0.95, "rationale": "User-controlled input"},
        ]
        result = apply_triage_verdicts(findings, verdicts)
        assert result[0]["triage"]["status"] == "confirmed"
        assert result[0]["triage"]["confidence"] == 0.95

    def test_applies_fp_verdict(self):
        findings = _findings()[:2]
        verdicts = [
            {"fingerprint": "fp-2", "verdict": "FP", "confidence": 0.85, "rationale": "Framework protection"},
        ]
        result = apply_triage_verdicts(findings, verdicts)
        assert result[1]["triage"]["status"] == "false-positive"
        assert result[1]["triage"]["confidence"] == 0.85

    def test_preserves_findings_without_verdict(self):
        findings = _findings()[:2]
        verdicts = [{"fingerprint": "fp-99", "verdict": "TP", "confidence": 0.5, "rationale": "Test"}]
        result = apply_triage_verdicts(findings, verdicts)
        assert result[0].get("triage", {}).get("status") == "active"

    def test_verdict_includes_timestamp(self):
        findings = [_findings()[0]]
        verdicts = [{"fingerprint": "fp-1", "verdict": "TP", "confidence": 0.9, "rationale": "R"}]
        result = apply_triage_verdicts(findings, verdicts)
        assert "validated_at" in result[0]["triage"]


# ---------------------------------------------------------------------------
# Phase C: Bulk triage and export
# ---------------------------------------------------------------------------

class TestBulkTriage:
    def test_bulk_triage_returns_targets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            findings_path = os.path.join(tmpdir, "findings.json")
            with open(findings_path, "w") as f:
                json.dump({"findings": _findings()}, f)

            os.makedirs(os.path.join(tmpdir, "src"), exist_ok=True)
            for fname in ["app.py", "auth.py", "exec.py", "debug.py"]:
                with open(os.path.join(tmpdir, "src", fname), "w") as f:
                    f.write("# code\n")

            result = bulk_triage(findings_path, tmpdir)
            assert result["total_targets"] == 5
            assert len(result["validation_targets"]) == 5
            assert result["auto_bucket"]["total_findings"] == 5


class TestExportTriageToBaseline:
    def test_exports_fps_to_baseline(self):
        from triage_findings import export_triage_to_baseline

        with tempfile.TemporaryDirectory() as tmpdir:
            baseline_path = os.path.join(tmpdir, "baseline.json")
            findings = [
                {"fingerprint": "fp-1", "triage": {"status": "false-positive", "confidence": 0.9, "rationale": "Framework CSRF"}},
                {"fingerprint": "fp-2", "triage": {"status": "confirmed", "confidence": 0.95, "rationale": "Real issue"}},
                {"fingerprint": "fp-3", "triage": {"status": "false-positive", "confidence": 0.3, "rationale": "Low conf"}},
            ]
            result = export_triage_to_baseline(findings, baseline_path, min_confidence=0.7)
            assert result["exported_count"] == 1
            assert result["exported"][0]["fingerprint"] == "fp-1"
