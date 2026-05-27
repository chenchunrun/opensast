"""Tests for baseline_manager CLI helpers."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from baseline_manager import (
    audit_baseline_file,
    cleanup_baseline_file,
    create_baseline_file,
    diff_baseline_file,
    import_baseline_file,
    show_baseline_file,
    stats_baseline_file,
    suppress_fingerprint,
    unsuppress_fingerprint,
    update_baseline_file,
)


def _write_findings(path: str, findings: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"findings": findings}, f)


def _finding(fp: str, file: str = "src/app.py", severity: str = "high") -> dict:
    return {
        "fingerprint": fp,
        "tool": "semgrep",
        "rule_id": "test.rule",
        "file": file,
        "severity": severity,
    }


class TestCreateAndShow:
    def test_create_and_show(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            findings_path = os.path.join(tmpdir, "findings.json")
            baseline_path = os.path.join(tmpdir, "baseline.json")
            _write_findings(findings_path, [_finding("fp-1"), _finding("fp-2")])

            created = create_baseline_file(findings_path, baseline_path)
            shown = show_baseline_file(baseline_path)

            assert created["fingerprints"] == 2
            assert shown["fingerprints"] == 2
            assert shown["suppressions"] == 0


class TestUpdate:
    def test_update_adds_new_fingerprints(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            findings_path = os.path.join(tmpdir, "findings.json")
            baseline_path = os.path.join(tmpdir, "baseline.json")
            _write_findings(findings_path, [_finding("fp-1")])
            create_baseline_file(findings_path, baseline_path)

            _write_findings(findings_path, [_finding("fp-1"), _finding("fp-2", severity="medium")])
            updated = update_baseline_file(findings_path, baseline_path)

            assert updated["fingerprints"] == 2


class TestSuppressUnsuppress:
    def test_suppress_and_unsuppress(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline_path = os.path.join(tmpdir, "baseline.json")

            suppressed = suppress_fingerprint(baseline_path, "fp-1", "False positive", "security", None)
            assert suppressed["suppressions"] == 1

            unsuppressed = unsuppress_fingerprint(baseline_path, "fp-1")
            assert unsuppressed["suppressions"] == 0


class TestDiff:
    def test_diff_shows_changes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            findings_path = os.path.join(tmpdir, "findings.json")
            baseline_path = os.path.join(tmpdir, "baseline.json")
            _write_findings(findings_path, [_finding("fp-1"), _finding("fp-2")])
            create_baseline_file(findings_path, baseline_path)

            _write_findings(findings_path, [_finding("fp-2"), _finding("fp-3")])
            diff = diff_baseline_file(baseline_path, findings_path)

            assert "fp-1" in diff["fingerprints_removed"]
            assert "fp-3" in diff["fingerprints_added"]


class TestStats:
    def test_stats(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline_path = os.path.join(tmpdir, "baseline.json")
            suppress_fingerprint(baseline_path, "fp-1", "FP", "team", "2099-12-31")
            suppress_fingerprint(baseline_path, "fp-2", "Expired", "team", "2020-01-01")

            stats = stats_baseline_file(baseline_path)
            assert stats["total_suppressions"] == 2
            assert stats["expired_suppressions"] == 1


class TestCleanup:
    def test_cleanup_removes_expired(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline_path = os.path.join(tmpdir, "baseline.json")
            suppress_fingerprint(baseline_path, "fp-1", "Active", "team", "2099-12-31")
            suppress_fingerprint(baseline_path, "fp-2", "Expired", "team", "2020-01-01")

            result = cleanup_baseline_file(baseline_path)
            assert result["removed_count"] == 1

            shown = show_baseline_file(baseline_path)
            assert shown["suppressions"] == 1


class TestImport:
    def test_import_from_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline_path = os.path.join(tmpdir, "baseline.json")
            import_path = os.path.join(tmpdir, "imports.json")
            with open(import_path, "w") as f:
                json.dump([
                    {"fingerprint": "fp-1", "reason": "Imported FP"},
                    {"fingerprint": "fp-2", "reason": "Imported risk"},
                ], f)

            result = import_baseline_file(baseline_path, import_path, "importer")
            assert result["imported_count"] == 2

            stats = stats_baseline_file(baseline_path)
            assert stats["total_suppressions"] == 2


class TestAudit:
    def test_audit_trail(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline_path = os.path.join(tmpdir, "baseline.json")
            suppress_fingerprint(baseline_path, "fp-1", "FP", "team", None)
            suppress_fingerprint(baseline_path, "fp-2", "Risk", "team", None)

            audit = audit_baseline_file(baseline_path)
            assert audit["total_entries"] == 2
            assert audit["audit_trail"][0]["action"] == "add_suppression"
