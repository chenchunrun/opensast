"""Tests for baseline management."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from baseline import (
    add_suppression,
    cleanup_expired,
    diff_baselines,
    filter_new_findings,
    generate_baseline,
    get_audit_trail,
    get_stats,
    import_suppressions,
    is_suppressed,
    load_baseline,
    remove_suppression,
    save_baseline,
    update_baseline,
)


def _make_finding(file: str = "app.py", line: int = 10, rule: str = "R1") -> dict:
    return {
        "tool": "semgrep", "rule_id": rule, "title": "Test finding",
        "severity": "high", "file": file, "start_line": line,
        "fingerprint": f"sha256:{file}:{line}:{rule}",
    }


# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------

class TestLoadBaseline:
    def test_missing_file(self):
        result = load_baseline("/nonexistent/baseline.json")
        assert result["fingerprints"] == {}
        assert result["suppressions"] == []
        assert "audit_trail" in result

    def test_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "baseline.json")
            with open(path, "w") as f:
                f.write("not json")
            result = load_baseline(path)
            assert result["fingerprints"] == {}

    def test_wrong_version(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "baseline.json")
            with open(path, "w") as f:
                json.dump({"version": 99, "fingerprints": {}, "suppressions": []}, f)
            result = load_baseline(path)
            assert result["fingerprints"] == {}


class TestSaveAndLoad:
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "baseline.json")
            baseline = generate_baseline([_make_finding()])
            save_baseline(path, baseline)
            loaded = load_baseline(path)
            assert len(loaded["fingerprints"]) == 1
            assert loaded["version"] == 2


class TestGenerateBaseline:
    def test_creates_entries(self):
        findings = [_make_finding("a.py", 1, "R1"), _make_finding("b.py", 2, "R2")]
        baseline = generate_baseline(findings)
        assert len(baseline["fingerprints"]) == 2
        assert "created_at" in baseline

    def test_handles_fingerprint_v1(self):
        findings = [_make_finding()]
        findings[0]["fingerprint_v1"] = "v1-fp"
        baseline = generate_baseline(findings)
        assert len(baseline["fingerprints"]) == 2

    def test_skips_empty_fingerprints(self):
        findings = [{"tool": "semgrep", "rule_id": "R1", "file": "a.py", "severity": "high"}]
        baseline = generate_baseline(findings)
        assert len(baseline["fingerprints"]) == 0


class TestFilterNewFindings:
    def test_no_baseline(self):
        findings = [_make_finding(), _make_finding("b.py", 20, "R2")]
        baseline = {"fingerprints": {}, "suppressions": []}
        result = filter_new_findings(findings, baseline)
        assert all(f["is_new"] for f in result)

    def test_marks_known_findings(self):
        f1 = _make_finding()
        findings = [f1]
        baseline = generate_baseline(findings)
        result = filter_new_findings(findings, baseline)
        assert not result[0]["is_new"]

    def test_suppressed_findings_marked(self):
        findings = [_make_finding()]
        baseline = generate_baseline(findings)
        fp = findings[0]["fingerprint"]
        baseline["suppressions"] = [{"fingerprint": fp, "reason": "test", "owner": "team"}]
        result = filter_new_findings(findings, baseline)
        assert result[0]["is_suppressed"] is True


class TestUpdateBaseline:
    def test_adds_new_fingerprints(self):
        baseline = generate_baseline([_make_finding()])
        new_finding = _make_finding("b.py", 20, "R2")
        updated = update_baseline(baseline, [new_finding])
        assert len(updated["fingerprints"]) == 2

    def test_preserves_first_seen(self):
        findings = [_make_finding()]
        baseline = generate_baseline(findings)
        first_seen = baseline["fingerprints"][findings[0]["fingerprint"]]["first_seen"]
        updated = update_baseline(baseline, findings)
        assert updated["fingerprints"][findings[0]["fingerprint"]]["first_seen"] == first_seen


# ---------------------------------------------------------------------------
# Suppressions
# ---------------------------------------------------------------------------

class TestAddSuppression:
    def test_adds_new(self):
        baseline = {"fingerprints": {}, "suppressions": [], "audit_trail": []}
        fp = "sha256:abc123"
        result = add_suppression(baseline, fp, "False positive", "team", None)
        assert len(result["suppressions"]) == 1
        assert result["suppressions"][0]["fingerprint"] == fp
        assert result["suppressions"][0]["reason"] == "False positive"

    def test_updates_existing(self):
        baseline = {"fingerprints": {}, "suppressions": [
            {"fingerprint": "fp-1", "reason": "old", "owner": "team"},
        ], "audit_trail": []}
        result = add_suppression(baseline, "fp-1", "new reason", "team2", None)
        assert len(result["suppressions"]) == 1
        assert result["suppressions"][0]["reason"] == "new reason"

    def test_records_audit(self):
        baseline = {"fingerprints": {}, "suppressions": [], "audit_trail": []}
        add_suppression(baseline, "fp-1", "test", "team", None)
        assert len(baseline["audit_trail"]) == 1
        assert baseline["audit_trail"][0]["action"] == "add_suppression"


class TestRemoveSuppression:
    def test_removes(self):
        baseline = {"fingerprints": {}, "suppressions": [
            {"fingerprint": "fp-1", "reason": "test", "owner": "team"},
        ], "audit_trail": []}
        result = remove_suppression(baseline, "fp-1")
        assert len(result["suppressions"]) == 0

    def test_records_audit(self):
        baseline = {"fingerprints": {}, "suppressions": [
            {"fingerprint": "fp-1", "reason": "test", "owner": "team"},
        ], "audit_trail": []}
        remove_suppression(baseline, "fp-1")
        assert len(baseline["audit_trail"]) == 1
        assert baseline["audit_trail"][0]["action"] == "remove_suppression"


class TestIsSuppressed:
    def test_active(self):
        fp = "sha256:abc123"
        baseline = {"suppressions": [{"fingerprint": fp, "reason": "test", "owner": "team", "expires_at": "2099-12-31"}]}
        assert is_suppressed({"fingerprint": fp}, baseline)

    def test_expired(self):
        fp = "sha256:abc123"
        baseline = {"suppressions": [{"fingerprint": fp, "reason": "test", "owner": "team", "expires_at": "2020-01-01"}]}
        assert not is_suppressed({"fingerprint": fp}, baseline)

    def test_not_found(self):
        baseline = {"suppressions": []}
        assert not is_suppressed({"fingerprint": "sha256:xyz"}, baseline)

    def test_permanent(self):
        fp = "sha256:abc123"
        baseline = {"suppressions": [{"fingerprint": fp, "reason": "test", "owner": "team", "expires_at": None}]}
        assert is_suppressed({"fingerprint": fp}, baseline)


# ---------------------------------------------------------------------------
# New functions
# ---------------------------------------------------------------------------

class TestDiffBaselines:
    def test_added_and_removed(self):
        before = {"fingerprints": {"fp-1": {}, "fp-2": {}}, "suppressions": []}
        after = {"fingerprints": {"fp-2": {}, "fp-3": {}}, "suppressions": []}
        diff = diff_baselines(before, after)
        assert "fp-1" in diff["fingerprints_removed"]
        assert "fp-3" in diff["fingerprints_added"]
        assert "fp-2" in diff["fingerprints_unchanged"]

    def test_suppression_changes(self):
        before = {"fingerprints": {}, "suppressions": [{"fingerprint": "fp-1"}]}
        after = {"fingerprints": {}, "suppressions": [{"fingerprint": "fp-1"}, {"fingerprint": "fp-2"}]}
        diff = diff_baselines(before, after)
        assert "fp-2" in diff["suppressions_added"]


class TestGetStats:
    def test_stats(self):
        baseline = {
            "fingerprints": {"fp-1": {}, "fp-2": {}},
            "suppressions": [
                {"fingerprint": "fp-1", "expires_at": "2099-12-31"},
                {"fingerprint": "fp-2", "expires_at": "2020-01-01"},
                {"fingerprint": "fp-3", "expires_at": None},
            ],
            "created_at": "2026-01-01",
            "updated_at": "2026-05-01",
        }
        stats = get_stats(baseline)
        assert stats["total_fingerprints"] == 2
        assert stats["total_suppressions"] == 3
        assert stats["expired_suppressions"] == 1
        assert stats["permanent_suppressions"] == 1
        assert stats["active_suppressions"] == 2  # permanent + non-expired (expired is NOT active)

    def test_empty_baseline(self):
        stats = get_stats({"fingerprints": {}, "suppressions": []})
        assert stats["total_fingerprints"] == 0
        assert stats["total_suppressions"] == 0


class TestCleanupExpired:
    def test_removes_expired(self):
        baseline = {
            "fingerprints": {},
            "suppressions": [
                {"fingerprint": "fp-1", "expires_at": "2099-12-31", "owner": "team"},
                {"fingerprint": "fp-2", "expires_at": "2020-01-01", "owner": "team"},
            ],
            "audit_trail": [],
        }
        result = cleanup_expired(baseline)
        assert result["removed_count"] == 1
        assert "fp-2" in result["removed"]
        assert len(baseline["suppressions"]) == 1

    def test_nothing_to_cleanup(self):
        baseline = {
            "fingerprints": {},
            "suppressions": [{"fingerprint": "fp-1", "expires_at": "2099-12-31", "owner": "team"}],
            "audit_trail": [],
        }
        result = cleanup_expired(baseline)
        assert result["removed_count"] == 0


class TestImportSuppressions:
    def test_imports_new(self):
        baseline = {"fingerprints": {}, "suppressions": [], "audit_trail": []}
        suppressions = [
            {"fingerprint": "fp-1", "reason": "FP"},
            {"fingerprint": "fp-2", "reason": "Accepted risk"},
        ]
        result = import_suppressions(baseline, suppressions, "importer")
        assert result["imported_count"] == 2
        assert result["skipped_count"] == 0

    def test_skips_existing(self):
        baseline = {
            "fingerprints": {},
            "suppressions": [{"fingerprint": "fp-1", "reason": "old", "owner": "team"}],
            "audit_trail": [],
        }
        suppressions = [
            {"fingerprint": "fp-1", "reason": "new"},
            {"fingerprint": "fp-2", "reason": "new"},
        ]
        result = import_suppressions(baseline, suppressions)
        assert result["imported_count"] == 1
        assert result["skipped_count"] == 1

    def test_skips_empty_fingerprint(self):
        baseline = {"fingerprints": {}, "suppressions": [], "audit_trail": []}
        suppressions = [{"fingerprint": "", "reason": "empty"}]
        result = import_suppressions(baseline, suppressions)
        assert result["skipped_count"] == 1


class TestGetAuditTrail:
    def test_returns_trail(self):
        baseline = {
            "audit_trail": [
                {"action": "add_suppression", "fingerprint": "fp-1"},
                {"action": "remove_suppression", "fingerprint": "fp-2"},
            ]
        }
        trail = get_audit_trail(baseline)
        assert len(trail) == 2
        assert trail[0]["action"] == "remove_suppression"  # Most recent first

    def test_respects_limit(self):
        baseline = {"audit_trail": [{"action": f"action-{i}"} for i in range(100)]}
        trail = get_audit_trail(baseline, limit=10)
        assert len(trail) == 10
