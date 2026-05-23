"""Tests for baseline management."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from baseline import (
    add_suppression,
    filter_new_findings,
    generate_baseline,
    is_suppressed,
    load_baseline,
    save_baseline,
)


def _make_finding(file: str = "app.py", line: int = 10, rule: str = "R1") -> dict:
    return {
        "tool": "semgrep", "rule_id": rule, "title": "Test finding",
        "severity": "high", "file": file, "start_line": line,
        "fingerprint": f"sha256:{file}:{line}:{rule}",
    }


def test_load_baseline_missing_file():
    result = load_baseline("/nonexistent/baseline.json")
    assert result["fingerprints"] == {}
    assert result["suppressions"] == []


def test_save_and_load_baseline():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "baseline.json")
        baseline = generate_baseline([_make_finding()])
        save_baseline(path, baseline)

        loaded = load_baseline(path)
        assert len(loaded["fingerprints"]) == 1


def test_generate_baseline():
    findings = [_make_finding("a.py", 1, "R1"), _make_finding("b.py", 2, "R2")]
    baseline = generate_baseline(findings)
    assert len(baseline["fingerprints"]) == 2
    assert "created_at" in baseline


def test_filter_new_findings_no_baseline():
    findings = [_make_finding(), _make_finding("b.py", 20, "R2")]
    baseline = {"fingerprints": {}, "suppressions": []}
    result = filter_new_findings(findings, baseline)
    assert all(f["is_new"] for f in result)


def test_filter_marks_known_findings():
    f1 = _make_finding()
    findings = [f1]
    baseline = generate_baseline(findings)
    result = filter_new_findings(findings, baseline)
    assert not result[0]["is_new"]


def test_add_suppression():
    baseline = {"fingerprints": {}, "suppressions": []}
    fp = "sha256:abc123"
    result = add_suppression(baseline, fp, "False positive", "team", None)
    assert len(result["suppressions"]) == 1
    assert result["suppressions"][0]["fingerprint"] == fp
    assert result["suppressions"][0]["reason"] == "False positive"


def test_is_suppressed_active():
    fp = "sha256:abc123"
    baseline = {"suppressions": [{"fingerprint": fp, "reason": "test", "owner": "team", "expires_at": "2099-12-31"}]}
    finding = {"fingerprint": fp}
    assert is_suppressed(finding, baseline)


def test_is_suppressed_expired():
    fp = "sha256:abc123"
    baseline = {"suppressions": [{"fingerprint": fp, "reason": "test", "owner": "team", "expires_at": "2020-01-01"}]}
    finding = {"fingerprint": fp}
    assert not is_suppressed(finding, baseline)


def test_is_suppressed_not_found():
    baseline = {"suppressions": []}
    finding = {"fingerprint": "sha256:xyz"}
    assert not is_suppressed(finding, baseline)
