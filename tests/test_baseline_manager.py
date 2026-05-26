"""Tests for baseline_manager CLI helpers."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from baseline_manager import (
    create_baseline_file,
    show_baseline_file,
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


def test_create_and_show_baseline_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        findings_path = os.path.join(tmpdir, "findings.json")
        baseline_path = os.path.join(tmpdir, "baseline.json")
        _write_findings(findings_path, [_finding("fp-1"), _finding("fp-2")])

        created = create_baseline_file(findings_path, baseline_path)
        shown = show_baseline_file(baseline_path)

        assert created["fingerprints"] == 2
        assert shown["fingerprints"] == 2
        assert shown["suppressions"] == 0


def test_update_baseline_file_adds_new_fingerprints():
    with tempfile.TemporaryDirectory() as tmpdir:
        findings_path = os.path.join(tmpdir, "findings.json")
        baseline_path = os.path.join(tmpdir, "baseline.json")
        _write_findings(findings_path, [_finding("fp-1")])
        create_baseline_file(findings_path, baseline_path)

        _write_findings(findings_path, [_finding("fp-1"), _finding("fp-2", severity="medium")])
        updated = update_baseline_file(findings_path, baseline_path)

        assert updated["fingerprints"] == 2


def test_suppress_and_unsuppress_fingerprint():
    with tempfile.TemporaryDirectory() as tmpdir:
        baseline_path = os.path.join(tmpdir, "baseline.json")

        suppressed = suppress_fingerprint(baseline_path, "fp-1", "False positive", "security", None)
        assert suppressed["suppressions"] == 1

        unsuppressed = unsuppress_fingerprint(baseline_path, "fp-1")
        assert unsuppressed["suppressions"] == 0
