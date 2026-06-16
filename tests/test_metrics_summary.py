"""Tests for metrics_summary.py."""

from __future__ import annotations

import json
import os
import sys

import pytest

TOOLS_DIR = os.path.join(
    os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"
)
sys.path.insert(0, TOOLS_DIR)

import metrics_summary as ms  # noqa: E402


def test_build_metrics_has_core_fields():
    metrics = ms.build_metrics()
    assert int(metrics["tests_collected"]) >= 300
    assert metrics["total_rules"] >= metrics["covered_rules"] > 0
    assert metrics["coverage_pct"] == 100.0
    assert len(metrics["supplemental_tools"]) == 8


def test_format_markdown_includes_tests():
    text = ms.format_markdown(ms.build_metrics())
    assert "## OpenSAST Metrics" in text
    assert "Tests collected" in text


def test_format_status_bullets():
    metrics = ms.build_metrics()
    bullets = ms.format_status_bullets(metrics)
    assert "Rule coverage audit" in bullets
    assert "pytest collected count" in bullets


def test_sync_status_doc_roundtrip(tmp_path):
    doc = tmp_path / "status.md"
    doc.write_text(
        "Before\n"
        f"{ms.METRICS_START}\n"
        "- old\n"
        f"{ms.METRICS_END}\n"
        "After\n",
        encoding="utf-8",
    )
    assert ms.sync_status_doc(str(doc)) is True
    content = doc.read_text(encoding="utf-8")
    assert "Before" in content and "After" in content
    assert "- old" not in content
    assert str(ms.build_metrics()["total_rules"]) in content


def test_sync_status_doc_missing_markers(tmp_path):
    doc = tmp_path / "status.md"
    doc.write_text("no markers", encoding="utf-8")
    assert ms.sync_status_doc(str(doc)) is False


def test_main_json_output(capsys):
    rc = ms.main(["--format", "json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert "tests_collected" in payload
