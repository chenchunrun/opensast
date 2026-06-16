"""Tests for corpus_report.py (no Semgrep required)."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from corpus_report import build_corpus_report, format_markdown


def test_build_corpus_report_structure():
    corpus_dir = os.path.join(os.path.dirname(__file__), "samples", "corpus")
    report = build_corpus_report(corpus_dir)
    assert report["files"]
    assert "overall" in report
    assert "recall" in report["overall"]
    rendered = format_markdown(report)
    assert "Corpus Validation Report" in rendered
    assert "| File |" in rendered
