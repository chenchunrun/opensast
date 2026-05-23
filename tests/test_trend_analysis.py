"""Tests for trend analysis."""

import importlib.util
import os

_spec = importlib.util.spec_from_file_location(
    "trend_analysis",
    os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools", "trend_analysis.py"),
)
_ta = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ta)

compute_trend_metrics = _ta.compute_trend_metrics


def _make_history_entry(total, high, medium, low, fps, day_offset=0) -> dict:
    ts = f"2026-05-{23 - day_offset:02d}T12:00:00Z"
    return {
        "scan_id": f"scan-{day_offset}",
        "timestamp": ts,
        "total_findings": total,
        "severity_counts": {"critical": 0, "high": high, "medium": medium, "low": low, "info": 0},
        "fingerprints": fps,
    }


def test_trend_improving():
    history = [
        _make_history_entry(10, 3, 4, 3, ["a", "b", "c", "d"], day_offset=0),
        _make_history_entry(15, 4, 6, 5, ["a", "b", "c", "d", "e", "f"], day_offset=5),
    ]
    result = compute_trend_metrics(history)
    assert result["direction"] == "improving"
    assert result["total_delta"] == -5
    assert result["fixed_findings"] == 2


def test_trend_worsening():
    history = [
        _make_history_entry(15, 4, 6, 5, ["a", "b", "c", "d", "e"], day_offset=0),
        _make_history_entry(10, 3, 4, 3, ["a", "b"], day_offset=5),
    ]
    result = compute_trend_metrics(history)
    assert result["direction"] == "worsening"
    assert result["total_delta"] == 5
    assert result["new_findings"] == 3


def test_trend_stable():
    fps = ["a", "b"]
    history = [
        _make_history_entry(5, 1, 2, 2, fps, day_offset=0),
        _make_history_entry(5, 1, 2, 2, fps, day_offset=1),
    ]
    result = compute_trend_metrics(history)
    assert result["direction"] == "stable"
    assert result["total_delta"] == 0


def test_trend_single_scan():
    history = [_make_history_entry(5, 1, 2, 2, ["a"], day_offset=0)]
    result = compute_trend_metrics(history)
    assert result["direction"] == "unknown"
    assert "Insufficient" in result.get("message", "")


def test_trend_daily_data():
    history = [
        _make_history_entry(10, 2, 4, 4, ["a"], day_offset=0),
        _make_history_entry(8, 1, 3, 4, ["a"], day_offset=3),
        _make_history_entry(12, 3, 5, 4, ["a", "b"], day_offset=7),
    ]
    result = compute_trend_metrics(history)
    assert len(result["daily_data"]) == 3
    assert result["daily_data"][0]["date"] == "2026-05-16"


def test_trend_severity_deltas():
    history = [
        _make_history_entry(10, 3, 4, 3, ["a"], day_offset=0),
        _make_history_entry(5, 1, 2, 2, ["a"], day_offset=1),
    ]
    result = compute_trend_metrics(history)
    assert result["severity_deltas"]["high"] == 2
    assert result["severity_deltas"]["medium"] == 2


def test_trend_mttr():
    history = [
        _make_history_entry(8, 2, 3, 3, ["a", "b"], day_offset=0),
        _make_history_entry(10, 2, 4, 4, ["a", "b", "c"], day_offset=3),
        _make_history_entry(9, 2, 3, 4, ["a", "c"], day_offset=7),
    ]
    result = compute_trend_metrics(history)
    assert result["mttr_days"] is not None
    assert result["mttr_days"] > 0
