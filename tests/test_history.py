"""Tests for scan history persistence."""

import importlib.util
import json
import os
import tempfile

_spec = importlib.util.spec_from_file_location(
    "history_module",
    os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools", "history.py"),
)
_hist = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_hist)

save_scan_result = _hist.save_scan_result
load_scan_history = _hist.load_scan_history
get_previous_scan = _hist.get_previous_scan
compare_scans = _hist.compare_scans


def _make_summary(**overrides) -> dict:
    defaults = {
        "target": "/tmp/project",
        "profile": "standard",
        "scan_time": "45.2s",
        "total_findings": 10,
        "new_findings": 3,
        "blocking_findings": 1,
        "severity_counts": {"critical": 0, "high": 2, "medium": 3, "low": 5, "info": 0},
        "tools_executed": ["semgrep"],
    }
    defaults.update(overrides)
    return defaults


def _make_findings(count=3) -> list[dict]:
    return [
        {"fingerprint": f"sha256:abc{i}", "severity": "high", "file": f"app{i}.py"}
        for i in range(count)
    ]


def test_save_and_load():
    with tempfile.TemporaryDirectory() as tmpdir:
        output = os.path.join(tmpdir, "results")
        os.makedirs(output)
        summary = _make_summary()
        findings = _make_findings()

        scan_id = save_scan_result(summary, findings, output)
        assert scan_id

        history_dir = os.path.join(tmpdir, "history")
        history = load_scan_history(history_dir)
        assert len(history) == 1
        assert history[0]["total_findings"] == 10
        assert len(history[0]["fingerprints"]) == 3


def test_get_previous_scan():
    with tempfile.TemporaryDirectory() as tmpdir:
        output = os.path.join(tmpdir, "results")
        os.makedirs(output)

        save_scan_result(_make_summary(total_findings=5), _make_findings(2), output)
        save_scan_result(_make_summary(total_findings=8), _make_findings(3), output)

        history_dir = os.path.join(tmpdir, "history")
        prev = get_previous_scan(history_dir)
        assert prev is not None
        assert prev["total_findings"] == 8


def test_compare_scans_improving():
    previous = {
        "scan_id": "001",
        "total_findings": 10,
        "severity_counts": {"critical": 0, "high": 3, "medium": 4, "low": 3, "info": 0},
        "fingerprints": ["sha256:a", "sha256:b", "sha256:c"],
    }
    summary = _make_summary(
        total_findings=8,
        severity_counts={"critical": 0, "high": 2, "medium": 3, "low": 3, "info": 0},
    )
    findings = [{"fingerprint": "sha256:a"}, {"fingerprint": "sha256:b"}]

    result = compare_scans(summary, findings, previous)
    assert result["direction"] == "improving"
    assert result["fixed_findings"] == 1
    assert result["total_delta"] == -2


def test_compare_scans_worsening():
    previous = {
        "scan_id": "001",
        "total_findings": 5,
        "severity_counts": {"critical": 0, "high": 1, "medium": 2, "low": 2, "info": 0},
        "fingerprints": ["sha256:a"],
    }
    summary = _make_summary(
        total_findings=8,
        severity_counts={"critical": 0, "high": 3, "medium": 3, "low": 2, "info": 0},
    )
    findings = [{"fingerprint": "sha256:a"}, {"fingerprint": "sha256:b"}, {"fingerprint": "sha256:c"}]

    result = compare_scans(summary, findings, previous)
    assert result["direction"] == "worsening"
    assert result["new_findings"] == 2


def test_compare_scans_stable():
    fps = ["sha256:a", "sha256:b"]
    previous = {"scan_id": "001", "total_findings": 2,
                "severity_counts": {"high": 1, "medium": 1}, "fingerprints": fps}
    summary = _make_summary(total_findings=2,
                            severity_counts={"high": 1, "medium": 1})
    findings = [{"fingerprint": fp} for fp in fps]

    result = compare_scans(summary, findings, previous)
    assert result["direction"] == "stable"
    assert result["new_findings"] == 0
    assert result["fixed_findings"] == 0


def test_load_empty_history():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert load_scan_history(tmpdir) == []


def test_load_nonexistent_dir():
    assert load_scan_history("/nonexistent/path") == []


def test_prune_history():
    with tempfile.TemporaryDirectory() as tmpdir:
        history_dir = os.path.join(tmpdir, "history")
        os.makedirs(history_dir)
        # Create files directly with unique names
        for i in range(5):
            path = os.path.join(history_dir, f"scan-2026052{i}T120000Z.json")
            with open(path, "w") as f:
                json.dump({"scan_id": f"scan-{i}", "total_findings": i, "fingerprints": []}, f)

        history = load_scan_history(history_dir, limit=100)
        assert len(history) == 5
