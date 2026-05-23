"""Persist scan history for trend analysis and CI trend gates."""

import json
import os
from datetime import datetime, timezone


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utcnow_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _history_dir(output_dir: str) -> str:
    return os.path.join(os.path.dirname(output_dir), "history")


def save_scan_result(summary: dict, findings: list[dict], output_dir: str) -> str:
    history_dir = _history_dir(output_dir)
    os.makedirs(history_dir, exist_ok=True)

    scan_id = _utcnow_compact()
    entry = {
        "scan_id": scan_id,
        "timestamp": _utcnow_iso(),
        "target": summary.get("target", ""),
        "profile": summary.get("profile", "standard"),
        "total_findings": summary.get("total_findings", 0),
        "new_findings": summary.get("new_findings", 0),
        "blocking_findings": summary.get("blocking_findings", 0),
        "severity_counts": summary.get("severity_counts", {}),
        "tools_executed": summary.get("tools_executed", []),
        "duration_seconds": float(summary.get("scan_time", "0s").rstrip("s")),
        "fingerprints": sorted(f.get("fingerprint", "") for f in findings if f.get("fingerprint")),
    }

    path = os.path.join(history_dir, f"scan-{scan_id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(entry, f, indent=2, ensure_ascii=False)

    _prune_history(history_dir, limit=90)
    return scan_id


def load_scan_history(history_dir: str, limit: int = 30) -> list[dict]:
    if not os.path.isdir(history_dir):
        return []
    entries: list[dict] = []
    for name in os.listdir(history_dir):
        if not name.startswith("scan-") or not name.endswith(".json"):
            continue
        path = os.path.join(history_dir, name)
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            data["_path"] = path
            entries.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    entries.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return entries[:limit]


def get_previous_scan(history_dir: str) -> dict | None:
    history = load_scan_history(history_dir, limit=2)
    return history[0] if history else None


def compare_scans(current_summary: dict, current_findings: list[dict],
                  previous: dict) -> dict:
    current_fps = {f.get("fingerprint") for f in current_findings if f.get("fingerprint")}
    previous_fps = set(previous.get("fingerprints", []))

    new_fps = current_fps - previous_fps
    fixed_fps = previous_fps - current_fps
    persisting_fps = current_fps & previous_fps

    prev_counts = previous.get("severity_counts", {})
    curr_counts = current_summary.get("severity_counts", {})

    severity_delta: dict[str, int] = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        severity_delta[sev] = curr_counts.get(sev, 0) - prev_counts.get(sev, 0)

    total_delta = sum(severity_delta.values())

    return {
        "previous_scan_id": previous.get("scan_id"),
        "previous_timestamp": previous.get("timestamp"),
        "new_findings": len(new_fps),
        "fixed_findings": len(fixed_fps),
        "persisting_findings": len(persisting_fps),
        "total_delta": total_delta,
        "severity_delta": severity_delta,
        "direction": "improving" if total_delta < 0 else "stable" if total_delta == 0 else "worsening",
    }


def _prune_history(history_dir: str, limit: int) -> None:
    files = sorted(
        (f for f in os.listdir(history_dir) if f.startswith("scan-") and f.endswith(".json")),
        reverse=True,
    )
    for old in files[limit:]:
        try:
            os.remove(os.path.join(history_dir, old))
        except OSError:
            pass
