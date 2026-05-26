"""Manage scan baselines for suppressing known issues."""

import json
import os
from datetime import datetime, timezone


_BASELINE_VERSION = 2


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _empty_baseline() -> dict:
    now = _utcnow_iso()
    return {
        "version": _BASELINE_VERSION,
        "created_at": now,
        "updated_at": now,
        "fingerprints": {},
        "suppressions": [],
    }


def load_baseline(path: str) -> dict:
    if not os.path.isfile(path):
        return _empty_baseline()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return _empty_baseline()
    if data.get("version") not in (_BASELINE_VERSION, 1):
        return _empty_baseline()
    return data


def save_baseline(path: str, baseline: dict) -> None:
    baseline["updated_at"] = _utcnow_iso()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2, ensure_ascii=False)


def generate_baseline(findings: list[dict]) -> dict:
    baseline = _empty_baseline()
    for f in findings:
        fp = f.get("fingerprint", "")
        if not fp:
            continue
        entry = {
            "first_seen": _utcnow_iso(),
            "last_seen": _utcnow_iso(),
            "tool": f.get("tool", ""),
            "rule_id": f.get("rule_id", ""),
            "file": f.get("file", ""),
            "severity": f.get("severity", "info"),
        }
        baseline["fingerprints"][fp] = entry
        fp_v1 = f.get("fingerprint_v1", "")
        if fp_v1 and fp_v1 != fp:
            baseline["fingerprints"][fp_v1] = entry
    return baseline


def filter_new_findings(findings: list[dict], baseline: dict) -> list[dict]:
    baseline = json.loads(json.dumps(baseline))
    known_fps = set(baseline.get("fingerprints", {}).keys())
    suppressed_fps = set()
    for s in baseline.get("suppressions", []):
        suppressed_fps.add(s.get("fingerprint", ""))

    result: list[dict] = []
    for f in findings:
        fp = f.get("fingerprint", "")
        fp_v1 = f.get("fingerprint_v1", "")
        is_known = fp in known_fps or (fp_v1 and fp_v1 in known_fps)

        entry = dict(f)
        entry["is_new"] = not is_known

        if not entry.get("is_suppressed"):
            entry["is_suppressed"] = False
            entry["suppression_reason"] = None
        check_fp = fp if fp in suppressed_fps else fp_v1 if fp_v1 in suppressed_fps else ""
        if check_fp:
            if is_suppressed({"fingerprint": check_fp}, baseline):
                entry["is_suppressed"] = True
                for s in baseline.get("suppressions", []):
                    if s.get("fingerprint") == check_fp:
                        entry["suppression_reason"] = s.get("reason")
                        break

        if is_known:
            update_fp = fp if fp in known_fps else fp_v1
            baseline["fingerprints"][update_fp]["last_seen"] = _utcnow_iso()
            baseline["fingerprints"][update_fp]["severity"] = f.get(
                "severity", baseline["fingerprints"][update_fp].get("severity", "info")
            )

        result.append(entry)
    return result


def add_suppression(
    baseline: dict,
    fingerprint: str,
    reason: str,
    owner: str,
    expires_at: str | None = None,
) -> dict:
    for s in baseline.get("suppressions", []):
        if s.get("fingerprint") == fingerprint:
            s["reason"] = reason
            s["owner"] = owner
            s["expires_at"] = expires_at
            baseline["updated_at"] = _utcnow_iso()
            return baseline

    baseline.setdefault("suppressions", []).append({
        "fingerprint": fingerprint,
        "reason": reason,
        "owner": owner,
        "expires_at": expires_at,
    })
    baseline["updated_at"] = _utcnow_iso()
    return baseline


def remove_suppression(baseline: dict, fingerprint: str) -> dict:
    suppressions = baseline.get("suppressions", [])
    updated = [s for s in suppressions if s.get("fingerprint") != fingerprint]
    baseline["suppressions"] = updated
    baseline["updated_at"] = _utcnow_iso()
    return baseline


def update_baseline(baseline: dict, findings: list[dict]) -> dict:
    baseline.setdefault("fingerprints", {})
    for f in findings:
        fp = f.get("fingerprint", "")
        if not fp:
            continue

        entry = baseline["fingerprints"].get(fp, {})
        first_seen = entry.get("first_seen", _utcnow_iso())
        baseline["fingerprints"][fp] = {
            "first_seen": first_seen,
            "last_seen": _utcnow_iso(),
            "tool": f.get("tool", entry.get("tool", "")),
            "rule_id": f.get("rule_id", entry.get("rule_id", "")),
            "file": f.get("file", entry.get("file", "")),
            "severity": f.get("severity", entry.get("severity", "info")),
        }

        fp_v1 = f.get("fingerprint_v1", "")
        if fp_v1 and fp_v1 != fp:
            baseline["fingerprints"][fp_v1] = baseline["fingerprints"][fp]

    baseline["updated_at"] = _utcnow_iso()
    return baseline


def is_suppressed(finding: dict, baseline: dict) -> bool:
    fp = finding.get("fingerprint", "")
    now = datetime.now(timezone.utc)

    for s in baseline.get("suppressions", []):
        if s.get("fingerprint") != fp:
            continue
        expires = s.get("expires_at")
        if expires is None:
            return True
        try:
            exp_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            return now < exp_dt
        except (ValueError, TypeError):
            return True

    return False
