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
        "audit_trail": [],
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
            old_reason = s.get("reason", "")
            s["reason"] = reason
            s["owner"] = owner
            s["expires_at"] = expires_at
            _record_audit(baseline, "update_suppression", fingerprint, f"reason: {old_reason} → {reason}", owner)
            baseline["updated_at"] = _utcnow_iso()
            return baseline

    baseline.setdefault("suppressions", []).append({
        "fingerprint": fingerprint,
        "reason": reason,
        "owner": owner,
        "expires_at": expires_at,
        "created_at": _utcnow_iso(),
    })
    _record_audit(baseline, "add_suppression", fingerprint, reason, owner)
    baseline["updated_at"] = _utcnow_iso()
    return baseline


def remove_suppression(baseline: dict, fingerprint: str) -> dict:
    suppressions = baseline.get("suppressions", [])
    removed = [s for s in suppressions if s.get("fingerprint") == fingerprint]
    updated = [s for s in suppressions if s.get("fingerprint") != fingerprint]
    baseline["suppressions"] = updated
    if removed:
        _record_audit(baseline, "remove_suppression", fingerprint, f"Removed: {removed[0].get('reason', '')}", removed[0].get("owner", ""))
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


# ---------------------------------------------------------------------------
# New functions: diff, stats, cleanup, import, audit
# ---------------------------------------------------------------------------

def _record_audit(baseline: dict, action: str, fingerprint: str, detail: str, owner: str) -> None:
    baseline.setdefault("audit_trail", []).append({
        "timestamp": _utcnow_iso(),
        "action": action,
        "fingerprint": fingerprint,
        "detail": detail,
        "owner": owner,
    })


def diff_baselines(baseline_before: dict, baseline_after: dict) -> dict:
    """Compare two baseline versions and return the diff."""
    fps_before = set(baseline_before.get("fingerprints", {}).keys())
    fps_after = set(baseline_after.get("fingerprints", {}).keys())

    sups_before = {s.get("fingerprint") for s in baseline_before.get("suppressions", [])}
    sups_after = {s.get("fingerprint") for s in baseline_after.get("suppressions", [])}

    return {
        "fingerprints_added": sorted(fps_after - fps_before),
        "fingerprints_removed": sorted(fps_before - fps_after),
        "fingerprints_unchanged": sorted(fps_before & fps_after),
        "suppressions_added": sorted(sups_after - sups_before),
        "suppressions_removed": sorted(sups_before - sups_after),
        "suppressions_unchanged": sorted(sups_before & sups_after),
    }


def get_stats(baseline: dict) -> dict:
    """Get baseline statistics."""
    suppressions = baseline.get("suppressions", [])
    now = datetime.now(timezone.utc)

    expired_count = 0
    active_count = 0
    permanent_count = 0

    for s in suppressions:
        expires = s.get("expires_at")
        if expires is None:
            permanent_count += 1
            active_count += 1
        else:
            try:
                exp_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if now >= exp_dt:
                    expired_count += 1
                else:
                    active_count += 1
            except (ValueError, TypeError):
                permanent_count += 1
                active_count += 1

    return {
        "total_fingerprints": len(baseline.get("fingerprints", {})),
        "total_suppressions": len(suppressions),
        "active_suppressions": active_count,
        "expired_suppressions": expired_count,
        "permanent_suppressions": permanent_count,
        "created_at": baseline.get("created_at"),
        "updated_at": baseline.get("updated_at"),
    }


def cleanup_expired(baseline: dict) -> dict:
    """Remove expired suppressions from the baseline."""
    now = datetime.now(timezone.utc)
    cleaned: list[dict] = []
    removed: list[str] = []

    for s in baseline.get("suppressions", []):
        expires = s.get("expires_at")
        if expires is None:
            cleaned.append(s)
            continue
        try:
            exp_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if now >= exp_dt:
                removed.append(s.get("fingerprint", ""))
                _record_audit(baseline, "cleanup_expired", s.get("fingerprint", ""), "Expired suppression removed", s.get("owner", ""))
            else:
                cleaned.append(s)
        except (ValueError, TypeError):
            cleaned.append(s)

    baseline["suppressions"] = cleaned
    baseline["updated_at"] = _utcnow_iso()
    return {"removed": removed, "removed_count": len(removed), "remaining": len(cleaned)}


def import_suppressions(baseline: dict, suppressions: list[dict], owner: str = "import") -> dict:
    """Bulk import suppressions from triage data or external source.

    Each suppression: {"fingerprint": str, "reason": str, "expires_at": str|None}
    """
    imported_count = 0
    skipped_count = 0

    for sup in suppressions:
        fp = sup.get("fingerprint", "")
        if not fp:
            skipped_count += 1
            continue
        reason = sup.get("reason", "Bulk imported")
        expires_at = sup.get("expires_at")

        existing_fps = {s.get("fingerprint") for s in baseline.get("suppressions", [])}
        if fp in existing_fps:
            skipped_count += 1
            continue

        baseline = add_suppression(baseline, fp, reason, owner, expires_at)
        imported_count += 1

    return {"imported_count": imported_count, "skipped_count": skipped_count}


def get_audit_trail(baseline: dict, limit: int = 50) -> list[dict]:
    """Get the suppression change history, most recent first."""
    trail = baseline.get("audit_trail", [])
    return list(reversed(trail[-limit:]))
