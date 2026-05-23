"""Compute trend metrics from scan history."""

from datetime import datetime, timezone


def compute_trend_metrics(history: list[dict], days: int = 30) -> dict:
    if len(history) < 2:
        return {
            "direction": "unknown",
            "total_delta": 0,
            "severity_deltas": {},
            "daily_data": [],
            "message": "Insufficient history for trend analysis",
        }

    current = history[0]
    previous = history[-1]

    sev_levels = ("critical", "high", "medium", "low", "info")
    current_counts = current.get("severity_counts", {})
    previous_counts = previous.get("severity_counts", {})

    severity_deltas: dict[str, int] = {}
    for sev in sev_levels:
        severity_deltas[sev] = current_counts.get(sev, 0) - previous_counts.get(sev, 0)

    total_delta = current.get("total_findings", 0) - previous.get("total_findings", 0)

    current_fps = set(current.get("fingerprints", []))
    previous_fps = set(previous.get("fingerprints", []))

    new_count = len(current_fps - previous_fps)
    fixed_count = len(previous_fps - current_fps)

    mttr = _compute_mttr(history)

    daily_data = _build_daily_data(history, days)

    if total_delta < -1:
        direction = "improving"
    elif total_delta > 1:
        direction = "worsening"
    else:
        direction = "stable"

    return {
        "direction": direction,
        "total_delta": total_delta,
        "severity_deltas": severity_deltas,
        "new_findings": new_count,
        "fixed_findings": fixed_count,
        "mttr_days": mttr,
        "daily_data": daily_data,
        "period_days": days,
        "scans_compared": len(history),
    }


def _compute_mttr(history: list[dict]) -> float | None:
    if len(history) < 2:
        return None

    fixed_durations: list[float] = []
    sorted_history = sorted(history, key=lambda h: h.get("timestamp", ""))

    for i in range(1, len(sorted_history)):
        prev_fps = set(sorted_history[i - 1].get("fingerprints", []))
        curr_fps = set(sorted_history[i].get("fingerprints", []))
        fixed = prev_fps - curr_fps
        if not fixed:
            continue
        try:
            t1 = datetime.fromisoformat(sorted_history[i - 1]["timestamp"].replace("Z", "+00:00"))
            t2 = datetime.fromisoformat(sorted_history[i]["timestamp"].replace("Z", "+00:00"))
            days = (t2 - t1).total_seconds() / 86400
            if days > 0:
                fixed_durations.append(days)
        except (ValueError, KeyError):
            continue

    if not fixed_durations:
        return None

    return round(sum(fixed_durations) / len(fixed_durations), 1)


def _build_daily_data(history: list[dict], days: int) -> list[dict]:
    sorted_history = sorted(history, key=lambda h: h.get("timestamp", ""))
    return [
        {
            "date": h.get("timestamp", "")[:10],
            "total": h.get("total_findings", 0),
            "critical": h.get("severity_counts", {}).get("critical", 0),
            "high": h.get("severity_counts", {}).get("high", 0),
            "medium": h.get("severity_counts", {}).get("medium", 0),
            "low": h.get("severity_counts", {}).get("low", 0),
        }
        for h in sorted_history
    ]
