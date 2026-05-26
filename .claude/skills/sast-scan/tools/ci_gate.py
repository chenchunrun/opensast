import logging

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
    "note": 0,
    "warning": 2,
    "error": 3,
}


def evaluate_gate(
    findings: list[dict],
    fail_on: str = "high",
    baseline_enabled: bool = False,
    review_findings_blocking: bool = False,
) -> dict:
    threshold = SEVERITY_ORDER.get(fail_on, 3)
    blocking = []
    review_only = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for f in findings:
        sev = f.get("severity", "info").lower()
        sev_order = SEVERITY_ORDER.get(sev, 0)
        counts[sev] = counts.get(sev, 0) + 1

        if not f.get("is_new", True):
            continue
        if f.get("is_suppressed", False):
            continue
        triage_status = (f.get("triage") or {}).get("status")
        if triage_status == "needs-review":
            review_only.append(f)
            if not review_findings_blocking:
                continue
        if sev_order >= threshold:
            blocking.append(f)

    passed = len(blocking) == 0
    result = {
        "passed": passed,
        "fail_on": fail_on,
        "blocking_count": len(blocking),
        "review_findings_blocking": review_findings_blocking,
        "review_only_count": len(review_only),
        "blocking_by_severity": {},
        "total_findings": len(findings),
        "severity_counts": counts,
    }

    for f in blocking:
        sev = f.get("severity", "info").lower()
        result["blocking_by_severity"][sev] = result["blocking_by_severity"].get(sev, 0) + 1

    if not passed:
        logger.warning(
            "CI gate FAILED: %d findings at or above '%s' severity",
            len(blocking),
            fail_on,
        )
    else:
        logger.info("CI gate PASSED: no blocking findings at '%s' severity", fail_on)

    return result


def get_exit_code(gate_result: dict) -> int:
    return 1 if not gate_result.get("passed", True) else 0


def check_trend_gate(
    current_summary: dict,
    current_findings: list[dict],
    history_dir: str,
    config: dict | None = None,
) -> dict:
    trend_config = (config or {}).get("gate", {}).get("trend", {})
    if not trend_config.get("enabled", False):
        return {"enabled": False, "trend": "disabled", "is_blocking": False}

    from history import get_previous_scan, compare_scans
    previous = get_previous_scan(history_dir)
    if not previous:
        return {"enabled": True, "trend": "no_history", "is_blocking": False, "message": "No previous scan to compare"}

    comparison = compare_scans(current_summary, current_findings, previous)

    max_new_high = trend_config.get("max_new_high", None)
    max_regression_pct = trend_config.get("max_regression_pct", None)

    blocking_reasons: list[str] = []

    severity_delta = comparison.get("severity_delta", {})
    if max_new_high is not None and severity_delta.get("high", 0) > max_new_high:
        blocking_reasons.append(
            f"New high findings: {severity_delta['high']} (max allowed: {max_new_high})"
        )

    if max_regression_pct is not None:
        prev_total = previous.get("total_findings", 0)
        if prev_total > 0:
            pct_change = (comparison.get("total_delta", 0) / prev_total) * 100
            if pct_change > max_regression_pct:
                blocking_reasons.append(
                    f"Regression: +{pct_change:.1f}% (max allowed: {max_regression_pct}%)"
                )

    is_blocking = len(blocking_reasons) > 0
    comparison["enabled"] = True
    comparison["is_blocking"] = is_blocking
    comparison["blocking_reasons"] = blocking_reasons

    if is_blocking:
        logger.warning("Trend gate FAILED: %s", "; ".join(blocking_reasons))
    else:
        logger.info("Trend gate PASSED: direction=%s", comparison.get("direction"))

    return comparison
