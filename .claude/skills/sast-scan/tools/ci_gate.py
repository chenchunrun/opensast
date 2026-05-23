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
) -> dict:
    threshold = SEVERITY_ORDER.get(fail_on, 3)
    blocking = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for f in findings:
        sev = f.get("severity", "info").lower()
        sev_order = SEVERITY_ORDER.get(sev, 0)
        counts[sev] = counts.get(sev, 0) + 1

        if not f.get("is_new", True):
            continue
        if f.get("is_suppressed", False):
            continue
        if sev_order >= threshold:
            blocking.append(f)

    passed = len(blocking) == 0
    result = {
        "passed": passed,
        "fail_on": fail_on,
        "blocking_count": len(blocking),
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
