"""Schema helpers for llm-findings.json and llm-analysis-plan.json envelopes."""

from __future__ import annotations

LLM_FINDINGS_SCHEMA_VERSION = "1.0"
LLM_ANALYSIS_PLAN_SCHEMA_VERSION = "1.0"

VALID_LLM_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_LLM_CONFIDENCE = {"high", "medium", "low"}
VALID_LLM_TRIAGE = {"confirmed", "likely", "needs-review", "false-positive", "active"}

REQUIRED_FINDING_FIELDS = ("rule_id", "title", "severity", "file", "message")


def validate_finding_item(item: dict, prefix: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(item, dict):
        return [f"{prefix}: entry must be an object"]

    for key in REQUIRED_FINDING_FIELDS:
        if not item.get(key):
            errors.append(f"{prefix}: missing required field '{key}'")

    severity = str(item.get("severity", "")).lower()
    if severity and severity not in VALID_LLM_SEVERITIES:
        errors.append(f"{prefix}: invalid severity '{item.get('severity')}'")

    confidence = str(item.get("confidence", "medium")).lower()
    if confidence and confidence not in VALID_LLM_CONFIDENCE:
        errors.append(f"{prefix}: invalid confidence '{item.get('confidence')}'")

    triage = item.get("triage")
    if triage is not None:
        if not isinstance(triage, dict):
            errors.append(f"{prefix}: triage must be an object")
        else:
            status = triage.get("status")
            if status and status not in VALID_LLM_TRIAGE:
                errors.append(f"{prefix}: invalid triage.status '{status}'")

    evidence = item.get("evidence")
    if evidence is not None:
        if not isinstance(evidence, dict):
            errors.append(f"{prefix}: evidence must be an object")
        else:
            dataflow = evidence.get("dataflow", [])
            if dataflow is not None and not isinstance(dataflow, list):
                errors.append(f"{prefix}: evidence.dataflow must be a list")

    for key in ("start_line", "end_line"):
        if key in item and item[key] is not None and not isinstance(item[key], int):
            errors.append(f"{prefix}: '{key}' must be an integer")

    return errors


def validate_dismissed_target(item: dict, prefix: str) -> list[str]:
    if not isinstance(item, dict):
        return [f"{prefix}: dismissed target must be an object"]
    errors: list[str] = []
    if not item.get("target_id"):
        errors.append(f"{prefix}: missing target_id")
    if not item.get("reason"):
        errors.append(f"{prefix}: missing reason")
    return errors


def validate_confirmed_finding(item: dict, prefix: str) -> list[str]:
    if not isinstance(item, dict):
        return [f"{prefix}: confirmed finding must be an object"]
    errors: list[str] = []
    if not item.get("target_id"):
        errors.append(f"{prefix}: missing target_id")
    finding = item.get("finding")
    if finding is None:
        errors.append(f"{prefix}: missing finding object")
    elif isinstance(finding, dict):
        errors.extend(validate_finding_item(finding, f"{prefix}.finding"))
    else:
        errors.append(f"{prefix}: finding must be an object")
    return errors


def validate_llm_findings_envelope(data: dict | list[dict]) -> tuple[bool, list[str]]:
    if isinstance(data, list):
        errors: list[str] = []
        for idx, item in enumerate(data):
            errors.extend(validate_finding_item(item, f"finding[{idx}]"))
        return len(errors) == 0, errors

    if not isinstance(data, dict):
        return False, ["LLM findings payload must be a list or an object with a 'findings' key"]

    errors = []
    version = data.get("schema_version")
    if version is not None and version != LLM_FINDINGS_SCHEMA_VERSION:
        errors.append(
            f"unsupported schema_version '{version}' (expected {LLM_FINDINGS_SCHEMA_VERSION})"
        )

    raw_findings = data.get("findings", [])
    if not isinstance(raw_findings, list):
        errors.append("LLM findings 'findings' field must be a list")
        raw_findings = []

    for idx, item in enumerate(raw_findings):
        errors.extend(validate_finding_item(item, f"findings[{idx}]"))

    dismissed = data.get("dismissed_targets", [])
    if dismissed is not None:
        if not isinstance(dismissed, list):
            errors.append("dismissed_targets must be a list")
        else:
            for idx, item in enumerate(dismissed):
                errors.extend(validate_dismissed_target(item, f"dismissed_targets[{idx}]"))

    confirmed = data.get("confirmed_findings", [])
    if confirmed is not None:
        if not isinstance(confirmed, list):
            errors.append("confirmed_findings must be a list")
        else:
            for idx, item in enumerate(confirmed):
                errors.extend(validate_confirmed_finding(item, f"confirmed_findings[{idx}]"))

    for key in ("llm_analysis_complete", "agent_review_complete"):
        if key in data and not isinstance(data[key], bool):
            errors.append(f"{key} must be a boolean")

    return len(errors) == 0, errors


def validate_agent_findings_envelope(data: dict) -> tuple[bool, list[str]]:
    """Validate agent-findings.json (alias of llm-findings with agent fields required)."""
    valid, errors = validate_llm_findings_envelope(data)
    if not isinstance(data, dict):
        return valid, errors
    if not data.get("agent_review_complete"):
        errors.append("agent_review_complete must be true for agent-findings.json")
    return len(errors) == 0, errors


def extract_importable_findings(data: dict | list[dict]) -> list[dict]:
    """Return normalized finding dicts ready for normalize_llm_findings."""
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]

    if not isinstance(data, dict):
        return []

    findings = [item for item in data.get("findings", []) if isinstance(item, dict)]

    for entry in data.get("confirmed_findings", []) or []:
        if not isinstance(entry, dict):
            continue
        finding = entry.get("finding")
        if not isinstance(finding, dict):
            continue
        enriched = dict(finding)
        enriched.setdefault("tool", "llm-analyzer")
        enriched.setdefault("analysis_enrichment", {})
        if isinstance(enriched["analysis_enrichment"], dict):
            enriched["analysis_enrichment"].setdefault("origin", "llm-discovery")
        triage = enriched.get("triage")
        if isinstance(triage, dict):
            triage.setdefault("status", "confirmed")
        else:
            enriched["triage"] = {"status": "confirmed", "rationale": entry.get("rationale", "confirmed in Phase A")}
        findings.append(enriched)

    return findings
