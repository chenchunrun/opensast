"""Versioned evidence and verification contract, independent of scanner confidence."""

from __future__ import annotations

from copy import deepcopy
import re

SCHEMA_VERSION = "1.0"
STATUSES = {"needs-review", "confirmed", "false-positive", "fixed", "unavailable"}
METHODS = {"unreviewed", "manual-review", "static-analysis", "runtime-test"}


def validate_verification(value: object) -> list[str]:
    if not isinstance(value, dict):
        return ["verification must be an object"]
    errors = []
    if value.get("schema_version", SCHEMA_VERSION) != SCHEMA_VERSION:
        errors.append("unsupported verification.schema_version")
    status = value.get("status")
    method = value.get("method", "unreviewed")
    if not isinstance(status, str) or status not in STATUSES:
        errors.append("invalid verification.status")
        status = "invalid"
    if not isinstance(method, str) or method not in METHODS:
        errors.append("invalid verification.method")
        method = "invalid"
    rationale = value.get("rationale", "")
    if not isinstance(rationale, str) or (status != "needs-review" and not rationale.strip()):
        errors.append("verification.rationale is required for a review decision")
    for key in ("reviewer", "verified_at"):
        if key in value and value[key] is not None and not isinstance(value[key], str):
            errors.append(f"verification.{key} must be a string or null")
    artifacts = value.get("artifacts", [])
    if not isinstance(artifacts, list):
        errors.append("verification.artifacts must be a list")
    else:
        for a in artifacts:
            if not isinstance(a, dict) or not isinstance(a.get("kind"), str) or a["kind"] not in {"source", "test", "log", "scan"}:
                errors.append("verification artifact requires a valid kind")
                continue
            if not isinstance(a.get("path"), str) or not a["path"].strip():
                errors.append("verification artifact requires a path")
            if "sha256" in a and (not isinstance(a["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", a["sha256"])):
                errors.append("verification artifact sha256 must be 64 lowercase hex characters")
    proof_kind = "scan" if method == "static-analysis" else "test"
    proof = isinstance(artifacts, list) and any(
        isinstance(a, dict) and a.get("kind") == proof_kind
        and isinstance(a.get("sha256"), str) and re.fullmatch(r"[a-f0-9]{64}", a["sha256"])
        for a in artifacts)
    if status == "fixed" and (not proof or method not in {"static-analysis", "runtime-test"}):
        errors.append("fixed verification requires a hashed scan/test artifact matching its verification method")
    if status in {"confirmed", "false-positive"} and method == "unreviewed":
        errors.append("a reviewed decision cannot use the unreviewed method")
    if "reviews" in value:
        reviews = value["reviews"]
        if not isinstance(reviews, list):
            errors.append("verification.reviews must be a list")
        else:
            for review in reviews:
                if isinstance(review, dict) and "reviews" in review:
                    errors.append("verification reviews cannot be nested")
                else:
                    errors.extend(validate_verification(review))
    return errors


def normalize_verification(finding: dict) -> dict:
    explicit = finding.get("verification")
    if explicit is not None:
        errors = validate_verification(explicit)
        if errors:
            raise ValueError("; ".join(errors))
        result = deepcopy(explicit)
        result.setdefault("schema_version", SCHEMA_VERSION)
        result.setdefault("method", "unreviewed")
        result.setdefault("rationale", "")
        result.setdefault("artifacts", [])
        return result
    triage = finding.get("triage") or {}
    status = triage.get("status")
    reviewed = status in {"confirmed", "false-positive"}
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status if reviewed else "needs-review",
        "method": "manual-review" if reviewed else "unreviewed",
        "rationale": (triage.get("rationale") or "Imported legacy review decision; supporting evidence may be incomplete") if reviewed else "",
        "artifacts": [],
    }


def review_status(finding: dict) -> str | None:
    """Resolve review authority while keeping default rule signals actionable."""
    if finding.get("verification") is None and not finding.get("triage"):
        nested = (finding.get("analysis_enrichment") or {}).get("triage") or {}
        if nested.get("status"):
            return nested["status"]
    verification = normalize_verification(finding)
    if verification["status"] != "needs-review" or verification["method"] != "unreviewed":
        return verification["status"]
    triage = finding.get("triage") or (finding.get("analysis_enrichment") or {}).get("triage") or {}
    status = triage.get("status")
    # An explicit default state cannot revive a stale dismissal or confirmation.
    return status if status in {"needs-review", "likely"} else None


def assess_evidence(finding: dict) -> dict:
    """Assess recorded source context; never assert that imported artifacts ran."""
    evidence = finding.get("evidence") or {}
    gaps = [key for key in ("source", "sink", "attacker_control", "preconditions") if not evidence.get(key)]
    has_location = bool(finding.get("file")) and isinstance(finding.get("start_line"), int) and finding["start_line"] > 0
    if not has_location:
        gaps.append("code_location")
    steps = evidence.get("dataflow") or []
    located = [s for s in steps if isinstance(s, dict) and isinstance(s.get("file"), str) and s["file"]
               and type(s.get("line")) is int and s["line"] > 0]
    level = "static-path" if len(located) >= 2 else ("source" if has_location or evidence.get("source") or evidence.get("sink") else "none")
    return {"schema_version": SCHEMA_VERSION, "level": level, "gaps": gaps,
            "located_dataflow_steps": len(located), "runtime_proven": False}


def enrich_finding(finding: dict) -> dict:
    result = deepcopy(finding)
    result["verification"] = normalize_verification(finding)
    result["evidence_assessment"] = assess_evidence(finding)
    return result


def summarize_verification(findings: list[dict]) -> dict:
    counts = {s: 0 for s in sorted(STATUSES)}
    with_gaps = 0
    for finding in findings:
        counts[normalize_verification(finding)["status"]] += 1
        with_gaps += bool(assess_evidence(finding)["gaps"])
    return {"schema_version": SCHEMA_VERSION, "by_status": counts, "findings_with_evidence_gaps": with_gaps}


def merge_verification(findings: list[dict]) -> dict:
    reviews = []
    for finding in findings:
        review = normalize_verification(finding)
        for entry in review.get("reviews", []) + [review]:
            entry = {k: deepcopy(v) for k, v in entry.items() if k != "reviews"}
            if entry not in reviews:
                reviews.append(entry)
    decisions = [r for r in reviews if r["status"] != "needs-review"]
    if len({r["status"] for r in decisions}) > 1:
        return {"schema_version": SCHEMA_VERSION, "status": "needs-review", "method": "manual-review",
                "rationale": "Conflicting review decisions require reconciliation", "artifacts": [], "reviews": reviews}
    result = deepcopy(decisions[0] if decisions else reviews[0])
    if len(reviews) > 1:
        result["reviews"] = reviews
    return result
