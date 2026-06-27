"""Convert tool-specific scan results into a unified finding format."""

import hashlib
import os
from collections import defaultdict

SEVERITY_MAP_SEMGREP = {"error": "high", "warning": "medium", "note": "info", "none": "info"}
SEVERITY_MAP_CHECKOV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info", "unknown": "info"}
SEVERITY_MAP_BANDIT = {"high": "high", "medium": "medium", "low": "low"}
CONFIDENCE_MAP_BANDIT = {"high": "high", "medium": "medium", "low": "low"}
SEVERITY_MAP_GOSEC = {"high": "high", "medium": "medium", "low": "low", "warning": "medium", "error": "high", "note": "info"}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
VALID_LLM_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_LLM_CONFIDENCE = {"high", "medium", "low"}
VALID_LLM_TRIAGE = {"confirmed", "likely", "needs-review", "false-positive", "active"}


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _snippet_hash(snippet: str) -> str:
    if not snippet:
        return ""
    return hashlib.sha256(snippet.encode()).hexdigest()[:16]


def compute_fingerprint(finding: dict) -> str:
    file_path = _normalize_path(finding.get("file", ""))
    rule_id = finding.get("rule_id", "")
    cwe = tuple(sorted(finding.get("cwe", [])))
    snippet = finding.get("evidence", {}).get("source", "")
    snippet_h = _snippet_hash(snippet)
    if snippet_h:
        raw = f"{file_path}:{rule_id}:{cwe}:{snippet_h}"
    else:
        start_line = finding.get("start_line", 0)
        end_line = finding.get("end_line", start_line)
        raw = f"{file_path}:{start_line}:{end_line}:{rule_id}"
    return f"sha256:{hashlib.sha256(raw.encode()).hexdigest()}"


def compute_fingerprint_v1(finding: dict) -> str:
    raw = f"{finding.get('file', '')}:{finding.get('start_line', 0)}:{finding.get('rule_id', '')}"
    return f"sha256:{hashlib.sha256(raw.encode()).hexdigest()}"


def _cwe_tags(tags: list[str]) -> list[str]:
    result: list[str] = []
    for t in tags:
        if t.startswith("CWE-"):
            result.append(t)
        elif "cwe/cwe-" in t.lower():
            parts = t.rsplit("/", 1)
            if len(parts) == 2:
                cwe_id = parts[1].upper()
                if cwe_id.startswith("CWE-"):
                    result.append(cwe_id)
    return result


def _owasp_tags(tags: list[str]) -> list[str]:
    return [t for t in tags if ("A0" in t and ":" in t) or "OWASP" in t.upper()]


def _find_rule(run: dict, rule_id: str, rule_index: int | None) -> dict:
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    if rule_index is not None and rule_index < len(rules):
        return rules[rule_index]
    for r in rules:
        if r.get("id") == rule_id:
            return r
    return {}


def _build(
    tool: str, rule_id: str, title: str, severity: str, file_path: str,
    start_line: int, end_line: int, message: str, cwe: list[str] | None = None,
    owasp: list[str] | None = None, evidence: dict | None = None,
    recommendation: str = "", language: str = "", confidence: str = "medium",
) -> dict:
    finding = {
        "id": "", "tool": tool, "rule_id": rule_id, "title": title,
        "severity": severity, "confidence": confidence, "language": language,
        "file": file_path, "start_line": start_line, "end_line": end_line,
        "cwe": cwe or [], "owasp": owasp or [], "message": message,
        "evidence": evidence or {"source": "", "sink": "", "dataflow": []},
        "recommendation": recommendation, "fingerprint": "",
        "is_new": True, "is_suppressed": False, "suppression_reason": None,
    }
    finding["fingerprint"] = compute_fingerprint(finding)
    finding["fingerprint_v1"] = compute_fingerprint_v1(finding)
    finding["snippet_hash"] = _snippet_hash(
        finding.get("evidence", {}).get("source", "")
    )
    finding["id"] = f"F-{hashlib.sha256(finding['fingerprint'].encode()).hexdigest()[:12]}"
    return finding


def _phys(result: dict) -> tuple[dict, str, int, int]:
    locations = result.get("locations", [])
    if not locations:
        return {}, "", 0, 0
    phys = locations[0].get("physicalLocation", {})
    region = phys.get("region", {})
    start = region.get("startLine", 0)
    return phys, phys.get("artifactLocation", {}).get("uri", ""), start, region.get("endLine", start)


def normalize_semgrep(sarif_data: dict) -> list[dict]:
    findings: list[dict] = []
    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            # Honor SARIF suppressions: semgrep emits inline `# nosemgrep`
            # suppressions as result.suppressions (kind "inSource"). Without
            # this, nosemgrep annotations have no effect through the runner.
            if result.get("suppressions"):
                continue
            rule_id = result.get("ruleId", "unknown")
            rule_def = _find_rule(run, rule_id, result.get("ruleIndex"))
            rule_level = rule_def.get("defaultConfiguration", {}).get("level", "note")
            severity = SEVERITY_MAP_SEMGREP.get(
                (result.get("level") or rule_level).lower(), "info",
            )
            tags = rule_def.get("properties", {}).get("tags", [])
            short_desc = rule_def.get("shortDescription", {}).get("text", rule_id)
            props = rule_def.get("properties", {})

            phys, file_uri, start_line, end_line = _phys(result)
            if not phys:
                continue
            snippet = phys.get("region", {}).get("snippet", {}).get("text", "")
            evidence = {"source": snippet, "sink": "", "dataflow": []}
            for flow in result.get("codeFlows", []):
                for tf in flow.get("threadFlows", []):
                    for loc in tf.get("locations", []):
                        step = loc.get("location", {}).get("physicalLocation", {})
                        evidence["dataflow"].append({
                            "file": step.get("artifactLocation", {}).get("uri", ""),
                            "line": step.get("region", {}).get("startLine", 0),
                            "snippet": step.get("region", {}).get("snippet", {}).get("text", ""),
                        })

            findings.append(_build(
                tool="semgrep", rule_id=rule_id, title=short_desc, severity=severity,
                file_path=file_uri, start_line=start_line, end_line=end_line,
                message=result.get("message", {}).get("text", short_desc),
                cwe=_cwe_tags(tags), owasp=_owasp_tags(tags), evidence=evidence,
                recommendation=rule_def.get("help", {}).get("text", ""),
                language=props.get("language", ""), confidence=props.get("precision", "medium"),
            ))
    return findings


def normalize_gitleaks(sarif_data: dict) -> list[dict]:
    findings: list[dict] = []
    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "generic-api-key")
            severity = "critical" if result.get("level", "error").lower() == "error" else "high"
            phys, file_uri, start_line, end_line = _phys(result)
            if not phys:
                continue
            snippet = phys.get("region", {}).get("snippet", {}).get("text", "")
            findings.append(_build(
                tool="gitleaks", rule_id=rule_id, title=f"Secret detected: {rule_id}",
                severity=severity, file_path=file_uri, start_line=start_line, end_line=end_line,
                message=result.get("message", {}).get("text", rule_id),
                evidence={"source": snippet, "sink": "", "dataflow": []},
                recommendation="Rotate the exposed secret immediately and use a secret manager.",
                confidence="high",
            ))
    return findings


def normalize_checkov(sarif_data: dict) -> list[dict]:
    findings: list[dict] = []
    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            level = result.get("level", "note").lower()
            rule_def = _find_rule(run, rule_id, result.get("ruleIndex"))
            props = rule_def.get("properties", {})

            sev_str = props.get("security-severity", "")
            if sev_str:
                sv = float(sev_str)
                severity = "critical" if sv >= 9 else "high" if sv >= 7 else "medium" if sv >= 4 else "low" if sv >= 1 else "info"
            else:
                severity = SEVERITY_MAP_CHECKOV.get(level, "info")

            phys, file_uri, start_line, end_line = _phys(result)
            if not phys:
                continue
            tags = props.get("tags", [])
            short_desc = rule_def.get("shortDescription", {}).get("text", rule_id)

            findings.append(_build(
                tool="checkov", rule_id=rule_id, title=short_desc, severity=severity,
                file_path=file_uri, start_line=start_line, end_line=end_line,
                message=result.get("message", {}).get("text", short_desc),
                cwe=_cwe_tags(tags), owasp=_owasp_tags(tags),
                recommendation=rule_def.get("help", {}).get("text", ""), confidence="medium",
            ))
    return findings


def _severity_from_score(score_str: str) -> str:
    try:
        sv = float(score_str)
    except (ValueError, TypeError):
        return "info"
    if sv >= 9:
        return "critical"
    if sv >= 7:
        return "high"
    if sv >= 4:
        return "medium"
    if sv >= 1:
        return "low"
    return "info"


def normalize_bandit(sarif_data: dict) -> list[dict]:
    findings: list[dict] = []
    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule_def = _find_rule(run, rule_id, result.get("ruleIndex"))
            props = rule_def.get("properties", {})

            raw_sev = props.get("issue_severity", "").lower()
            severity = SEVERITY_MAP_BANDIT.get(raw_sev, "info")
            raw_conf = props.get("issue_confidence", "medium").lower()
            confidence = CONFIDENCE_MAP_BANDIT.get(raw_conf, "medium")
            tags = props.get("tags", [])
            short_desc = rule_def.get("shortDescription", {}).get("text", rule_id)

            phys, file_uri, start_line, end_line = _phys(result)
            if not phys:
                continue
            snippet = phys.get("region", {}).get("snippet", {}).get("text", "")

            findings.append(_build(
                tool="bandit", rule_id=rule_id, title=short_desc, severity=severity,
                file_path=file_uri, start_line=start_line, end_line=end_line,
                message=result.get("message", {}).get("text", short_desc),
                cwe=_cwe_tags(tags), owasp=_owasp_tags(tags),
                evidence={"source": snippet, "sink": "", "dataflow": []},
                recommendation=rule_def.get("help", {}).get("text", ""),
                confidence=confidence,
            ))
    return findings


def normalize_gosec(sarif_data: dict) -> list[dict]:
    findings: list[dict] = []
    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule_def = _find_rule(run, rule_id, result.get("ruleIndex"))
            props = rule_def.get("properties", {})

            raw_sev = props.get("issue_severity", "")
            if raw_sev:
                severity = SEVERITY_MAP_GOSEC.get(raw_sev.lower(), "info")
            else:
                severity = SEVERITY_MAP_GOSEC.get(result.get("level", "note").lower(), "info")
            tags = props.get("tags", [])
            short_desc = rule_def.get("shortDescription", {}).get("text", rule_id)

            phys, file_uri, start_line, end_line = _phys(result)
            if not phys:
                continue
            snippet = phys.get("region", {}).get("snippet", {}).get("text", "")

            findings.append(_build(
                tool="gosec", rule_id=rule_id, title=short_desc, severity=severity,
                file_path=file_uri, start_line=start_line, end_line=end_line,
                message=result.get("message", {}).get("text", short_desc),
                cwe=_cwe_tags(tags), owasp=_owasp_tags(tags),
                evidence={"source": snippet, "sink": "", "dataflow": []},
                recommendation=rule_def.get("help", {}).get("text", ""),
                confidence="medium",
            ))
    return findings


def normalize_codeql(sarif_data: dict) -> list[dict]:
    findings: list[dict] = []
    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule_def = _find_rule(run, rule_id, result.get("ruleIndex"))
            props = rule_def.get("properties", {})

            sev_str = props.get("security-severity", "")
            if sev_str:
                severity = _severity_from_score(sev_str)
            else:
                codeql_level = result.get("level") or rule_def.get("defaultConfiguration", {}).get("level", "note")
                severity = SEVERITY_MAP_SEMGREP.get(codeql_level.lower(), "info")
            tags = props.get("tags", [])
            short_desc = rule_def.get("shortDescription", {}).get("text", rule_id)

            phys, file_uri, start_line, end_line = _phys(result)
            if not phys:
                continue
            snippet = phys.get("region", {}).get("snippet", {}).get("text", "")

            dataflow: list[dict] = []
            for flow in result.get("codeFlows", []):
                for tf in flow.get("threadFlows", []):
                    for loc in tf.get("locations", []):
                        step = loc.get("location", {}).get("physicalLocation", {})
                        msg = loc.get("location", {}).get("message", {}).get("text", "")
                        dataflow.append({
                            "file": step.get("artifactLocation", {}).get("uri", ""),
                            "line": step.get("region", {}).get("startLine", 0),
                            "snippet": step.get("region", {}).get("snippet", {}).get("text", ""),
                            "message": msg,
                        })

            findings.append(_build(
                tool="codeql", rule_id=rule_id, title=short_desc, severity=severity,
                file_path=file_uri, start_line=start_line, end_line=end_line,
                message=result.get("message", {}).get("text", short_desc),
                cwe=_cwe_tags(tags), owasp=_owasp_tags(tags),
                evidence={"source": snippet, "sink": "", "dataflow": dataflow},
                recommendation=rule_def.get("help", {}).get("text", ""),
                confidence="high" if sev_str else "medium",
            ))
    return findings


def validate_llm_findings(data: dict | list[dict]) -> tuple[bool, list[str]]:
    # Lazy import to avoid circular dependency (llm_findings_schema imports normalize_findings helpers)
    try:
        from llm_findings_schema import validate_llm_findings_envelope
    except ImportError as exc:
        return False, [f"Failed to import llm_findings_schema: {exc}"]

    return validate_llm_findings_envelope(data)


def normalize_llm_findings(data: dict | list[dict]) -> list[dict]:
    try:
        from llm_findings_schema import extract_importable_findings
    except ImportError as exc:
        return []

    is_valid, _ = validate_llm_findings(data)
    if not is_valid:
        return []

    raw_findings = extract_importable_findings(data)

    findings: list[dict] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            continue

        finding = _build(
            tool=item.get("tool", "llm-analyzer"),
            rule_id=item.get("rule_id", "llm.unknown"),
            title=item.get("title", item.get("rule_id", "LLM finding")),
            severity=item.get("severity", "medium"),
            file_path=item.get("file", ""),
            start_line=item.get("start_line", 0),
            end_line=item.get("end_line", item.get("start_line", 0)),
            message=item.get("message", item.get("title", "LLM finding")),
            cwe=item.get("cwe", []),
            owasp=item.get("owasp", []),
            evidence=item.get("evidence", {"source": "", "sink": "", "dataflow": []}),
            recommendation=item.get("recommendation", ""),
            language=item.get("language", ""),
            confidence=item.get("confidence", "medium"),
        )

        for key in (
            "triage",
            "analysis_enrichment",
            "llm_analysis_notes",
            "confidence_score",
            "reachability",
            "context",
        ):
            if key in item:
                finding[key] = item[key]

        for key in ("is_new", "is_suppressed", "suppression_reason"):
            if key in item:
                finding[key] = item[key]

        findings.append(finding)

    return findings


def normalize_eslint_json(data: list | dict) -> list[dict]:
    findings: list[dict] = []
    files = data if isinstance(data, list) else data.get("results", [])
    for entry in files:
        file_path = entry.get("filePath", "")
        for msg in entry.get("messages", []):
            rule_id = msg.get("ruleId", "eslint")
            severity = "high" if msg.get("severity") == 2 else "medium"
            findings.append(_build(
                tool="eslint", rule_id=rule_id, title=rule_id,
                severity=severity, file_path=file_path,
                start_line=msg.get("line", 0), end_line=msg.get("endLine", msg.get("line", 0)),
                message=msg.get("message", rule_id),
                confidence="medium",
            ))
    return findings


def normalize_brakeman_json(data: dict) -> list[dict]:
    findings: list[dict] = []
    for warn in data.get("warnings", []):
        sev = {"High": "high", "Medium": "medium", "Weak": "low"}.get(warn.get("confidence", ""), "medium")
        findings.append(_build(
            tool="brakeman", rule_id=warn.get("warning_type", "brakeman"),
            title=warn.get("warning_type", "brakeman"),
            severity=sev, file_path=warn.get("file", ""),
            start_line=warn.get("line", 0), end_line=warn.get("line", 0),
            message=warn.get("message", warn.get("warning_type", "")),
            cwe=[f"CWE-{warn['cwe_id']}"] if warn.get("cwe_id") else [],
            confidence="medium",
        ))
    return findings


def normalize_cargo_audit_json(data: dict) -> list[dict]:
    findings: list[dict] = []
    for vuln in data.get("vulnerabilities", {}).get("list", []):
        advisory = vuln.get("advisory", {})
        findings.append(_build(
            tool="cargo-audit", rule_id=advisory.get("id", "cargo-audit"),
            title=advisory.get("title", advisory.get("id", "cargo-audit")),
            severity="high", file_path=vuln.get("package", {}).get("name", "Cargo.toml"),
            start_line=0, end_line=0,
            message=advisory.get("description", advisory.get("title", "")),
            cwe=[f"CWE-{c}" for c in advisory.get("categories", []) if str(c).isdigit()],
            confidence="high",
        ))
    return findings


def normalize_phpstan_json(data: dict) -> list[dict]:
    findings: list[dict] = []
    files = data.get("files", {})
    if not isinstance(files, dict):
        return findings

    security_identifiers = (
        "security.",
        "unsafe",
        "eval",
        "shell",
        "sql",
        "xss",
        "path",
    )

    for file_path, payload in files.items():
        if not isinstance(payload, dict):
            continue
        # Normalize path to prevent traversal and ensure relative paths
        safe_path = os.path.normpath(file_path)
        if safe_path.startswith("..") or os.path.isabs(safe_path):
            safe_path = safe_path.lstrip("/")
        # Strip leading ../ components that normpath preserves on relative paths
        while safe_path.startswith("../") or safe_path.startswith("..\\"):
            safe_path = safe_path[3:]
        if safe_path.startswith(".."):
            safe_path = safe_path[2:]  # bare .. without trailing slash
        for msg in payload.get("messages", []):
            if not isinstance(msg, dict):
                continue
            identifier = str(msg.get("identifier", "phpstan"))
            message = msg.get("message", identifier)
            severity = "medium"
            lower_id = identifier.lower()
            if any(token in lower_id for token in security_identifiers):
                severity = "high"
            if msg.get("ignorable") and "security." not in lower_id:
                severity = "low"
            findings.append(_build(
                tool="phpstan",
                rule_id=identifier,
                title=identifier,
                severity=severity,
                file_path=safe_path,
                start_line=msg.get("line", 0),
                end_line=msg.get("line", 0),
                message=message,
                confidence="medium",
            ))
    return findings


def normalize_swiftlint_json(data: list) -> list[dict]:
    findings: list[dict] = []
    sev_map = {"error": "high", "warning": "medium", "weak": "low"}
    for item in data:
        rule_id = item.get("rule_id", item.get("rule_identifier", "swiftlint"))
        findings.append(_build(
            tool="swiftlint", rule_id=rule_id, title=rule_id,
            severity=sev_map.get(item.get("severity", "warning"), "medium"),
            file_path=item.get("file", ""),
            start_line=item.get("line", 0), end_line=item.get("line", 0),
            message=item.get("reason", rule_id),
            confidence="medium",
        ))
    return findings


NORMALIZERS: dict[str, callable] = {
    "semgrep": normalize_semgrep,
    "gitleaks": normalize_gitleaks,
    "checkov": normalize_checkov,
    "bandit": normalize_bandit,
    "gosec": normalize_gosec,
    "codeql": normalize_codeql,
    "cppcheck": normalize_semgrep,
    "llm-analyzer": normalize_llm_findings,
}

JSON_NORMALIZERS: dict[str, callable] = {
    "eslint": normalize_eslint_json,
    "brakeman": normalize_brakeman_json,
    "cargo-audit": normalize_cargo_audit_json,
    "phpstan": normalize_phpstan_json,
    "swiftlint": normalize_swiftlint_json,
}


def _severity_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return len(SEVERITY_ORDER)


def _confidence_rank(conf: str) -> int:
    order = ["high", "medium", "low"]
    try:
        return order.index(conf)
    except ValueError:
        return len(order)


def _dedup_key(finding: dict) -> tuple:
    return (
        _normalize_path(finding.get("file", "")),
        finding.get("start_line", 0),
        finding.get("end_line", 0),
        finding.get("rule_id", ""),
        tuple(sorted(finding.get("cwe", []))),
    )


def _fuzzy_dedup_key(finding: dict) -> tuple:
    snippet_h = finding.get("snippet_hash", "") or _snippet_hash(
        finding.get("evidence", {}).get("source", "")
    )
    return (
        _normalize_path(finding.get("file", "")),
        tuple(sorted(finding.get("cwe", []))),
        snippet_h,
    )


def _merge_group(group: list[dict]) -> dict:
    best_sev = min(group, key=lambda f: _severity_rank(f["severity"]))
    best_conf = min(group, key=lambda f: _confidence_rank(f.get("confidence", "medium")))
    best_evidence = max(group, key=lambda f: len(f.get("evidence", {}).get("dataflow", [])))

    all_tools = sorted(set(f["tool"] for f in group))
    all_rule_ids = sorted(set(f["rule_id"] for f in group))
    all_messages = sorted(set(f.get("message", "") for f in group if f.get("message")))

    merged = dict(best_sev)
    merged["tool"] = all_tools[0] if len(all_tools) == 1 else ",".join(all_tools)
    merged["tools"] = all_tools
    merged["rule_ids"] = all_rule_ids
    merged["confidence"] = best_conf.get("confidence", "medium")
    merged["evidence"] = best_evidence.get("evidence", {"source": "", "sink": "", "dataflow": []})
    if len(all_messages) > 1:
        merged["message"] = all_messages[0]
    return merged


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    if not findings:
        return []

    exact_groups: dict[tuple, list[dict]] = defaultdict(list)
    for f in findings:
        exact_groups[_dedup_key(f)].append(f)

    merged_by_exact: list[dict] = []
    for group in exact_groups.values():
        if len(group) == 1:
            f = dict(group[0])
            f["tools"] = [f["tool"]]
            f["rule_ids"] = [f["rule_id"]]
            merged_by_exact.append(f)
        else:
            merged_by_exact.append(_merge_group(group))

    fuzzy_groups: dict[tuple, list[dict]] = defaultdict(list)
    for f in merged_by_exact:
        fuzzy_groups[_fuzzy_dedup_key(f)].append(f)

    deduped: list[dict] = []
    for group in fuzzy_groups.values():
        if len(group) == 1:
            deduped.append(group[0])
        else:
            deduped.append(_merge_group(group))

    return deduped


__all__ = [
    "_build",
    "compute_fingerprint",
    "deduplicate_findings",
    "normalize_semgrep",
    "validate_llm_findings",
    "normalize_llm_findings",
    "NORMALIZERS",
    "SEVERITY_ORDER",
]
