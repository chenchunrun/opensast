"""Convert tool-specific scan results into a unified finding format."""

import hashlib
from collections import defaultdict

SEVERITY_MAP_SEMGREP = {"error": "high", "warning": "medium", "note": "info", "none": "info"}
SEVERITY_MAP_CHECKOV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info", "unknown": "info"}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def compute_fingerprint(finding: dict) -> str:
    raw = f"{finding.get('file', '')}:{finding.get('start_line', 0)}:{finding.get('rule_id', '')}"
    return f"sha256:{hashlib.sha256(raw.encode()).hexdigest()}"


def _cwe_tags(tags: list[str]) -> list[str]:
    return [t for t in tags if t.startswith("CWE-")]


def _owasp_tags(tags: list[str]) -> list[str]:
    return [t for t in tags if "A0" in t or "OWASP" in t.upper()]


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
    finding["id"] = f"finding-{hashlib.sha256(finding['fingerprint'].encode()).hexdigest()[:16]}"
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
            rule_id = result.get("ruleId", "unknown")
            severity = SEVERITY_MAP_SEMGREP.get(result.get("level", "note").lower(), "info")
            rule_def = _find_rule(run, rule_id, result.get("ruleIndex"))
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


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for f in findings:
        groups[(f["file"], f["start_line"], tuple(sorted(f.get("cwe", []))))].append(f)

    deduped: list[dict] = []
    for group in groups.values():
        best = min(group, key=lambda f: SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else 99)
        tools = sorted(set(f["tool"] for f in group))
        merged = dict(best)
        merged["tool"] = tools[0] if len(tools) == 1 else ",".join(tools)
        deduped.append(merged)
    return deduped
