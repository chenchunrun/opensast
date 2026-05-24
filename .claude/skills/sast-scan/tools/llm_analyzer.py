"""Generate structured LLM analysis plans for deep security review.

Pre-extracts code context and builds focused analysis checklists for targets
that rule-based tools cannot fully evaluate. This module does NOT perform
analysis itself — it prepares data for Claude to analyze within the skill workflow.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone

logger = logging.getLogger("llm_analyzer")

EXCLUDE_DIRS = frozenset({
    "node_modules", ".next", ".git", "vendor", "dist", "build",
    "__pycache__", ".claude", "coverage", ".cache",
})

MAX_TARGETS_DEFAULT = 15
SNIPPET_CONTEXT_LINES = 15
MAX_FILE_LINES_FULL = 200

RISK_ANALYSIS_CHECKLISTS: dict[str, dict] = {
    "missing-authentication": {
        "analysis_steps": [
            "Check middleware.ts — does the matcher include this route path?",
            "Is this a public API (webhook, health check, registration)?",
            "Is this inside an (auth) or (public) route group?",
            "Does the returned data contain sensitive info (PII, tokens, keys)?",
            "Is there a custom auth header check we missed (e.g., x-api-key)?",
        ],
        "fp_signals": [
            "Route path contains /auth/, /login, /register, /verify",
            "Health check endpoint returning non-sensitive data",
            "Webhook handler with signature verification",
            "Public API documented as intentionally public",
        ],
        "cwe": ["CWE-306", "CWE-862"],
        "owasp": ["A01:2021-Broken Access Control"],
    },
    "idor-risk": {
        "analysis_steps": [
            "Trace the resource lookup: params.id → service call → DB query",
            "Does the where clause include userId or teamId?",
            "Is there an ownership check (isOwner, verifyOwnership)?",
            "Is the resource team-scoped with team membership verified?",
            "Could an attacker guess/enumerate resource IDs?",
        ],
        "fp_signals": [
            "Admin-only routes with separate authorization",
            "Public resources without access restrictions",
            "UUID primary keys (low collision, but not a guarantee)",
        ],
        "cwe": ["CWE-639", "CWE-862"],
        "owasp": ["A01:2021-Broken Access Control"],
    },
    "business-logic": {
        "analysis_steps": [
            "Check financial calculations — integer division, floating point errors",
            "Look for race conditions in state mutations (balance updates without transactions)",
            "Check authorization scope — can user perform actions outside their role?",
            "Look for missing business rule validation (max quantity, allowed transitions)",
            "Check for information disclosure in error messages",
            "Look for mass assignment — can user set fields they shouldn't?",
        ],
        "fp_signals": [
            "Read-only operations without financial impact",
            "Operations with proper transaction handling",
            "Routes with comprehensive server-side validation",
        ],
        "cwe": ["CWE-841", "CWE-367", "CWE-915"],
        "owasp": ["A04:2021-Insecure Design"],
    },
    "missing-csrf": {
        "analysis_steps": [
            "Check authentication method: Bearer token (CSRF-safe) vs cookies (CSRF-vulnerable)",
            "Look for SameSite cookie attributes",
            "Check if custom headers are required (X-Requested-With, etc.)",
            "Is this a JSON-only API that rejects form submissions?",
            "Does the CORS policy restrict origins?",
        ],
        "fp_signals": [
            "API uses Bearer token authorization (inherently CSRF-safe)",
            "SameSite=Strict cookie attribute",
            "Custom header required for all requests",
            "JSON-only content type with no form support",
        ],
        "cwe": ["CWE-352"],
        "owasp": ["A01:2021-Broken Access Control"],
    },
    "missing-input-validation": {
        "analysis_steps": [
            "What fields are accepted without validation?",
            "Do unvalidated fields flow to DB queries, command exec, or HTML output?",
            "Is there type confusion risk (string where number expected)?",
            "Could mass assignment occur (setting arbitrary model fields)?",
            "Is there file upload without type/size validation?",
        ],
        "fp_signals": [
            "Validation in a separate middleware or decorator",
            "Framework-level automatic validation",
            "Input only used in safe operations (logging, display)",
        ],
        "cwe": ["CWE-20", "CWE-915"],
        "owasp": ["A03:2021-Injection"],
    },
    "unsafe-type-assertion": {
        "analysis_steps": [
            "Does the asserted type match the expected schema?",
            "Does user input flow through this assertion unchecked?",
            "Is there runtime validation elsewhere in the call chain?",
            "Could type confusion lead to privilege escalation?",
        ],
        "fp_signals": [
            "Assertion on server-controlled data, not user input",
            "Runtime validation immediately after the assertion",
        ],
        "cwe": ["CWE-20"],
        "owasp": ["A03:2021-Injection"],
    },
    "sensitive-file": {
        "analysis_steps": [
            "Check for hardcoded API keys, passwords, tokens",
            "Verify crypto uses secure algorithms (not MD5, SHA1 for passwords)",
            "Check for missing encryption at rest",
            "Look for insecure random number generation",
            "Check for sensitive data in logs or error responses",
        ],
        "fp_signals": [
            "Values loaded from environment variables, not hardcoded",
            "Using established crypto libraries correctly",
            "Test fixtures with dummy data",
        ],
        "cwe": ["CWE-798", "CWE-327", "CWE-312"],
        "owasp": ["A02:2021-Cryptographic Failures", "A07:2021-Identification and Authentication Failures"],
    },
}

ROUTE_HANDLER_PATTERN = re.compile(
    r"export\s+async\s+function\s+(GET|POST|PUT|DELETE|PATCH)\s*\(",
)
EXPRESS_HANDLER_PATTERN = re.compile(
    r"(?:router|app)\.\s*(get|post|put|delete|patch)\s*\(\s*['\"]",
)
NEXT_ROUTE_EXPORT = re.compile(
    r"export\s+async\s+function\s+(GET|POST|PUT|DELETE|PATCH)",
)
IMPORT_PATTERN = re.compile(
    r"^(?:import\s|from\s|const\s+.*require\(|import\s*\()",
    re.MULTILINE,
)
ALIAS_PATTERN = re.compile(r"@/([\w./-]+)")


def generate_llm_analysis_plan(
    findings: list[dict],
    analysis_targets: dict,
    project_root: str,
    config: dict | None = None,
) -> dict:
    if config is None:
        config = {}

    llm_config = config.get("llm_analysis", {})
    max_targets = llm_config.get("max_targets", MAX_TARGETS_DEFAULT)

    raw_targets = analysis_targets.get("llm_analysis_targets", [])
    if not raw_targets:
        return _empty_plan(project_root, 0)

    prioritized = _prioritize_targets(raw_targets, findings, llm_config)
    selected = prioritized[:max_targets]

    skipped_covered = len(raw_targets) - len([t for t in prioritized if t.get("_score", 0) > 0])
    skipped_threshold = len(prioritized) - min(len(prioritized), max_targets)
    total_skipped = len(raw_targets) - len(selected)

    analysis_plan_targets: list[dict] = []
    for i, target in enumerate(selected):
        target_id = f"T-{i + 1:03d}"
        code_ctx = _extract_code_context(target, project_root)
        findings_for_file = _get_findings_for_file(findings, target.get("file", ""))
        checklist = _build_analysis_checklist(target, code_ctx, findings_for_file)

        analysis_plan_targets.append({
            "target_id": target_id,
            "file": _rel_path(target.get("file", ""), project_root),
            "priority": target.get("priority", "medium"),
            "priority_score": target.get("_score", 0),
            "risks": target.get("risks", []),
            "reason": target.get("reason", ""),
            "code_context": code_ctx,
            "analysis_checklist": checklist,
        })

    middleware_ctx = _extract_middleware_context(project_root)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_root": project_root,
        "total_targets_available": len(raw_targets),
        "targets_selected": len(analysis_plan_targets),
        "targets_skipped_reason": (
            f"{total_skipped} skipped: "
            f"{skipped_covered} covered by existing findings, "
            f"{skipped_threshold} below priority threshold"
        ),
        "analysis_targets": analysis_plan_targets,
        "middleware_context": middleware_ctx,
        "output_format": _output_format_schema(),
    }


def save_llm_analysis_plan(plan: dict, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "llm-analysis-plan.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(plan, fh, indent=2, default=str)
    return path


def _empty_plan(project_root: str, total: int) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_root": project_root,
        "total_targets_available": total,
        "targets_selected": 0,
        "targets_skipped_reason": "No targets available",
        "analysis_targets": [],
        "middleware_context": {},
        "output_format": _output_format_schema(),
    }


def _prioritize_targets(
    targets: list[dict],
    findings: list[dict],
    llm_config: dict,
) -> list[dict]:
    risk_priorities = llm_config.get("risk_priorities", {})
    coverage_deduction = llm_config.get("coverage_deduction", {
        "dataflow-analyzer": 2, "rbac-analyzer": 2,
        "auth-chain-analyzer": 1, "taint-tracker": 1,
    })

    findings_by_file: dict[str, list[dict]] = {}
    for f in findings:
        fp = f.get("file", "")
        if fp:
            findings_by_file.setdefault(fp, []).append(f)

    scored: list[dict] = []
    for t in targets:
        file_path = t.get("file", "")
        risks = t.get("risks", [])
        score = 0

        for risk in risks:
            rp = risk_priorities.get(risk, {})
            base = rp.get("base_score", 1)
            score += base

            fp_paths = rp.get("fp_paths", [])
            for fp_path in fp_paths:
                if fp_path in file_path.replace("\\", "/"):
                    score -= 3

        if len(risks) >= 3:
            score += 1

        for f in findings_by_file.get(file_path, []):
            tool = f.get("tool", "")
            deduction = coverage_deduction.get(tool, 0)
            if deduction and f.get("confidence") in ("high", "very-high"):
                score -= deduction

        entry = dict(t)
        entry["_score"] = score
        scored.append(entry)

    scored.sort(key=lambda t: t.get("_score", 0), reverse=True)
    return scored


def _extract_code_context(target: dict, project_root: str) -> dict:
    file_path = target.get("file", "")
    if not file_path:
        return {}

    if not os.path.isabs(file_path):
        file_path = os.path.join(project_root, file_path)

    if _is_sensitive_file(file_path):
        return {"error": "sensitive_file_skipped"}

    content = _read_file_safe(file_path)
    if not content:
        return {"error": "file_not_readable"}

    lines = content.splitlines()
    file_size = len(lines)

    imports = _extract_imports(content)
    handler_regions = _extract_handler_regions(content)
    called_services = _extract_called_services(content, file_path, project_root)

    context: dict = {
        "imports": imports,
        "handler_regions": handler_regions,
        "called_services": called_services,
        "file_size": file_size,
    }

    return context


def _extract_handler_regions(content: str) -> list[dict]:
    lines = content.splitlines()
    regions: list[dict] = []

    handler_starts: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        m = ROUTE_HANDLER_PATTERN.search(line)
        if m:
            handler_starts.append((i, m.group(1)))
        else:
            m2 = EXPRESS_HANDLER_PATTERN.search(line)
            if m2:
                handler_starts.append((i, m2.group(1).upper()))

    for idx, (start, method) in enumerate(handler_starts):
        end = handler_starts[idx + 1][0] - 1 if idx + 1 < len(handler_starts) else len(lines) - 1
        end = min(end, start + 80)
        region_content = "\n".join(lines[start:end + 1])
        regions.append({
            "method": method,
            "start_line": start + 1,
            "end_line": end + 1,
            "content": region_content,
        })

    if not regions and len(lines) <= MAX_FILE_LINES_FULL:
        regions.append({
            "method": "ALL",
            "start_line": 1,
            "end_line": len(lines),
            "content": content,
        })

    return regions


def _extract_imports(content: str) -> str:
    lines = content.splitlines()
    import_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        if IMPORT_PATTERN.match(stripped):
            import_lines.append(line)
        elif stripped and not stripped.startswith("//") and not stripped.startswith("/*"):
            break
    return "\n".join(import_lines)


def _extract_called_services(
    route_content: str, route_path: str, project_root: str,
) -> list[dict]:
    services: list[dict] = []
    aliases = ALIAS_PATTERN.findall(route_content)

    route_dir = os.path.dirname(route_path)

    for alias in set(aliases):
        rel_path = alias
        if not rel_path.endswith((".ts", ".tsx", ".js")):
            rel_path += ".ts"

        candidates = [
            os.path.join(project_root, "src", rel_path),
            os.path.join(project_root, rel_path),
            os.path.join(route_dir, rel_path),
        ]

        for candidate in candidates:
            if os.path.isfile(candidate):
                svc_content = _read_file_safe(candidate)
                if svc_content:
                    func_names = _extract_exported_functions(svc_content, route_content)
                    if func_names:
                        svc_lines = svc_content.splitlines()
                        services.append({
                            "file": _rel_path(candidate, project_root),
                            "functions": func_names,
                            "file_size": len(svc_lines),
                        })
                break

    return services[:5]


def _extract_exported_functions(svc_content: str, route_content: str) -> list[str]:
    func_pattern = re.compile(
        r"(?:export\s+(?:async\s+)?)?function\s+(\w+)|"
        r"(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s+)?\(",
    )
    all_funcs = [m.group(1) or m.group(2) for m in func_pattern.finditer(svc_content)]

    route_calls = set(re.findall(r"\b(\w+)\s*\(", route_content))
    return [f for f in all_funcs if f in route_calls]


def _build_analysis_checklist(
    target: dict,
    code_context: dict,
    findings_for_file: list[dict],
) -> dict:
    risks = set(target.get("risks", []))
    covered_risks: set[str] = set()
    existing_coverage: list[dict] = []

    for f in findings_for_file:
        tool = f.get("tool", "")
        confidence = f.get("confidence", "medium")
        rule = f.get("rule_id", "")
        f_risks = _risk_from_finding(f)
        for r in f_risks:
            if r in risks and confidence in ("high", "very-high"):
                covered_risks.add(r)
                existing_coverage.append({
                    "tool": tool, "rule": rule,
                    "confidence": confidence, "addresses": r,
                })

    risks_to_analyze = [r for r in risks if r not in covered_risks]

    handler_methods = set()
    for region in code_context.get("handler_regions", []):
        handler_methods.add(region.get("method", ""))

    write_methods = handler_methods & {"POST", "PUT", "DELETE", "PATCH"}
    has_db_access = any(
        kw in json.dumps(code_context)
        for kw in ["prisma", "findMany", "findUnique", "findFirst", "query", "execute"]
    )

    if write_methods and has_db_access and "business-logic" not in risks_to_analyze:
        risks_to_analyze.append("business-logic")

    analysis_steps: list[str] = []
    for risk in risks_to_analyze:
        checklist = RISK_ANALYSIS_CHECKLISTS.get(risk, {})
        for i, step in enumerate(checklist.get("analysis_steps", [])):
            analysis_steps.append(f"[{risk}] {step}")

    if not analysis_steps and not risks_to_analyze:
        return {
            "risks_to_analyze": [],
            "analysis_steps": [],
            "existing_coverage": existing_coverage,
            "skip": True,
        }

    return {
        "risks_to_analyze": risks_to_analyze,
        "analysis_steps": analysis_steps,
        "existing_coverage": existing_coverage,
        "skip": False,
    }


def _risk_from_finding(finding: dict) -> list[str]:
    rule = finding.get("rule_id", "").lower()
    cwe = finding.get("cwe", [])
    if "missing-auth" in rule or "no-auth" in rule:
        return ["missing-authentication"]
    if "idor" in rule or "missing-owner" in rule:
        return ["idor-risk"]
    if "csrf" in rule:
        return ["missing-csrf"]
    if "business" in rule or "logic" in rule:
        return ["business-logic"]
    if any("CWE-306" in c for c in cwe):
        return ["missing-authentication"]
    if any("CWE-862" in c for c in cwe):
        return ["missing-authentication", "idor-risk"]
    if any("CWE-639" in c for c in cwe):
        return ["idor-risk"]
    return []


def _get_findings_for_file(findings: list[dict], file_path: str) -> list[dict]:
    if not file_path:
        return []
    normalized = file_path.replace("\\", "/")
    return [
        f for f in findings
        if f.get("file", "").replace("\\", "/") in (normalized, os.path.basename(normalized))
    ]


def _extract_middleware_context(project_root: str) -> dict:
    candidates = [
        os.path.join(project_root, "middleware.ts"),
        os.path.join(project_root, "src", "middleware.ts"),
        os.path.join(project_root, "middleware.js"),
    ]

    for path in candidates:
        if os.path.isfile(path):
            content = _read_file_safe(path)
            if content:
                return _parse_middleware(content, path, project_root)

    return {"detected": False}


def _parse_middleware(content: str, file_path: str, project_root: str) -> dict:
    matcher_match = re.search(r"matcher\s*:\s*\[([^\]]+)\]", content)
    protected: list[str] = []
    excluded: list[str] = []

    if matcher_match:
        raw = matcher_match.group(1)
        patterns = re.findall(r"'([^']+)'", raw) + re.findall(r'"([^"]+)"', raw)
        for p in patterns:
            if p.startswith("!"):
                excluded.append(p[1:])
            else:
                protected.append(p)

    has_auth = bool(re.search(r"getServerSession|getToken|auth\(\)|requireAuth", content))

    return {
        "detected": True,
        "file": _rel_path(file_path, project_root),
        "protected_prefixes": protected,
        "excluded_prefixes": excluded,
        "has_auth_check": has_auth,
        "content_preview": content[:1000],
    }


SENSITIVE_EXTENSIONS = frozenset({".env", ".pem", ".key", ".p12", ".pfx", ".jks", ".p8"})
SENSITIVE_NAME_PARTS = {"secrets", "credentials", "private_key"}
MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024  # 1 MB


def _read_file_safe(file_path: str) -> str:
    try:
        if os.path.getsize(file_path) > MAX_FILE_SIZE_BYTES:
            return ""
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def _is_sensitive_file(file_path: str) -> bool:
    name = os.path.basename(file_path).lower()
    _, ext = os.path.splitext(name)
    if ext.lower() in SENSITIVE_EXTENSIONS or name.startswith(".env"):
        return True
    return any(part in name.lower().replace("-", "_").split("_") for part in SENSITIVE_NAME_PARTS)


def _rel_path(file_path: str, root: str) -> str:
    if os.path.isabs(file_path):
        try:
            return os.path.relpath(file_path, root)
        except ValueError:
            return file_path
    return file_path


def _output_format_schema() -> dict:
    return {
        "description": "Save findings to .claude/sast/results/llm-findings.json",
        "schema": {
            "tool": "llm-analyzer",
            "rule_id": "llm.<risk-type>",
            "title": "Short descriptive title",
            "severity": "critical|high|medium|low",
            "confidence": "high (confirmed exploitable) | medium (likely) | low (speculative)",
            "file": "relative path from project root",
            "start_line": 0,
            "end_line": 0,
            "message": "Explanation of why this is a vulnerability",
            "cwe": ["CWE-XXX"],
            "owasp": ["A0X:2021-..."],
            "evidence": {
                "source": "The vulnerable code snippet",
                "sink": "Where the vulnerability manifests",
                "dataflow": [{"file": "...", "line": 0, "label": "step description"}],
            },
            "recommendation": "Specific fix guidance with code example",
            "language": "typescript|python|...",
            "llm_analysis_notes": "Your reasoning about why this is/is not a real finding",
        },
    }
