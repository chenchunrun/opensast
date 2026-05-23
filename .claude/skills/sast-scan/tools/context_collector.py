"""Collect code context for LLM-augmented security analysis."""

import json
import logging
import os
import re

logger = logging.getLogger(__name__)

AUTH_PATTERNS = re.compile(
    r"(requireAuth|requireAuthApi|getServerSession|withAuth|authenticate|"
    r"auth\(\)|useSession|getSession|checkAuth|verifyToken|validateToken)",
    re.IGNORECASE,
)
AUTHZ_PATTERNS = re.compile(
    r"(requireTeamAccess|requireProjectAccess|checkPermission|authorize|"
    r"hasAccess|isOwner|isMember|canAccess|verifyOwnership|"
    r"project\.members|team\.members|where.*userId)",
    re.IGNORECASE,
)
CSRF_PATTERNS = re.compile(r"checkCsrf|csrfToken|csrfProtection", re.IGNORECASE)
RATE_LIMIT_PATTERNS = re.compile(r"checkRateLimit|rateLimit|rateLimiter|rate.?limit", re.IGNORECASE)
ZOD_PARSE_PATTERNS = re.compile(r"\.parse\(|\.safeParse\(|z\.object\(", re.IGNORECASE)
ROUTE_EXPORT_PATTERN = re.compile(r"export\s+async\s+function\s+(GET|POST|PUT|DELETE|PATCH)")
PARAMS_PATTERN = re.compile(r"params.*?:\s*(?:Promise<)?\{[^}]*id:\s*string")
BODY_PARSE_PATTERN = re.compile(r"req\.json\(\)|request\.json\(\)|formData\(\)")
TYPE_ASSERTION_PATTERN = re.compile(r"\bas\s+(?:Record|{\s*[A-Za-z?]+)")
SENSITIVE_FILE_PATTERNS = re.compile(
    r"(encrypt|decrypt|crypto|hash|password|secret|auth.*config|middleware)",
    re.IGNORECASE,
)
RAW_QUERY_PATTERN = re.compile(r"\$queryRawUnsafe|\$executeRawUnsafe|raw\s*\(", re.IGNORECASE)


def _find_route_files(target: str) -> list[str]:
    """Find all Next.js API route files."""
    routes = []
    abs_target = os.path.abspath(target)
    for root, dirs, files in os.walk(abs_target):
        dirs[:] = [d for d in dirs if d not in {
            "node_modules", ".next", ".git", "dist", ".venv",
        }]
        for f in files:
            if f == "route.ts" or f == "route.js":
                routes.append(os.path.join(root, f))
    return routes


def _analyze_route(file_path: str) -> dict:
    """Analyze a single API route file for auth/authz patterns."""
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except OSError:
        return {"file": file_path, "error": "unreadable"}

    methods = ROUTE_EXPORT_PATTERN.findall(content)
    has_params = bool(PARAMS_PATTERN.search(content))
    has_auth = bool(AUTH_PATTERNS.search(content))
    has_authz = bool(AUTHZ_PATTERNS.search(content))
    has_csrf = bool(CSRF_PATTERNS.search(content))
    has_rate_limit = bool(RATE_LIMIT_PATTERNS.search(content))
    has_body_parse = bool(BODY_PARSE_PATTERN.search(content))
    has_zod = bool(ZOD_PARSE_PATTERNS.search(content))
    has_type_assertion = bool(TYPE_ASSERTION_PATTERN.search(content))
    has_raw_query = bool(RAW_QUERY_PATTERN.search(content))

    return {
        "file": file_path,
        "methods": methods,
        "has_params": has_params,
        "has_auth": has_auth,
        "has_authz": has_authz,
        "has_csrf": has_csrf,
        "has_rate_limit": has_rate_limit,
        "has_body_parse": has_body_parse,
        "has_zod_validation": has_zod,
        "has_unsafe_type_assertion": has_type_assertion,
        "has_raw_query": has_raw_query,
        "risks": _identify_risks(
            methods, has_params, has_auth, has_authz, has_csrf,
            has_rate_limit, has_body_parse, has_zod, has_type_assertion,
        ),
    }


def _identify_risks(
    methods: list[str],
    has_params: bool,
    has_auth: bool,
    has_authz: bool,
    has_csrf: bool,
    has_rate_limit: bool,
    has_body_parse: bool,
    has_zod: bool,
    has_type_assertion: bool,
) -> list[str]:
    risks = []
    if not has_auth:
        risks.append("missing-authentication")
    if has_auth and has_params and not has_authz:
        risks.append("idor-risk")
    write_methods = {"POST", "PUT", "DELETE", "PATCH"}
    if write_methods.intersection(methods) and not has_csrf:
        risks.append("missing-csrf")
    if has_body_parse and not has_zod:
        risks.append("missing-input-validation")
    if has_type_assertion:
        risks.append("unsafe-type-assertion")
    return risks


def _find_env_files(target: str) -> list[str]:
    """Find .env files in the project (content NOT read)."""
    env_files = []
    abs_target = os.path.abspath(target)
    for root, dirs, files in os.walk(abs_target):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", ".next"}]
        for f in files:
            if f.startswith(".env") and not f.endswith(".example"):
                env_files.append(os.path.relpath(os.path.join(root, f), abs_target))
    return env_files


def _find_sensitive_files(target: str) -> list[str]:
    """Find files related to encryption, auth config, etc."""
    sensitive = []
    abs_target = os.path.abspath(target)
    exclude = {"node_modules", ".next", ".git", "dist", ".venv", "__pycache__"}
    for root, dirs, files in os.walk(abs_target):
        dirs[:] = [d for d in dirs if d not in exclude]
        for f in files:
            if not f.endswith((".ts", ".js", ".tsx", ".jsx", ".py", ".go", ".java")):
                continue
            name_lower = f.lower()
            if SENSITIVE_FILE_PATTERNS.search(name_lower):
                sensitive.append(os.path.relpath(os.path.join(root, f), abs_target))
            else:
                filepath = os.path.join(root, f)
                try:
                    with open(filepath, encoding="utf-8", errors="ignore") as fh:
                        content = fh.read(5000)
                except OSError:
                    continue
                if RAW_QUERY_PATTERN.search(content):
                    sensitive.append(os.path.relpath(filepath, abs_target))
    return sensitive


def _compute_middleware_coverage(routes: list[dict]) -> dict:
    """Compute middleware coverage statistics."""
    total = len(routes)
    with_auth = sum(1 for r in routes if r.get("has_auth"))
    with_authz = sum(1 for r in routes if r.get("has_authz"))
    write_routes = [r for r in routes if {"POST", "PUT", "DELETE", "PATCH"}.intersection(r.get("methods", []))]
    with_csrf = sum(1 for r in write_routes if r.get("has_csrf"))
    with_rate_limit = sum(1 for r in routes if r.get("has_rate_limit"))
    with_body_parse = sum(1 for r in routes if r.get("has_body_parse"))
    with_zod = sum(1 for r in routes if r.get("has_zod_validation"))

    return {
        "total_api_routes": total,
        "with_auth": with_auth,
        "without_auth": total - with_auth,
        "with_resource_authz": with_authz,
        "write_routes": len(write_routes),
        "write_routes_with_csrf": with_csrf,
        "write_routes_without_csrf": len(write_routes) - with_csrf,
        "with_rate_limit": with_rate_limit,
        "with_body_parse": with_body_parse,
        "with_zod_validation": with_zod,
    }


def collect_analysis_targets(
    target: str,
    project: dict,
    findings: list[dict],
) -> dict:
    """Collect code context for LLM-augmented analysis.

    Returns structured analysis targets without reading sensitive file contents.
    """
    route_files = _find_route_files(target)
    routes = [_analyze_route(f) for f in route_files]

    risky_routes = [r for r in routes if r.get("risks")]

    middleware_coverage = _compute_middleware_coverage(routes)
    env_files = _find_env_files(target)
    sensitive_files = _find_sensitive_files(target)

    existing_files = {f.get("file", "") for f in findings}

    llm_targets = []
    for r in risky_routes:
        if r.get("file") not in existing_files:
            llm_targets.append({
                "file": r["file"],
                "risks": r["risks"],
                "priority": _priority_for_risks(r["risks"]),
                "reason": _describe_risks(r),
            })

    for sf in sensitive_files:
        if sf not in existing_files:
            llm_targets.append({
                "file": sf,
                "risks": ["sensitive-file"],
                "priority": "medium",
                "reason": "File handles encryption, auth config, or raw SQL queries",
            })

    llm_targets.sort(key=lambda t: {"critical": 0, "high": 1, "medium": 2}.get(t["priority"], 3))

    result = {
        "api_routes": routes,
        "risky_routes": risky_routes,
        "llm_analysis_targets": llm_targets,
        "middleware_coverage": middleware_coverage,
        "env_files": env_files,
        "sensitive_files": sensitive_files,
    }

    logger.info(
        "Context collection: %d routes (%d risky), %d env files, %d sensitive files, %d LLM targets",
        len(routes), len(risky_routes), len(env_files), len(sensitive_files), len(llm_targets),
    )

    return result


def _priority_for_risks(risks: list[str]) -> str:
    if "missing-authentication" in risks:
        return "critical"
    if "idor-risk" in risks:
        return "high"
    if "missing-input-validation" in risks:
        return "high"
    if "missing-csrf" in risks:
        return "medium"
    return "medium"


def _describe_risks(route: dict) -> str:
    parts = []
    risks = route.get("risks", [])
    if "missing-authentication" in risks:
        parts.append("No authentication check found")
    if "idor-risk" in risks:
        parts.append("Has URL params but no resource authorization")
    if "missing-csrf" in risks:
        parts.append("Write method without CSRF protection")
    if "missing-input-validation" in risks:
        parts.append("Parses request body without Zod schema validation")
    if "unsafe-type-assertion" in risks:
        parts.append("Uses unsafe 'as' type assertion instead of validation")
    return "; ".join(parts)


def save_analysis_targets(targets: dict, output_dir: str) -> str:
    """Save analysis targets to JSON file."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "analysis-targets.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(targets, fh, indent=2, default=str)
    return path
