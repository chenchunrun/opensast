"""Cross-file data flow analyzer for detecting missing authorization checks.

Traces data from API route handlers through service functions to database
queries, identifying paths where resource ownership is never verified.
"""

import logging
import os
import re

logger = logging.getLogger("dataflow_analyzer")

EXCLUDE_DIRS = frozenset({
    "node_modules", ".next", ".git", "vendor", "dist", "build", "__pycache__",
    ".claude", "coverage", ".cache", "public", "static", "assets",
    ".venv", ".nuxt", ".turbo", ".ruff_cache",
})

# Patterns for detecting Prisma/ORM database queries
DB_QUERY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'\.findUnique\s*\(\s*\{', re.DOTALL),
    re.compile(r'\.findFirst\s*\(\s*\{', re.DOTALL),
    re.compile(r'\.findMany\s*\(\s*\{', re.DOTALL),
    re.compile(r'\.delete\s*\(\s*\{', re.DOTALL),
    re.compile(r'\.update\s*\(\s*\{', re.DOTALL),
]

# Patterns for detecting ownership checks in where clauses
OWNERSHIP_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'userId'),
    re.compile(r'teamId'),
    re.compile(r'ownerId'),
    re.compile(r'organizationId'),
    re.compile(r'memberId'),
]

# Resource ID parameter patterns
RESOURCE_ID_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'(\w+Id)\s*[:=]'),
    re.compile(r'params\.(\w+)'),
    re.compile(r'params\["(\w+)"\]'),
]

# Built-in names to skip when tracing function calls
SKIP_CALL_NAMES = frozenset({
    "GET", "POST", "PUT", "DELETE", "PATCH",
    "json", "NextResponse", "Response", "request", "console",
    "parseInt", "parseFloat", "String", "Number", "Boolean",
    "Promise", "Object", "Array", "Map", "Set",
})


def analyze_project(target: str, project: dict) -> list[dict]:
    """Main entry point. Scans project for cross-file authorization gaps."""
    from normalize_findings import _build

    findings: list[dict] = []

    # Only supports JS/TS projects currently
    languages = set(project.get("languages", {}).keys())
    if not languages & {"typescript", "javascript"}:
        return findings

    # Step 1: Build function index
    function_index = _build_function_index(target)

    # Step 2: Find route handlers
    routes = _find_route_handlers(target)

    # Step 3: For each route, trace data flow
    for route in routes:
        route_findings = _analyze_route(route, function_index, target)
        findings.extend(route_findings)

    logger.info(
        "Data flow analysis: %d routes analyzed, %d findings",
        len(routes), len(findings),
    )
    return findings


def _build_function_index(target: str) -> dict[str, dict]:
    """Build index of exported functions across the project.

    Returns:
        Mapping of function_name -> {
            file, params, line, is_service, has_db_query, has_ownership_check
        }
    """
    index: dict[str, dict] = {}
    abs_target = os.path.abspath(target)

    for root, dirs, files in os.walk(abs_target):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]

        for fname in files:
            if not fname.endswith((".ts", ".tsx", ".js")):
                continue

            fpath = os.path.join(root, fname)
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                continue

            has_db_query = any(p.search(content) for p in DB_QUERY_PATTERNS)
            has_ownership = any(p.search(content) for p in OWNERSHIP_PATTERNS)

            # Find exported functions
            func_re = re.compile(
                r'(?:export\s+(?:async\s+)?function\s+(\w+)|'
                r'export\s+const\s+(\w+)\s*=\s*(?:async\s*)?\(|'
                r'(?:async\s+)?function\s+(\w+))',
            )
            for m in func_re.finditer(content):
                fn_name = m.group(1) or m.group(2) or m.group(3)
                if not fn_name:
                    continue

                # Extract parameters
                start = m.end()
                params = _extract_params(content, start)

                index[fn_name] = {
                    "file": fpath,
                    "params": params,
                    "line": content[:m.start()].count("\n") + 1,
                    "is_service": (
                        has_db_query
                        or "service" in fname.lower()
                        or "lib" in fpath.lower()
                    ),
                    "has_db_query": has_db_query,
                    "has_ownership_check": has_ownership,
                }

    return index


def _extract_params(content: str, start: int) -> list[str]:
    """Extract parameter names from function signature."""
    depth = 0
    paren_start = content.find("(", start)
    if paren_start == -1:
        return []

    for i in range(paren_start, min(paren_start + 200, len(content))):
        if content[i] == "(":
            depth += 1
        elif content[i] == ")":
            depth -= 1
            if depth == 0:
                params_str = content[paren_start + 1:i]
                return re.findall(r'(\w+)', params_str)
    return []


def _find_route_handlers(target: str) -> list[dict]:
    """Find all API route handlers (Next.js route.ts / route.js files)."""
    routes: list[dict] = []
    abs_target = os.path.abspath(target)

    for root, dirs, files in os.walk(abs_target):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]

        for fname in files:
            if fname not in ("route.ts", "route.js"):
                continue

            fpath = os.path.join(root, fname)
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                continue

            # Extract URL params from directory structure
            rel_path = os.path.relpath(root, abs_target)
            url_params = re.findall(r'\[(\w+)\]', rel_path)

            # Extract HTTP methods
            http_methods: list[str] = []
            for m in re.finditer(
                r'export\s+async\s+function\s+(GET|POST|PUT|DELETE|PATCH)', content,
            ):
                http_methods.append(m.group(1))

            # Find function calls in the route handler
            function_calls = re.findall(r'(?:await\s+)?(\w+)\s*\(', content)

            # Find resource IDs accessed from params
            resource_ids: list[str] = []
            for pm in RESOURCE_ID_PATTERNS:
                for match in pm.finditer(content):
                    rid = match.group(1)
                    if rid and rid not in ("id",) and rid.endswith("Id"):
                        resource_ids.append(rid)
                    elif rid == "id":
                        resource_ids.append("id")

            routes.append({
                "file": fpath,
                "url_params": url_params,
                "http_methods": http_methods,
                "function_calls": list(set(function_calls)),
                "resource_ids": list(set(resource_ids)),
                "content": content,
            })

    return routes


def _analyze_route(
    route: dict, function_index: dict[str, dict], target: str,
) -> list[dict]:
    """Analyze a route handler for authorization gaps."""
    from normalize_findings import _build

    findings: list[dict] = []

    # For each function called in the route, check if it reaches a DB query
    for call in route["function_calls"]:
        if call in SKIP_CALL_NAMES:
            continue

        service_fn = function_index.get(call)
        if not service_fn or not service_fn["is_service"]:
            continue

        # Check: does the service function have a DB query?
        if not service_fn["has_db_query"]:
            continue

        # Potential gap found: service function has DB query.
        # Verify at function granularity whether ownership is actually checked.
        gap = _verify_authorization_gap(service_fn, call)
        if gap:
            findings.append(_build(
                tool="dataflow-analyzer",
                rule_id="dataflow.missing-ownership",
                title=f"Missing ownership check in {call}",
                severity="high",
                file_path=route["file"],
                start_line=1,
                end_line=1,
                message=(
                    f"Route calls {call}() which queries the database without "
                    f"verifying resource ownership. Any authenticated user can "
                    f"access resources belonging to other users/teams."
                ),
                cwe=["CWE-862"],
                owasp=["A01:2021-Broken Access Control"],
                evidence={
                    "source": os.path.basename(route["file"]),
                    "sink": (
                        f"{os.path.basename(service_fn['file'])}:"
                        f"{service_fn['line']}"
                    ),
                    "dataflow": [
                        {
                            "file": os.path.basename(route["file"]),
                            "description": f"Route handler calls {call}()",
                        },
                        {
                            "file": os.path.basename(service_fn["file"]),
                            "line": service_fn["line"],
                            "description": (
                                "Service function queries DB without "
                                "userId/teamId filter"
                            ),
                        },
                    ],
                },
                recommendation=(
                    f"Add ownership verification in {call}(): include "
                    f"userId or teamId in the where clause."
                ),
                language="typescript",
                confidence="high",
            ))

    return findings


def _verify_authorization_gap(service_fn: dict, fn_name: str) -> bool:
    """Verify an authorization gap exists by reading the specific function body."""
    try:
        with open(service_fn["file"], encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except OSError:
        return False

    # Extract the specific function body
    fn_body = _extract_function_body(content, fn_name)
    if not fn_body:
        return False

    # If the specific function body has ownership patterns, it checks
    if any(p.search(fn_body) for p in OWNERSHIP_PATTERNS):
        return False

    # Check for findUnique/findFirst/delete/update with only { id } in where.
    # This is a heuristic: findUnique({ where: { id: ... } }) without userId
    # is likely a gap.
    for m in re.finditer(
        r'\.(findUnique|findFirst|delete|update)\s*\(\s*\{\s*where:\s*\{([^}]+)\}',
        fn_body,
    ):
        where_clause = m.group(2)
        has_user = any(p.search(where_clause) for p in OWNERSHIP_PATTERNS)
        if not has_user:
            return True

    return False


def _extract_function_body(content: str, fn_name: str) -> str:
    """Extract the body of a named function from file content."""
    # Match function declarations: function name(...){
    pattern = re.compile(
        r'(?:export\s+)?(?:async\s+)?function\s+'
        + re.escape(fn_name)
        + r'\s*\([^)]*\)\s*\{',
    )
    m = pattern.search(content)
    if not m:
        # Try arrow function: const name = (async)? (...) => {
        arrow_pattern = re.compile(
            r'(?:export\s+)?const\s+'
            + re.escape(fn_name)
            + r'\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{',
        )
        m = arrow_pattern.search(content)
    if not m:
        return ""

    # Find the matching closing brace
    start = m.end()  # position after the opening {
    depth = 1
    for i in range(start, min(start + 5000, len(content))):
        if content[i] == "{":
            depth += 1
        elif content[i] == "}":
            depth -= 1
            if depth == 0:
                return content[m.start():i + 1]

    return content[m.start():]
