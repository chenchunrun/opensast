"""Cross-file authorization chain analysis for detecting unprotected routes and IDOR candidates."""

import logging
import os
import re

from normalize_findings import _build

logger = logging.getLogger(__name__)

# --- Middleware patterns ---

NEXTJS_MIDDLEWARE_FILES = {"middleware.ts", "middleware.js"}
EXPRESS_ENTRY_FILES = {"app.ts", "app.js", "index.ts", "index.js", "server.ts", "server.js"}

NEXTJS_MATCHER_RE = re.compile(r"matcher\s*:\s*\[([^\]]+)\]")
NEXTJS_PATHNAME_RE = re.compile(r"pathname\.startsWith\(['\"]([^'\"]+)['\"]\)")
NEXTJS_IF_PATH_RE = re.compile(r"if\s*\(\s*request\.nextUrl\.pathname", re.IGNORECASE)

EXPRESS_APP_USE_RE = re.compile(r"app\.use\(\s*['\"]([^'\"]+)['\"]")
EXPRESS_ROUTER_USE_RE = re.compile(r"router\.use\(\s*\w+")
EXPRESS_ROUTE_AUTH_RE = re.compile(r"router\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"](?:\s*,\s*(\w+))+")

SPRING_SECURITY_CONFIG_RE = re.compile(r"requestMatchers?\(['\"]([^'\"]+)['\"]\)\.(\w+)")
SPRING_PERMIT_ALL_RE = re.compile(r"permitAll\(\)")

ROUTE_EXPORT_RE = re.compile(r"export\s+async\s+function\s+(GET|POST|PUT|DELETE|PATCH)")

AUTHZ_PATTERNS = re.compile(
    r"(requireTeamAccess|requireProjectAccess|checkPermission|authorize|"
    r"hasAccess|isOwner|isMember|canAccess|verifyOwnership|"
    r"where.*userId|\.userId\s*===)",
    re.IGNORECASE,
)
PARAMS_PATTERN = re.compile(r"params.*?:\s*(?:Promise<)?\{[^}]*id:\s*string")

EXCLUDE_DIRS = frozenset({
    "node_modules", ".next", ".git", "dist", ".venv", "__pycache__",
    ".cache", ".nuxt", ".turbo", "coverage", ".ruff_cache", "build",
})


def _find_route_files(target: str) -> list[str]:
    routes = []
    abs_target = os.path.abspath(target)
    for root, dirs, files in os.walk(abs_target):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in files:
            if f == "route.ts" or f == "route.js":
                routes.append(os.path.join(root, f))
    return routes


def _relative_path(file_path: str, target: str) -> str:
    try:
        return os.path.relpath(file_path, os.path.abspath(target))
    except ValueError:
        return file_path


def _read_file(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


# --- Next.js middleware analysis ---

def _parse_nextjs_middleware(target: str) -> dict:
    """Parse Next.js middleware.ts to extract protected route patterns."""
    result = {"protected_prefixes": [], "excluded_prefixes": [], "has_auth_check": False}
    abs_target = os.path.abspath(target)

    for root, dirs, files in os.walk(abs_target):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in files:
            if f in NEXTJS_MIDDLEWARE_FILES:
                content = _read_file(os.path.join(root, f))
                if not content:
                    continue

                # Extract matcher config
                matcher_match = NEXTJS_MATCHER_RE.search(content)
                if matcher_match:
                    patterns = [p.strip().strip("'\"") for p in matcher_match.group(1).split(",")]
                    result["protected_prefixes"].extend(patterns)

                # Extract pathname.startsWith checks
                for m in NEXTJS_PATHNAME_RE.finditer(content):
                    result["protected_prefixes"].append(m.group(1))

                # Check if auth is verified
                auth_keywords = ["getToken", "getServerSession", "auth()", "session", "verify", "cookie"]
                result["has_auth_check"] = any(kw in content for kw in auth_keywords)

                result["middleware_file"] = os.path.relpath(os.path.join(root, f), abs_target)

    return result


def _nextjs_route_to_url_pattern(file_path: str, target: str) -> str:
    """Convert Next.js route file path to URL pattern."""
    abs_target = os.path.abspath(target)
    rel = os.path.relpath(file_path, abs_target)
    # app/api/users/[id]/route.ts → /api/users/[id]
    parts = rel.replace(os.sep, "/")
    if parts.startswith("app/"):
        parts = parts[4:]
    if parts.endswith("/route.ts") or parts.endswith("/route.js"):
        parts = parts.rsplit("/", 1)[0]
    return "/" + parts


def _is_route_protected(route_url: str, protected_prefixes: list[str]) -> bool:
    """Check if a route URL matches any protected prefix pattern."""
    for prefix in protected_prefixes:
        clean = prefix.strip()
        # Convert Next.js matcher patterns like /api/:path* to prefix matching
        clean = re.sub(r":\w+\*?", "", clean).rstrip("/")
        if not clean:
            continue
        if route_url.startswith(clean):
            return True
    return False


# --- Express middleware analysis ---

def _parse_express_middleware(target: str) -> dict:
    """Parse Express app files for global middleware."""
    result = {"global_auth": False, "protected_prefixes": [], "route_auth": {}}
    abs_target = os.path.abspath(target)

    for root, dirs, files in os.walk(abs_target):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in files:
            if f not in EXPRESS_ENTRY_FILES:
                continue
            content = _read_file(os.path.join(root, f))
            if not content:
                continue

            # Check for global auth middleware
            auth_keywords = ["requireAuth", "authenticate", "authMiddleware", "verifyToken", "passport"]
            for line in content.splitlines():
                stripped = line.strip()
                # app.use(authMiddleware) without path = global
                if re.match(r"app\.use\(\s*\w+", stripped):
                    for kw in auth_keywords:
                        if kw in stripped:
                            result["global_auth"] = True

                # app.use("/api", authMiddleware)
                match = EXPRESS_APP_USE_RE.match(stripped)
                if match:
                    for kw in auth_keywords:
                        if kw in stripped:
                            result["protected_prefixes"].append(match.group(1))

    return result


# --- Spring Security analysis ---

def _parse_spring_security(target: str) -> dict:
    """Parse Spring Security configuration."""
    result = {"global_auth": False, "permit_all_patterns": [], "authenticated": False}
    abs_target = os.path.abspath(target)

    for root, dirs, files in os.walk(abs_target):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in files:
            if not f.endswith(".java"):
                continue
            content = _read_file(os.path.join(root, f))
            if "HttpSecurity" not in content and "SecurityFilterChain" not in content:
                continue

            if "anyRequest().authenticated()" in content:
                result["authenticated"] = True
                result["global_auth"] = True

            for m in SPRING_SECURITY_CONFIG_RE.finditer(content):
                path_pattern = m.group(1)
                method = m.group(2)
                if method == "permitAll":
                    result["permit_all_patterns"].append(path_pattern)

    return result


# --- Rails middleware analysis ---

RAILS_AUTH_BEFORE_ACTION_RE = re.compile(r"before_action\s+:.*(?:authenticate|authorize|require_login|verify_token)")
RAILS_SKIP_CSRF_RE = re.compile(r"skip_before_action\s+:verify_authenticity_token")
RAILS_CONTROLLER_RE = re.compile(r"class\s+\w+\s*<\s*ApplicationController")


def _parse_rails_middleware(target: str) -> dict:
    """Parse Rails controllers for authentication patterns."""
    result = {"global_auth": False, "protected_prefixes": [], "skip_csrf_controllers": []}
    abs_target = os.path.abspath(target)

    for root, dirs, files in os.walk(abs_target):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in files:
            if not f.endswith(("_controller.rb",)):
                continue
            content = _read_file(os.path.join(root, f))
            if not content or not RAILS_CONTROLLER_RE.search(content):
                continue

            if RAILS_AUTH_BEFORE_ACTION_RE.search(content):
                result["global_auth"] = True

            if RAILS_SKIP_CSRF_RE.search(content):
                rel = os.path.relpath(os.path.join(root, f), abs_target)
                result["skip_csrf_controllers"].append(rel)

    # Check application_controller.rb for global auth
    app_controller = os.path.join(abs_target, "app", "controllers", "application_controller.rb")
    if os.path.isfile(app_controller):
        content = _read_file(app_controller)
        if RAILS_AUTH_BEFORE_ACTION_RE.search(content):
            result["global_auth"] = True

    return result


# --- Laravel middleware analysis ---

LARAVEL_AUTH_MIDDLEWARE_RE = re.compile(r"'auth'\s*=>\s*\\\\?(\w+)")
LARAVEL_ROUTE_AUTH_RE = re.compile(r"Route::(?:middleware|group)\(\[['\"][^'\"]*auth[^'\"]*['\"]")


def _parse_laravel_middleware(target: str) -> dict:
    """Parse Laravel middleware and route configuration."""
    result = {"global_auth": False, "protected_prefixes": []}
    abs_target = os.path.abspath(target)

    # Check kernel.php for global middleware
    kernel = os.path.join(abs_target, "app", "Http", "Kernel.php")
    if os.path.isfile(kernel):
        content = _read_file(kernel)
        if "'auth'" in content or "AuthMiddleware" in content:
            result["global_auth"] = True

    # Check routes for auth middleware
    routes_dir = os.path.join(abs_target, "routes")
    if os.path.isdir(routes_dir):
        for rf in os.listdir(routes_dir):
            if rf.endswith(".php"):
                content = _read_file(os.path.join(routes_dir, rf))
                if LARAVEL_ROUTE_AUTH_RE.search(content):
                    result["global_auth"] = True

    return result


# --- Route analysis ---

def _analyze_route_auth(file_path: str) -> dict:
    """Analyze a single route file for auth/authz patterns."""
    content = _read_file(file_path)
    if not content:
        return {"file": file_path, "methods": [], "has_auth": False, "has_authz": False, "has_params": False}

    methods = ROUTE_EXPORT_RE.findall(content)
    has_auth = bool(re.search(r"requireAuth|getServerSession|auth\(\)|useSession|getSession|checkAuth|verifyToken", content, re.IGNORECASE))
    has_authz = bool(AUTHZ_PATTERNS.search(content))
    has_params = bool(PARAMS_PATTERN.search(content))

    return {
        "file": file_path,
        "methods": methods,
        "has_auth": has_auth,
        "has_authz": has_authz,
        "has_params": has_params,
    }


def _detect_framework(project: dict) -> str:
    """Detect the primary web framework."""
    frameworks = [f.lower() for f in project.get("frameworks", [])]
    if "next.js" in frameworks or "nextjs" in frameworks:
        return "nextjs"
    if "express" in frameworks:
        return "express"
    if "spring" in frameworks or "spring boot" in frameworks:
        return "spring"
    if "flask" in frameworks or "django" in frameworks:
        return "python"
    if "rails" in frameworks or "ruby on rails" in frameworks:
        return "rails"
    if "laravel" in frameworks:
        return "laravel"
    return "unknown"


def analyze_auth_chains(target: str, project: dict) -> dict:
    """Analyze authorization chains across the project.

    Returns:
        dict with keys:
            findings: list of standard finding dicts
            middleware_files: list of middleware file paths
            protected_patterns: list of protected URL patterns
            unprotected_routes: list of routes not covered by auth middleware
            idor_candidates: list of routes with params but no resource-level auth
            coverage: dict with coverage statistics
    """
    framework = _detect_framework(project)
    route_files = _find_route_files(target)

    if not route_files:
        return {"findings": [], "unprotected_routes": [], "idor_candidates": [], "coverage": {}}

    # Parse middleware
    if framework == "nextjs":
        mw = _parse_nextjs_middleware(target)
        protected_prefixes = mw.get("protected_prefixes", [])
        mw_has_auth = mw.get("has_auth_check", False)
        mw_file = mw.get("middleware_file", "")
    elif framework == "express":
        mw = _parse_express_middleware(target)
        protected_prefixes = mw.get("protected_prefixes", [])
        mw_has_auth = mw.get("global_auth", False)
        mw_file = ""
    elif framework == "rails":
        mw = _parse_rails_middleware(target)
        protected_prefixes = []
        mw_has_auth = mw.get("global_auth", False)
        mw_file = ""
    elif framework == "laravel":
        mw = _parse_laravel_middleware(target)
        protected_prefixes = []
        mw_has_auth = mw.get("global_auth", False)
        mw_file = ""
    elif framework == "spring":
        mw = _parse_spring_security(target)
        protected_prefixes = []
        mw_has_auth = mw.get("global_auth", False)
        mw_file = ""
    else:
        protected_prefixes = []
        mw_has_auth = False
        mw_file = ""

    # Analyze each route
    findings: list[dict] = []
    unprotected_routes = []
    idor_candidates = []
    total = len(route_files)
    protected_count = 0

    for fp in route_files:
        route_info = _analyze_route_auth(fp)
        rel_path = _relative_path(fp, target)
        route_url = _nextjs_route_to_url_pattern(fp, target)
        methods = route_info["methods"]

        # Check if route is protected by middleware
        middleware_protected = _is_route_protected(route_url, protected_prefixes) if protected_prefixes else False

        # Check for missing authentication
        if not route_info["has_auth"] and not middleware_protected and not mw_has_auth:
            unprotected_routes.append({
                "file": rel_path,
                "url": route_url,
                "methods": methods,
                "reason": "no auth check in handler and no protecting middleware",
            })
            findings.append(_build(
                tool="auth-chain-analyzer",
                rule_id="auth.unprotected-route",
                title="API route not protected by authentication",
                severity="critical",
                file_path=rel_path,
                start_line=1,
                end_line=1,
                message=f"Route {route_url} ({', '.join(methods)}) has no authentication middleware or handler-level auth check",
                cwe=["CWE-284"],
                owasp=["A01:2021-Broken Access Control"],
                evidence={"source": "", "sink": "", "dataflow": []},
                recommendation="Add authentication middleware or handler-level auth check.",
                language=_detect_language_ext(fp),
                confidence="high",
            ))
        else:
            protected_count += 1

        # Check for IDOR: has params but no resource-level authorization
        if route_info["has_params"] and route_info["has_auth"] and not route_info["has_authz"]:
            idor_candidates.append({
                "file": rel_path,
                "url": route_url,
                "methods": methods,
                "reason": "has URL params and auth but no resource-level authorization check",
            })
            findings.append(_build(
                tool="auth-chain-analyzer",
                rule_id="auth.idor-risk",
                title="Potential IDOR: resource access without ownership check",
                severity="high",
                file_path=rel_path,
                start_line=1,
                end_line=1,
                message=f"Route {route_url} ({', '.join(methods)}) accesses resource by ID but has no ownership/authorization check",
                cwe=["CWE-639"],
                owasp=["A01:2021-Broken Access Control"],
                evidence={"source": "", "sink": "", "dataflow": []},
                recommendation="Add resource-level authorization: verify the current user owns or can access the requested resource.",
                language=_detect_language_ext(fp),
                confidence="medium",
            ))

    coverage = {
        "total_routes": total,
        "protected_routes": protected_count,
        "unprotected_routes": len(unprotected_routes),
        "idor_candidates": len(idor_candidates),
        "middleware_file": mw_file,
        "middleware_has_auth": mw_has_auth,
        "protected_patterns": protected_prefixes,
    }

    logger.info(
        "Auth chain analysis: %d routes, %d unprotected, %d IDOR candidates",
        total, len(unprotected_routes), len(idor_candidates),
    )

    return {
        "findings": findings,
        "middleware_files": [mw_file] if mw_file else [],
        "protected_patterns": protected_prefixes,
        "unprotected_routes": unprotected_routes,
        "idor_candidates": idor_candidates,
        "coverage": coverage,
    }


def _detect_language_ext(file_path: str) -> str:
    ext = os.path.splitext(file_path)[1].lower()
    mapping = {".ts": "typescript", ".tsx": "typescript", ".js": "javascript", ".jsx": "javascript",
               ".py": "python", ".java": "java", ".go": "go"}
    return mapping.get(ext, "")
