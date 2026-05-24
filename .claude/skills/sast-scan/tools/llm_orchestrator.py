"""LLM Orchestrator — context extraction and analysis plan generation.

Core module for LLM-primary SAST architecture. Replaces regex-based analyzers
with archetype-aware analysis prompts that Claude validates.
"""

import json
import logging
import os
import re
from collections import Counter
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

MAX_FILE_SIZE_BYTES = 1_000_000
CONTEXT_LINES = 15
MAX_TARGETS_DEFAULT = 15
MAX_FILE_LINES_FULL = 200

# --- Archetype context messages ---

ARCHETYPE_CONTEXTS = {
    "web-app": {
        "exec.Command": "web-app (exec.Command in web handler = potential RCE via CWE-78)",
        "os.Getenv": "web-app (env vars acceptable, check for hardcoded fallback values)",
        "eval(": "web-app (eval = potential code injection via CWE-94)",
        "innerHTML": "web-app (innerHTML = potential XSS via CWE-79)",
        "raw query": "web-app (raw SQL = potential injection via CWE-89)",
    },
    "cli-tool": {
        "exec.Command": "cli-tool (exec.Command is NORMAL for CLI tools — only flag if user input flows to args)",
        "os.Getenv": "cli-tool (reading env vars is normal for CLI tools)",
        "eval(": "cli-tool (eval in CLI may be acceptable for config/scripting, check input source)",
        "innerHTML": "cli-tool (not web-rendered, likely false positive)",
        "raw query": "cli-tool (SQL in CLI tool — check if user input reaches query without sanitization)",
    },
    "library": {
        "exec.Command": "library (exec.Command in library — consumers may pass untrusted input, validate interface)",
        "os.Getenv": "library (env access in library — consider parameterization instead)",
        "eval(": "library (eval in library = high risk, consumers may not expect code execution)",
        "innerHTML": "library (innerHTML in library — consumers may use in web context, sanitize)",
        "raw query": "library (raw SQL in library — validate that consumers can't inject)",
    },
    "serverless": {
        "exec.Command": "serverless (exec.Command in serverless function = potential RCE via CWE-78)",
        "os.Getenv": "serverless (env vars common in serverless, check for hardcoded defaults)",
        "eval(": "serverless (eval = potential injection via CWE-94, high risk in cloud)",
        "innerHTML": "serverless (innerHTML — check if output is web-rendered)",
        "raw query": "serverless (raw SQL in serverless = potential injection via CWE-89)",
    },
}

# --- Entry point patterns by language/framework ---

ENTRY_POINT_PATTERNS: dict[str, list[re.Pattern]] = {
    "typescript": [
        re.compile(r"export\s+async\s+function\s+(GET|POST|PUT|DELETE|PATCH)\b"),
        re.compile(r"(?:app|router|server)\.(?:get|post|put|delete|patch|use)\s*\("),
        re.compile(r"export\s+(?:async\s+)?function\s+(?:handler|GET|POST|PUT|DELETE)"),
    ],
    "javascript": [
        re.compile(r"(?:app|router|server)\.(?:get|post|put|delete|patch|use)\s*\("),
        re.compile(r"module\.exports\s*=\s*(?:async\s+)?function"),
        re.compile(r"(?:GET|POST|PUT|DELETE|PATCH)\s*=\s*(?:async\s+)?\("),
    ],
    "go": [
        re.compile(r"func\s+\w+\(\s*w\s+http\.ResponseWriter"),
        re.compile(r"\.\s*(?:GET|POST|Put|Delete|HandleFunc|Handle)\s*\("),
        re.compile(r"func\s+\w+\(.*(?:echo|gin|fiber|iris)\.Context"),
    ],
    "python": [
        re.compile(r"@(?:app|router|bp|blueprint|api)\.(?:get|post|put|delete|patch|route)"),
        re.compile(r"@(?:router|api_router)\.(?:get|post|put|delete|patch)"),
        re.compile(r"class\s+\w+(?:View|APIView|Resource|Handler|Controller)\b"),
        re.compile(r"def\s+(?:main|handle_|serve_|api_|index)\b"),
    ],
    "java": [
        re.compile(r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping"),
        re.compile(r"@(?:GET|POST|PUT|DELETE|PATCH)\s*\("),
        re.compile(r"public\s+\w+\s+(?:doGet|doPost|handle|process)\b"),
    ],
}

# --- Security-relevant patterns ---

SECURITY_FILE_PATTERNS = re.compile(
    r"(encrypt|decrypt|crypto|hash|password|secret|auth.*config|"
    r"middleware|jwt|token|session|rbac|acl|credential|apikey|private.?key|"
    r"config[/\\]resolve|config[/\\]store|database.query)",
    re.IGNORECASE,
)

RAW_QUERY_PATTERN = re.compile(
    r"\$queryRawUnsafe|\$executeRawUnsafe|raw\s*\(|"
    r"(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*\+\s*(?:req|params|body|query|input|user)|"
    r"\$\([^)]*\)",  # shell command substitution
    re.IGNORECASE,
)

GO_SECURITY_IMPORTS = re.compile(
    r'"(?:os/exec|crypto/(?:cipher|aes|rsa|sha256|md5|rand|tls)|'
    r'net/http|database/sql|encoding/hex|encoding/base64)"',
)

GO_SECURITY_PATTERNS = re.compile(
    r"(exec\.Command|http\.Client|http\.Get|http\.Post|sql\.Query|sql\.Exec|"
    r"sha256\.Sum|md5\.New|aes\.NewCipher|rand\.Read|"
    r"os\.Getenv|viper\.Get|filepath\.Join|exec\.LookPath)",
)

GENERATED_PATH_PATTERN = re.compile(
    r"(?:^|/)(?:vendor|node_modules|dist|build|\.next|\.nuxt|out|\.gomodcache|"
    r"\.cache|\.parcel-cache)(?:/|$)|"
    r"(?:\.generated\.|\.pb\.go|\.pb\.rs|_gen\.|\.min\.js|\.min\.css|\.bundle\.)|"
    r"(?:^|/)(?:testdata|testfixtures|test-harness|fixture)(?:/|$)",
)

TEST_PATH_PATTERN = re.compile(
    r"(?:^|/)(?:test|tests|__tests__|spec|specs|testing|fixtures|mocks|stubs)(?:/|$)|"
    r"(?:^|/|_)(?:test_|spec_)[\w]+\.(?:py|js|ts|go|java|rb|rs)$|"
    r"(?:^|/)[\w]+(?:_test|_spec)\.(?:py|js|ts|go|java|rb|rs)$|"
    r"(?:^|/)[\w]+\.(?:test|spec)\.(?:py|js|ts|tsx|jsx|go|java|rb|rs)$",
)

SENSITIVE_FILE_BLOCKLIST = re.compile(
    r"\.(?:env|pem|key|p12|pfx|jks|keystore)$|"
    r"(?:^|/)(?:credentials|secrets?|\.htpasswd|\.netrc|\.npmrc|\.pypirc)$",
    re.IGNORECASE,
)

EXCLUDE_DIRS = {
    "node_modules", ".git", ".next", ".nuxt", "dist", "build", ".venv",
    "__pycache__", "vendor", ".gomodcache", "testdata", "test-harness",
    "fixtures", ".tox", ".mypy_cache", ".pytest_cache", ".turbo", ".cache",
    ".parcel-cache", "coverage", ".ruff_cache",
}

# --- Severity ranking ---

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


# ============================================================
# Fast deterministic filters
# ============================================================

def is_generated_code(file_path: str) -> bool:
    return bool(GENERATED_PATH_PATTERN.search(file_path.replace("\\", "/")))


def is_test_code(file_path: str) -> bool:
    return bool(TEST_PATH_PATTERN.search(file_path.replace("\\", "/")))


def apply_fast_filters(findings: list[dict]) -> list[dict]:
    """Remove findings from generated code and test code."""
    result = []
    for f in findings:
        file_path = f.get("file", "").replace("\\", "/")
        if is_generated_code(file_path):
            continue
        if is_test_code(file_path):
            continue
        result.append(f)
    return result


# ============================================================
# Entry point detection
# ============================================================

def _language_for_file(file_path: str) -> str:
    ext = os.path.splitext(file_path)[1].lower()
    mapping = {
        ".ts": "typescript", ".tsx": "typescript",
        ".js": "javascript", ".jsx": "javascript",
        ".go": "go", ".py": "python", ".java": "java",
        ".kt": "java", ".rb": "python", ".php": "python",
    }
    return mapping.get(ext, "")


def find_entry_points(target: str) -> list[dict]:
    """Find all API entry points across the project."""
    entry_points = []
    abs_target = os.path.abspath(target)
    file_cache: dict[str, str] = {}

    for root, dirs, files in os.walk(abs_target):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext not in (".ts", ".tsx", ".js", ".jsx", ".go", ".py", ".java"):
                continue
            filepath = os.path.join(root, f)
            language = _language_for_file(f)
            patterns = ENTRY_POINT_PATTERNS.get(language, [])
            if not patterns:
                continue

            try:
                with open(filepath, encoding="utf-8", errors="ignore") as fh:
                    content = fh.read(100000)
            except OSError:
                continue

            if len(content) > MAX_FILE_SIZE_BYTES:
                continue

            for i, line in enumerate(content.splitlines(), 1):
                for pat in patterns:
                    if pat.search(line):
                        entry_points.append({
                            "file": os.path.relpath(filepath, abs_target),
                            "line": i,
                            "content": line.strip(),
                            "language": language,
                        })
                        break

    return entry_points


# ============================================================
# Security file identification
# ============================================================

def find_security_files(target: str) -> list[str]:
    """Find security-relevant files across the project."""
    security_files = []
    abs_target = os.path.abspath(target)

    for root, dirs, files in os.walk(abs_target):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext not in (".ts", ".tsx", ".js", ".jsx", ".go", ".py", ".java"):
                continue
            name_lower = f.lower()

            if name_lower.endswith(("_test.go", "_test.py", ".test.ts", ".test.js", ".spec.ts")):
                continue

            filepath = os.path.join(root, f)
            rel_path = os.path.relpath(filepath, abs_target)

            if SECURITY_FILE_PATTERNS.search(name_lower):
                security_files.append(rel_path)
                continue

            try:
                with open(filepath, encoding="utf-8", errors="ignore") as fh:
                    head = fh.read(5000)
            except OSError:
                continue

            if RAW_QUERY_PATTERN.search(head):
                security_files.append(rel_path)
                continue

            if name_lower.endswith(".go"):
                has_security_import = bool(GO_SECURITY_IMPORTS.search(head))
                has_security_code = bool(GO_SECURITY_PATTERNS.search(head))
                if has_security_import and has_security_code:
                    security_files.append(rel_path)

    return security_files


# ============================================================
# Middleware detection
# ============================================================

def _find_middleware(target: str) -> dict:
    """Find middleware files and extract protection info."""
    abs_target = os.path.abspath(target)
    middleware_candidates = [
        "middleware.ts", "middleware.js",
        "middleware.go",
        "middleware.py",
    ]

    for root, dirs, files in os.walk(abs_target):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in files:
            if f not in middleware_candidates:
                continue
            filepath = os.path.join(root, f)
            rel_path = os.path.relpath(filepath, abs_target)
            try:
                with open(filepath, encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                continue

            has_auth = bool(re.search(
                r"(getServerSession|getSession|checkAuth|verifyToken|"
                r"requireAuth|authenticate|auth\(\)|jwt\.Verify|"
                r"session\.Get|c\.Get.*user)",
                content, re.IGNORECASE,
            ))
            protected_prefixes = re.findall(r"['\"`](/api/[^'\"`]*)['\"`]", content)
            excluded_prefixes = re.findall(r"!\s*\(['\"`]([^'\"]+)['\"`]", content)

            return {
                "detected": True,
                "file": rel_path,
                "has_auth_check": has_auth,
                "protected_prefixes": protected_prefixes,
                "excluded_prefixes": excluded_prefixes,
            }

    return {"detected": False}


# ============================================================
# Finding context extraction
# ============================================================

def _read_file_safe(filepath: str) -> str:
    if SENSITIVE_FILE_BLOCKLIST.search(filepath):
        return ""
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as fh:
            return fh.read(MAX_FILE_SIZE_BYTES)
    except OSError:
        return ""


def _extract_surrounding_lines(content: str, line_number: int, context: int = CONTEXT_LINES) -> str:
    lines = content.splitlines()
    start = max(0, line_number - context - 1)
    end = min(len(lines), line_number + context)
    return "\n".join(lines[start:end])


def _extract_imports(content: str) -> str:
    lines = content.splitlines()
    import_lines = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("/*"):
            if import_lines:
                break
            continue
        is_import = (
            stripped.startswith("import ") or stripped.startswith("from ")
            or stripped.startswith('require(') or stripped.startswith('include ')
        )
        if is_import:
            import_lines.append(line)
        elif import_lines:
            break
    return "\n".join(import_lines)


def _extract_function_block(content: str, line_number: int) -> str:
    """Extract the function/method containing the given line."""
    lines = content.splitlines()
    if line_number < 1 or line_number > len(lines):
        return ""

    # Find function start by searching backwards for def/func/function/class
    func_start = 0
    func_patterns = [
        re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+", re.IGNORECASE),
        re.compile(r"^\s*func\s+"),
        re.compile(r"^\s*def\s+"),
        re.compile(r"^\s*class\s+"),
        re.compile(r"^\s*(?:public|private|protected)?\s*(?:static\s+)?(?:void|int|String|boolean)\s+\w+\s*\("),
    ]

    for i in range(line_number - 1, max(0, line_number - 100), -1):
        if i < len(lines):
            for pat in func_patterns:
                if pat.search(lines[i]):
                    func_start = i
                    break
            else:
                continue
            break

    # Find function end (next function start or end of file)
    func_end = len(lines)
    brace_count = 0
    found_open_brace = False

    for i in range(func_start, min(len(lines), func_start + 100)):
        if "{" in lines[i]:
            found_open_brace = True
        if found_open_brace:
            brace_count += lines[i].count("{") - lines[i].count("}")
            if brace_count <= 0:
                func_end = i + 1
                break

    return "\n".join(lines[func_start:func_end])


def extract_finding_context(
    finding: dict, project_root: str, archetype: str,
) -> dict:
    """Extract code context around a finding."""
    file_path = finding.get("file", "")
    line_number = finding.get("start_line", 0)

    if not file_path:
        return {"error": "no_file"}

    full_path = os.path.join(project_root, file_path) if not os.path.isabs(file_path) else file_path

    content = _read_file_safe(full_path)
    if not content:
        return {"error": "file_not_readable"}

    imports = _extract_imports(content)
    surrounding = _extract_surrounding_lines(content, line_number)
    func_block = _extract_function_block(content, line_number)
    file_lines = len(content.splitlines())

    # Determine archetype context
    code_text = surrounding.lower()
    archetype_msg = ""
    for pattern_key, msg in ARCHETYPE_CONTEXTS.get(archetype, {}).items():
        if pattern_key.lower() in code_text:
            archetype_msg = msg
            break

    return {
        "file": file_path,
        "line": line_number,
        "archetype_context": archetype_msg,
        "surrounding_code": surrounding,
        "function_block": func_block,
        "imports": imports,
        "file_lines": file_lines,
        "language": _language_for_file(file_path),
    }


# ============================================================
# Analysis prompt generation
# ============================================================

def _generate_analysis_prompt(
    finding: dict, context: dict, archetype: str,
) -> str:
    """Generate a tailored analysis prompt for a finding."""
    severity = finding.get("severity", "info")
    rule_id = finding.get("rule_id", "")
    message = finding.get("message", finding.get("code", ""))
    tool = finding.get("tool", "")
    file_path = finding.get("file", "")
    cwe = finding.get("cwe", [])
    if isinstance(cwe, list):
        cwe_str = ", ".join(cwe) if cwe else "unknown"
    else:
        cwe_str = str(cwe) if cwe else "unknown"

    archetype_note = context.get("archetype_context", "")
    surrounding = context.get("surrounding_code", "")
    imports = context.get("imports", "")

    parts = [
        f"[{tool}] {rule_id} in {file_path} (severity: {severity}, CWE: {cwe_str})",
        f"Message: {message}",
    ]

    if archetype_note:
        parts.append(f"Archetype context: {archetype_note}")

    parts.append(f"Code context:\n{surrounding}")

    if imports:
        parts.append(f"Imports:\n{imports}")

    # Add specific analysis guidance based on pattern
    # Check rule_id + message + code context for pattern matching
    code_lower = (surrounding + message + " " + rule_id).lower()

    if "exec.command" in code_lower or "os/exec" in code_lower:
        if archetype == "cli-tool":
            parts.append(
                "ANALYSIS: exec.Command is NORMAL in CLI tools. "
                "Only flag as vulnerability if user input (args, stdin, env from external source) "
                "flows directly into command arguments without sanitization."
            )
        else:
            parts.append(
                "ANALYSIS: Check if user-controlled data reaches exec.Command args. "
                "Look for: 1) HTTP request params → command args 2) SQL/user input → shell command "
                "3) Missing input sanitization before command execution."
            )
    elif ("ssrf" in code_lower or "http.get" in code_lower or "http.request" in code_lower
          or "http client" in code_lower or "user-controlled url" in code_lower
          or "http.post" in code_lower):
        if archetype == "cli-tool":
            parts.append(
                "ANALYSIS: SSRF in CLI tool — HTTP requests may be NORMAL for this type of tool "
                "(API client, scanner, agent). Only flag if: 1) User-supplied URLs are fetched "
                "without validation 2) Internal metadata endpoints are accessible "
                "3) Redirects are followed to internal services."
            )
        else:
            parts.append(
                "ANALYSIS: Check if URL/request target is user-controlled. "
                "Look for: 1) URL from query param/body without allowlist 2) Redirect following "
                "3) Internal network access (169.254.169.254 for cloud metadata)."
            )
    elif "path.traversal" in code_lower or "filepath.join" in code_lower:
        parts.append(
            "ANALYSIS: Check if path components come from user input. "
            "Look for: 1) .. sequences in path 2) Missing path sanitization "
            "3) Symlink following. Note: filepath.Join alone is NOT a vulnerability."
        )
    elif "csrf" in code_lower:
        parts.append(
            "ANALYSIS: CSRF protection is NOT needed for: 1) Bearer token APIs "
            "2) SameSite=Strict cookies 3) Custom header requirement (X-Requested-With). "
            "Only flag if using cookie-based session auth without CSRF token."
        )
    elif "sql" in code_lower and ("inject" in code_lower or "raw" in code_lower):
        parts.append(
            "ANALYSIS: Check if user input reaches SQL query without parameterization. "
            "Look for: 1) String concatenation in queries 2) Format strings with user data "
            "3) Raw query functions with unsanitized input."
        )
    elif "crypto" in code_lower or "aes" in code_lower or "md5" in code_lower:
        parts.append(
            "ANALYSIS: Check for: 1) ECB mode (insecure) 2) Hardcoded keys/IVs "
            "3) MD5/SHA1 used for security (not checksums) 4) Small key sizes "
            "5) Missing authentication (GCM vs CBC)."
        )
    elif "secret" in code_lower or "password" in code_lower or "api_key" in code_lower:
        parts.append(
            "ANALYSIS: Check for: 1) Hardcoded credentials in source 2) Secrets in config files "
            "3) Default passwords 4) Secrets in logs/error messages."
        )
    else:
        parts.append(
            "ANALYSIS: Evaluate if this is a true positive by tracing the data flow "
            "from source (user input, external data) to sink (dangerous operation). "
            "Consider the project context and whether the pattern is expected behavior."
        )

    return "\n\n".join(parts)


def _generate_explore_prompt(file_path: str, context: dict, archetype: str) -> str:
    """Generate a prompt for exploring a security-relevant file."""
    imports = context.get("imports", "")
    func_block = context.get("function_block", "")

    parts = [
        f"Security-relevant file: {file_path}",
        f"Project type: {archetype}",
    ]

    if imports:
        parts.append(f"Imports:\n{imports}")
    if func_block:
        parts.append(f"Key code:\n{func_block}")

    parts.append(
        "ANALYSIS: Review this file for: 1) Hardcoded secrets/keys 2) Insecure crypto usage "
        "3) Missing input validation 4) Authentication bypass 5) Authorization gaps "
        "6) Race conditions 7) Error handling that leaks sensitive info."
    )

    return "\n\n".join(parts)


# ============================================================
# Discovery targets — analysis areas rules CAN'T detect
# ============================================================

def _generate_discover_targets(
    project_root: str,
    project: dict,
    entry_points: list[dict],
    security_files: list[str],
    middleware_info: dict,
    archetype: str,
    existing_files: set[str],
    max_discover: int = 20,
) -> list[dict]:
    """Generate discovery targets based on code structure, not rule findings.

    These cover vulnerability classes that pattern-matching rules cannot detect:
    IDOR, authorization bypass, business logic flaws, crypto weaknesses,
    credential management, timing attacks, etc.
    """
    targets = []
    files_in_plan = set(existing_files)
    target_counter = [0]

    def _next_id() -> str:
        target_counter[0] += 1
        return f"D-{target_counter[0]:03d}"

    # --- 1. IDOR / Authorization analysis for API routes with params ---
    param_routes = []
    for ep in entry_points:
        content = ep.get("content", "")
        file_path = ep.get("file", "")
        if file_path in files_in_plan:
            continue
        # Routes with [id] or :id patterns are IDOR candidates
        if re.search(r"\[id\]|\[.*Id\]|:id|params.*id", file_path + content):
            param_routes.append(ep)

    if param_routes and archetype in ("web-app", "serverless"):
        # Group by file
        by_file: dict[str, list[dict]] = {}
        for ep in param_routes:
            by_file.setdefault(ep["file"], []).append(ep)

        for file_path, eps in sorted(by_file.items()):
            if file_path in files_in_plan:
                continue
            if len(targets) >= max_discover:
                break

            full_path = os.path.join(project_root, file_path) if not os.path.isabs(file_path) else file_path
            content = _read_file_safe(full_path)
            if not content:
                continue

            methods = [ep["content"][:80] for ep in eps[:5]]
            has_auth = bool(re.search(
                r"(getServerSession|getSession|requireAuth|checkAuth|withAuth|"
                r"auth\(\)|verifyToken|useSession|authenticate)",
                content, re.IGNORECASE,
            ))
            has_authz = bool(re.search(
                r"(checkPermission|authorize|hasAccess|isOwner|verifyOwnership|"
                r"where.*userId|member.*check|project\.members)",
                content, re.IGNORECASE,
            ))

            risk_desc = []
            if not has_auth:
                risk_desc.append("No authentication check detected")
            if not has_authz:
                risk_desc.append("No resource-level authorization (potential IDOR)")

            if not risk_desc:
                continue

            prompt = (
                f"IDOR / Authorization Analysis: {file_path}\n"
                f"Project type: {archetype}\n"
                f"Entry points: {len(eps)} handlers with path params\n"
                f"Handlers: {'; '.join(methods[:3])}\n\n"
                f"Risk indicators: {'; '.join(risk_desc)}\n\n"
                f"DISCOVERY ANALYSIS:\n"
                f"1. Read the full handler code for each HTTP method\n"
                f"2. Check if the route verifies the authenticated user has access to the requested resource\n"
                f"3. Look for patterns like: `findUnique({{ where: {{ id }} }})` without userId filter = IDOR\n"
                f"4. Check if EDITOR role can escalate to ADMIN role in member management\n"
                f"5. Verify ownership checks exist for all data modification endpoints\n"
                f"6. Report only CONFIRMED IDOR/authorization bypasses with specific exploit paths"
            )

            context = {
                "file": file_path,
                "imports": _extract_imports(content),
                "surrounding_code": content[:4000],
                "function_block": "",
                "file_lines": len(content.splitlines()),
                "language": _language_for_file(file_path),
                "archetype_context": "",
                "has_auth": has_auth,
                "has_authz": has_authz,
                "entry_points": len(eps),
            }

            targets.append({
                "target_id": _next_id(),
                "type": "discover_idor",
                "priority": "high" if not has_auth else "medium",
                "priority_score": 8 if not has_auth else 5,
                "file": file_path,
                "risks": ["idor-risk"] + (["missing-authentication"] if not has_auth else []),
                "context": context,
                "analysis_prompt": prompt,
            })
            files_in_plan.add(file_path)

    # --- 2. Credential / Config security ---
    env_files = _find_env_files(project_root)
    if env_files:
        env_prompt = (
            "Credential Security Analysis\n"
            f"Project type: {archetype}\n"
            f"Found .env files: {len(env_files)}\n\n"
            "DISCOVERY ANALYSIS:\n"
            "1. Check if .env contains REAL credentials (not just placeholders/examples)\n"
            "   - Real SMTP passwords, database passwords, API keys = CRITICAL\n"
            "   - Placeholder strings like 'change-me', 'your-key-here' = HIGH (weak defaults)\n"
            "2. Check if .env is committed to git (check .gitignore)\n"
            "3. Check if auth secrets (NEXTAUTH_SECRET, JWT_SECRET) are weak/placeholder values\n"
            "   - These allow session forgery if known\n"
            "4. Check encryption keys — are they placeholder/guessable?\n"
            "5. DO NOT display actual secret values in findings — reference them by variable name\n"
            "6. For each finding, specify the ENV variable name and its weakness (not the value)"
        )
        targets.append({
            "target_id": _next_id(),
            "type": "discover_credentials",
            "priority": "critical",
            "priority_score": 10,
            "file": ", ".join(env_files[:5]),
            "risks": ["hardcoded-credentials", "weak-secrets"],
            "context": {"env_files": env_files},
            "analysis_prompt": env_prompt,
        })

    # --- 3. Auth chain / middleware coverage ---
    if middleware_info.get("detected") and archetype in ("web-app", "serverless"):
        mw_file = middleware_info.get("file", "")
        if mw_file and mw_file not in files_in_plan:
            mw_prompt = (
                f"Auth Middleware Analysis: {mw_file}\n"
                f"Project type: {archetype}\n"
                f"Has auth check: {middleware_info.get('has_auth_check', False)}\n"
                f"Protected prefixes: {middleware_info.get('protected_prefixes', [])}\n"
                f"Excluded prefixes: {middleware_info.get('excluded_prefixes', [])}\n\n"
                "DISCOVERY ANALYSIS:\n"
                "1. Is the middleware function actually CONNECTED (exported as 'middleware')?\n"
                "   - If file is named proxy.ts instead of middleware.ts, it may not be active\n"
                "2. Which routes are NOT covered by the matcher config?\n"
                "3. Are there security headers (CSP, X-Frame-Options, HSTS)?\n"
                "4. Check token comparison — is it timing-safe (crypto.timingSafeEqual/hmac.compareDigest)?\n"
                "   - Using !== or != for token comparison = timing attack (CWE-208)\n"
                "5. Are webhooks/public routes properly excluded from auth?\n"
                "6. Report routes that bypass auth and access sensitive data"
            )
            targets.append({
                "target_id": _next_id(),
                "type": "discover_auth_chain",
                "priority": "high",
                "priority_score": 7,
                "file": mw_file,
                "risks": ["auth-bypass", "timing-attack", "missing-security-headers"],
                "context": middleware_info,
                "analysis_prompt": mw_prompt,
            })
            files_in_plan.add(mw_file)

    # --- 4. Crypto / Encryption analysis ---
    crypto_files = [sf for sf in security_files if re.search(
        r"(encrypt|decrypt|crypto|aes|hash|password|cipher)", sf, re.IGNORECASE,
    )]
    for sf in crypto_files[:3]:
        if sf in files_in_plan:
            continue
        if len(targets) >= max_discover:
            break

        full_path = os.path.join(project_root, sf) if not os.path.isabs(sf) else sf
        content = _read_file_safe(full_path)
        if not content:
            continue

        crypto_prompt = (
            f"Crypto Implementation Analysis: {sf}\n"
            f"Project type: {archetype}\n\n"
            "DISCOVERY ANALYSIS:\n"
            "1. Check for hardcoded keys, IVs, or salts\n"
            "2. Is there a fallback to insecure decryption? (e.g., plain base64 decode if format mismatch)\n"
            "3. Are weak algorithms used? (MD5 for security, ECB mode, SHA-1 for signatures)\n"
            "4. Is key derivation using proper KDF (PBKDF2/scrypt/Argon2) or single hash?\n"
            "5. Are encrypted values authenticated (GCM) or just encrypted (CBC without HMAC)?\n"
            "6. Check for timing-safe comparisons in MAC/tag verification"
        )
        context = {
            "file": sf,
            "imports": _extract_imports(content),
            "surrounding_code": content[:4000],
            "file_lines": len(content.splitlines()),
            "language": _language_for_file(sf),
        }
        targets.append({
            "target_id": _next_id(),
            "type": "discover_crypto",
            "priority": "high",
            "priority_score": 6,
            "file": sf,
            "risks": ["weak-crypto", "hardcoded-key"],
            "context": context,
            "analysis_prompt": crypto_prompt,
        })
        files_in_plan.add(sf)

    # --- 5. SSRF via user-controlled URLs (web-app specific) ---
    if archetype in ("web-app", "serverless"):
        ssrf_prompt = (
            f"SSRF Discovery Analysis\n"
            f"Project type: {archetype}\n\n"
            "DISCOVERY ANALYSIS: Find HTTP client calls where URL is NOT hardcoded.\n"
            "1. Search for: fetch(), axios.*, http.Get, http.Post where URL comes from:\n"
            "   - Database fields (user settings, API endpoints stored in DB)\n"
            "   - Request parameters (query params, body fields)\n"
            "   - Configuration that users can modify\n"
            "2. Check if there's URL allowlisting or internal IP filtering\n"
            "3. Can users configure AI API endpoints? → SSRF via baseURL\n"
            "4. Check webhooks — can users set webhook URLs to internal addresses?\n"
            "5. Report each SSRF with: source (where URL comes from) → sink (HTTP call)"
        )
        targets.append({
            "target_id": _next_id(),
            "type": "discover_ssrf",
            "priority": "high",
            "priority_score": 6,
            "risks": ["ssrf"],
            "context": {},
            "analysis_prompt": ssrf_prompt,
        })

    # --- 6. SQL injection / raw query analysis ---
    sql_files = [sf for sf in security_files if re.search(
        r"(query|sql|database|db|prisma|repository|secops)", sf, re.IGNORECASE,
    )]
    # Also include files with raw query patterns found by content scanning
    for sf in security_files:
        if sf in files_in_plan:
            continue
        full_path = os.path.join(project_root, sf) if not os.path.isabs(sf) else sf
        content = _read_file_safe(full_path)
        if content and RAW_QUERY_PATTERN.search(content) and sf not in sql_files:
            sql_files.append(sf)
    for sf in sql_files[:2]:
        if sf in files_in_plan:
            continue
        if len(targets) >= max_discover:
            break

        full_path = os.path.join(project_root, sf) if not os.path.isabs(sf) else sf
        content = _read_file_safe(full_path)
        if not content:
            continue

        # Check for raw query patterns
        has_raw = bool(re.search(
            r"\$queryRawUnsafe|\$executeRawUnsafe|raw\s*\(|\.raw\(",
            content, re.IGNORECASE,
        ))
        if not has_raw:
            continue

        sql_prompt = (
            f"SQL Injection Analysis: {sf}\n"
            f"Project type: {archetype}\n\n"
            f"Found raw query usage in this file.\n\n"
            "DISCOVERY ANALYSIS:\n"
            "1. Trace how user input reaches the raw query\n"
            "2. Is it parameterized ($1, ?) or string-concatenated?\n"
            "3. Even if parameterized, does the query structure allow information disclosure?\n"
            "4. For MongoDB/Redis: are users restricted to read-only operations?\n"
            "5. Report only if user-controlled data can influence the query structure"
        )
        context = {
            "file": sf,
            "imports": _extract_imports(content),
            "surrounding_code": content[:4000],
            "file_lines": len(content.splitlines()),
            "language": _language_for_file(sf),
        }
        targets.append({
            "target_id": _next_id(),
            "type": "discover_sql_injection",
            "priority": "high",
            "priority_score": 7,
            "file": sf,
            "risks": ["sql-injection"],
            "context": context,
            "analysis_prompt": sql_prompt,
        })
        files_in_plan.add(sf)

    # --- 7. CLI config / store security (for CLI tools) ---
    if archetype in ("cli-tool", "library"):
        config_files = [sf for sf in security_files if re.search(
            r"(config|store|resolve|secret|credential)", sf, re.IGNORECASE,
        )]
        # Also include secops/database files for query injection analysis
        for sf in security_files:
            if sf in files_in_plan:
                continue
            if re.search(r"secops|database.query", sf, re.IGNORECASE):
                if sf not in config_files:
                    config_files.append(sf)
        for sf in config_files[:5]:
            if sf in files_in_plan:
                continue
            if len(targets) >= max_discover:
                break

            full_path = os.path.join(project_root, sf) if not os.path.isabs(sf) else sf
            content = _read_file_safe(full_path)
            if not content:
                continue

            cli_config_prompt = (
                f"CLI Config Security Analysis: {sf}\n"
                f"Project type: {archetype}\n\n"
                "DISCOVERY ANALYSIS:\n"
                "1. Does the config resolver evaluate shell commands or expressions? (e.g., $(cmd))\n"
                "   - If config values can contain $(...), this is command injection (CWE-78)\n"
                "2. How is the encryption key derived? Is there a weak fallback?\n"
                "   - Single hash SHA-256(identity) = weak key derivation (CWE-327)\n"
                "3. Are file/directory permissions restrictive enough (0600/0700 vs 0755)?\n"
                "4. Is sensitive data (tokens, keys) stored securely? Encrypted at rest?\n"
                "5. Can config from untrusted sources (e.g., cloned repo .crush/crush.json)\n"
                "   trigger code execution?\n"
                "6. For database query files: Are Redis/MongoDB commands restricted?\n"
                "   - redis-cli accepts FLUSHALL, CONFIG SET → no read-only enforcement\n"
                "   - mongosh --eval executes arbitrary JavaScript\n"
                "7. Report confirmed issues with specific code references"
            )
            context = {
                "file": sf,
                "imports": _extract_imports(content),
                "surrounding_code": content[:4000],
                "file_lines": len(content.splitlines()),
                "language": _language_for_file(sf),
            }
            targets.append({
                "target_id": _next_id(),
                "type": "discover_cli_config",
                "priority": "high",
                "priority_score": 7,
                "file": sf,
                "risks": ["command-injection", "weak-key-derivation", "insecure-permissions"],
                "context": context,
                "analysis_prompt": cli_config_prompt,
            })
            files_in_plan.add(sf)

    return targets


def _find_env_files(target: str) -> list[str]:
    """Find .env files (paths only, content not read)."""
    env_files = []
    abs_target = os.path.abspath(target)
    for root, dirs, files in os.walk(abs_target):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in files:
            if f.startswith(".env") and not f.endswith(".example"):
                rel = os.path.relpath(os.path.join(root, f), abs_target)
                env_files.append(rel)
    return env_files


# ============================================================
# Finding prioritization
# ============================================================

def _finding_priority_score(finding: dict, archetype: str) -> int:
    """Score a finding for prioritization."""
    severity = finding.get("severity", "info")
    score = SEVERITY_RANK.get(severity, 0)

    tool = finding.get("tool", "")
    if tool in ("gitleaks",):
        score += 2  # High precision tool

    # CWE Top 25 bonus
    cwe = finding.get("cwe", [])
    if isinstance(cwe, list) and cwe:
        first_cwe = cwe[0]
    elif isinstance(cwe, str):
        first_cwe = cwe.split(",")[0].strip()
    else:
        first_cwe = ""

    CWE_TOP_25 = {
        "CWE-89", "CWE-79", "CWE-78", "CWE-20", "CWE-22",
        "CWE-352", "CWE-434", "CWE-502", "CWE-287", "CWE-798",
        "CWE-918", "CWE-94", "CWE-862", "CWE-284", "CWE-190",
        "CWE-476", "CWE-732", "CWE-639", "CWE-276", "CWE-327",
        "CWE-252", "CWE-400", "CWE-312", "CWE-532", "CWE-208",
    }
    if first_cwe in CWE_TOP_25:
        score += 1

    return score


# ============================================================
# Main: generate analysis plan
# ============================================================

def generate_analysis_plan(
    findings: list[dict],
    project: dict,
    project_root: str,
    config: dict | None = None,
) -> dict:
    """Generate LLM analysis plan with archetype-aware prompts."""
    if config is None:
        config = {}

    archetype = project.get("archetype", "library")
    llm_config = config.get("llm_orchestration", config.get("llm_analysis", {}))
    max_targets = llm_config.get("max_targets", MAX_TARGETS_DEFAULT)

    # Security file detection
    security_files = find_security_files(project_root)
    entry_points = find_entry_points(project_root)
    middleware_info = _find_middleware(project_root)

    # Deduplicate findings by file+line+rule
    seen: set[tuple[str, int, str]] = set()
    unique_findings = []
    for f in findings:
        key = (f.get("file", ""), f.get("start_line", 0), f.get("rule_id", ""))
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # Sort by priority
    scored_findings = [(f, _finding_priority_score(f, archetype)) for f in unique_findings]
    scored_findings.sort(key=lambda x: x[1], reverse=True)

    # Build analysis targets
    analysis_targets = []
    target_files_in_plan: set[str] = set()

    for finding, score in scored_findings[:max_targets]:
        file_path = finding.get("file", "")
        context = extract_finding_context(finding, project_root, archetype)
        prompt = _generate_analysis_prompt(finding, context, archetype)

        severity = finding.get("severity", "info")
        target_id = f"T-{len(analysis_targets) + 1:03d}"

        analysis_targets.append({
            "target_id": target_id,
            "type": "validate_finding",
            "priority": severity,
            "priority_score": score,
            "finding": finding,
            "context": context,
            "analysis_prompt": prompt,
        })
        target_files_in_plan.add(file_path)

    # Add security files not already covered
    security_limit = max(0, max_targets - len(analysis_targets))
    for sf in security_files[:security_limit]:
        if sf in target_files_in_plan:
            continue
        full_path = os.path.join(project_root, sf) if not os.path.isabs(sf) else sf
        content = _read_file_safe(full_path)
        if not content:
            continue

        context = {
            "file": sf,
            "imports": _extract_imports(content),
            "function_block": "",
            "surrounding_code": content[:3000] if len(content) <= MAX_FILE_SIZE_BYTES else content[:3000],
            "file_lines": len(content.splitlines()),
            "language": _language_for_file(sf),
            "archetype_context": "",
        }

        prompt = _generate_explore_prompt(sf, context, archetype)
        target_id = f"T-{len(analysis_targets) + 1:03d}"

        analysis_targets.append({
            "target_id": target_id,
            "type": "explore_area",
            "priority": "high",
            "priority_score": 3,
            "file": sf,
            "risks": ["sensitive-file"],
            "context": context,
            "analysis_prompt": prompt,
        })
        target_files_in_plan.add(sf)

    # --- Discovery targets (what rules CAN'T detect) ---
    discover_targets = _generate_discover_targets(
        project_root=project_root,
        project=project,
        entry_points=entry_points,
        security_files=security_files,
        middleware_info=middleware_info,
        archetype=archetype,
        existing_files=target_files_in_plan,
        max_discover=max_targets,
    )

    # Summarize findings
    tool_counts: dict[str, int] = Counter(f.get("tool", "unknown") for f in unique_findings)
    severity_counts: dict[str, int] = Counter(f.get("severity", "info") for f in unique_findings)

    plan = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "project_archetype": archetype,
        "project_context": {
            "languages": project.get("languages", {}),
            "frameworks": project.get("frameworks", []),
            "archetype": archetype,
            "has_middleware": middleware_info.get("detected", False),
            "entry_points_count": len(entry_points),
        },
        "rule_findings_summary": {
            "total": len(unique_findings),
            "by_tool": dict(tool_counts),
            "by_severity": dict(severity_counts),
        },
        "analysis_targets": analysis_targets,
        "discover_targets": discover_targets,
        "security_files": security_files,
        "middleware_info": middleware_info,
        "output_format": {
            "description": "Save findings to .claude/sast/results/llm-findings.json",
            "schema": {
                "tool": "llm-analyzer",
                "rule_id": "llm.<risk-type>",
                "title": "...",
                "severity": "critical|high|medium|low|info",
                "confidence": "high|medium|low",
                "file": "relative path",
                "start_line": 0,
                "end_line": 0,
                "message": "explanation",
                "cwe": ["CWE-XXX"],
                "owasp": ["A0X:2021-..."],
                "evidence": {"source": "...", "sink": "...", "dataflow": []},
                "recommendation": "fix guidance",
                "language": "...",
            },
        },
    }

    logger.info(
        "Analysis plan: archetype=%s, %d findings, %d targets, %d security files",
        archetype, len(unique_findings), len(analysis_targets), len(security_files),
    )

    return plan


def save_analysis_plan(plan: dict, output_dir: str) -> str:
    """Save analysis plan to JSON file."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "llm-analysis-plan.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(plan, fh, indent=2, default=str)
    return path
