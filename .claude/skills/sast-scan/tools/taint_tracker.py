"""Lightweight single-file taint tracking for source-to-sink data flow detection."""

import logging
import os
import re
from collections import defaultdict

from normalize_findings import _build

logger = logging.getLogger(__name__)

# --- Source patterns (user input entry points) ---

SOURCES: dict[str, list[tuple[str, str]]] = {
    "javascript": [
        (r"req\.query\.(\w+)", "query parameter"),
        (r"req\.body\.(\w+)", "request body field"),
        (r"req\.params\.(\w+)", "URL parameter"),
        (r"params\.(\w+)", "URL parameter"),
        (r"request\.json\(\)", "parsed JSON body"),
        (r"searchParams\.get\(['\"](\w+)['\"]\)", "search parameter"),
        (r"request\.nextUrl\.searchParams\.get\(['\"](\w+)['\"]\)", "search parameter"),
        (r"\$REQ\.json\(\)", "parsed JSON body"),
        (r"formData\(\)", "form data"),
    ],
    "typescript": [
        (r"req\.query\.(\w+)", "query parameter"),
        (r"req\.body\.(\w+)", "request body field"),
        (r"req\.params\.(\w+)", "URL parameter"),
        (r"params\.(\w+)", "URL parameter"),
        (r"request\.json\(\)", "parsed JSON body"),
        (r"searchParams\.get\(['\"](\w+)['\"]\)", "search parameter"),
        (r"request\.nextUrl\.searchParams\.get\(['\"](\w+)['\"]\)", "search parameter"),
        (r"\$REQ\.json\(\)", "parsed JSON body"),
        (r"formData\(\)", "form data"),
    ],
    "python": [
        (r"request\.args\.get\(['\"](\w+)['\"]\)", "query parameter"),
        (r"request\.form\.get\(['\"](\w+)['\"]\)", "form field"),
        (r"request\.form\[['\"](\w+)['\"]\]", "form field"),
        (r"request\.json\.get\(['\"](\w+)['\"]\)", "JSON body field"),
        (r"request\.json\[['\"](\w+)['\"]\]", "JSON body field"),
        (r"request\.get_data\(\)", "raw body"),
        (r"request\.values\.get\(['\"](\w+)['\"]\)", "request value"),
    ],
    "java": [
        (r"request\.getParameter\(['\"](\w+)['\"]\)", "HTTP parameter"),
        (r"request\.getHeader\(['\"](\w+)['\"]\)", "HTTP header"),
        (r"request\.getInputStream\(\)", "request body"),
        (r"request\.getReader\(\)", "request body"),
    ],
    "go": [
        (r"r\.URL\.Query\(\)", "query string"),
        (r"r\.FormValue\(['\"](\w+)['\"]\)", "form value"),
        (r"r\.PostFormValue\(['\"](\w+)['\"]\)", "post form value"),
        (r"r\.URL\.Path", "URL path"),
    ],
    "php": [
        (r"\$_GET\[['\"](\w+)['\"]\]", "GET parameter"),
        (r"\$_POST\[['\"](\w+)['\"]\]", "POST parameter"),
        (r"\$_REQUEST\[['\"](\w+)['\"]\]", "request parameter"),
        (r"\$_FILES\[['\"](\w+)['\"]\]", "uploaded file"),
        (r"\$_SERVER\[['\"]QUERY_STRING['\"]\]", "query string"),
    ],
    "ruby": [
        (r"params\[:(\w+)\]", "Rails parameter"),
        (r"params\['(\w+)'\]", "Rails parameter"),
        (r"request\.parameters\[['\"](\w+)['\"]\]", "request parameter"),
    ],
    "c": [
        (r"getenv\(['\"](\w+)['\"]\)", "environment variable"),
        (r"argv\[(\d+)\]", "command-line argument"),
        (r"scanf\([^\"]*%s", "scanf input"),
    ],
    "cpp": [
        (r"getenv\(['\"](\w+)['\"]\)", "environment variable"),
        (r"argv\[(\d+)\]", "command-line argument"),
        (r"std::cin\s*>>\s*(\w+)", "stdin input"),
    ],
    "rust": [
        (r"std::env::args\(\)", "command-line argument"),
        (r"std::io::stdin\(\)", "stdin input"),
    ],
}

# --- Sink patterns (dangerous operations) ---

SINK_CATEGORIES: dict[str, dict] = {
    "sql": {
        "patterns": [
            (r"\.query\(`[^`]*\$\{[^}]+\}", "SQL query with interpolation"),
            (r"\.query\(['\"][^'\"]*'\s*\+\s*\w+", "SQL query with concatenation"),
            (r"\.execute\(`[^`]*\$\{[^}]+\}", "SQL execute with interpolation"),
            (r"\.execute\(['\"][^'\"]*'\s*\+\s*\w+", "SQL execute with concatenation"),
            (r"\.raw\(`[^`]*\$\{[^}]+\}", "raw SQL with interpolation"),
            (r"\$queryRaw\(`[^`]*\$\{[^}]+\}", "Prisma raw query with interpolation"),
            (r"cursor\.execute\(f['\"]", "Python f-string SQL"),
            (r"executeQuery\(['\"][^'\"]*'\s*\+\s*\w+", "Java SQL query with concat"),
            (r"Exec\(fmt\.Sprintf", "Go SQL with fmt.Sprintf"),
            (r"Query\(fmt\.Sprintf", "Go query with fmt.Sprintf"),
            (r"QueryRow\(fmt\.Sprintf", "Go query with fmt.Sprintf"),
            (r"mysqli_query\([^,]+,\s*['\"][^'\"]*'\s*\.\s*\w+", "PHP SQL with concat"),
            (r"\$CONN->query\(['\"][^'\"]*'\s*\.\s*\w+", "PHP PDO SQL with concat"),
            (r"\.where\(['\"][^'\"]*#\{", "Ruby SQL with interpolation"),
            (r"find_by_sql\(['\"][^'\"]*#\{", "Ruby SQL with interpolation"),
            (r"sprintf\(\w+,\s*['\"][^'\"]SELECT", "C/C++ SQL with sprintf"),
            (r"db\.execSQL\(['\"][^'\"]*'\s*\+\s*\w+", "Kotlin SQL with concat"),
        ],
        "cwe": ["CWE-89"],
        "owasp": ["A03:2021-Injection"],
        "title": "User input flows to SQL query without validation",
        "recommendation": "Use parameterized queries or ORM methods with placeholder arguments.",
    },
    "command": {
        "patterns": [
            (r"exec\(`[^`]*\$\{[^}]+\}", "command execution with interpolation"),
            (r"execSync\(`[^`]*\$\{[^}]+\}", "sync command execution with interpolation"),
            (r"exec\(['\"][^'\"]*'\s*\+\s*\w+", "command execution with concatenation"),
            (r"subprocess\.run\([^,]+,\s*shell\s*=\s*True", "subprocess with shell=True"),
            (r"subprocess\.call\([^,]+,\s*shell\s*=\s*True", "subprocess call with shell=True"),
            (r"os\.system\(", "os.system command execution"),
            (r"Runtime\.getRuntime\(\)\.exec\(", "Java runtime exec"),
            (r"exec\.Command\(['\"][^'\"]sh['\"]", "Go shell command execution"),
            (r"\bexec\s*\(\s*\$", "PHP exec with variable"),
            (r"\bsystem\s*\(\s*\$", "PHP system with variable"),
            (r"\bshell_exec\s*\(\s*\$", "PHP shell_exec with variable"),
            (r"\bsystem\s*\(['\"][^'\"]*#\{", "Ruby system with interpolation"),
            (r"`[^`]*#\{", "Ruby backtick with interpolation"),
            (r"\bsystem\s*\(\s*\w+\)", "C/C++ system call"),
            (r"\bpopen\s*\(\s*\w+\)", "C/C++ popen call"),
            (r"Command::new\(['\"][^'\"]sh['\"]", "Rust shell command"),
        ],
        "cwe": ["CWE-78"],
        "owasp": ["A03:2021-Injection"],
        "title": "User input flows to command execution",
        "recommendation": "Use array-form command arguments. Never pass user input to shell.",
    },
    "file": {
        "patterns": [
            (r"open\([^'\"]*\w+[^'\"]*,", "file open with variable path"),
            (r"os\.path\.join\([^'\"]*\w+", "path join with variable"),
            (r"readFile\([^'\"]*\w+[^'\"]*,", "readFile with variable path"),
            (r"writeFile\([^'\"]*\w+[^'\"]*,", "writeFile with variable path"),
            (r"new FileInputStream\(", "Java file input with variable"),
            (r"os\.Open\(filepath\.Join\(", "Go file open with join"),
            (r"os\.ReadFile\(filepath\.Join\(", "Go file read with join"),
        ],
        "cwe": ["CWE-22"],
        "owasp": ["A01:2021-Broken Access Control"],
        "title": "User input flows to file operation",
        "recommendation": "Validate and sanitize file paths. Use allowlists for permitted directories.",
    },
    "html": {
        "patterns": [
            (r"\.innerHTML\s*=\s*\w+", "innerHTML assignment"),
            (r"\.outerHTML\s*=\s*\w+", "outerHTML assignment"),
            (r"document\.write\(\w+", "document.write with variable"),
            (r"res\.send\(`[^`]*\$\{", "response send with interpolation"),
            (r"res\.write\(`[^`]*\$\{", "response write with interpolation"),
        ],
        "cwe": ["CWE-79"],
        "owasp": ["A03:2021-Injection"],
        "title": "User input flows to HTML output without escaping",
        "recommendation": "Escape output before rendering. Use textContent instead of innerHTML.",
    },
    "redirect": {
        "patterns": [
            (r"res\.redirect\(\w+\)", "response redirect with variable"),
            (r"NextResponse\.redirect\(\w+\)", "Next.js redirect with variable"),
            (r"redirect\(\w+\)", "redirect with variable"),
            (r"Response\.redirect\(\w+\)", "Response redirect with variable"),
            (r"HttpResponseRedirect\(\w+\)", "Django redirect with variable"),
        ],
        "cwe": ["CWE-601"],
        "owasp": ["A01:2021-Broken Access Control"],
        "title": "User input flows to redirect target",
        "recommendation": "Validate redirect URLs against an allowlist of permitted destinations.",
    },
}

# Validation/sanitization patterns (stop taint propagation)
SANITIZER_PATTERNS = [
    re.compile(r"\.safeParse\(", re.IGNORECASE),
    re.compile(r"\.parse\(", re.IGNORECASE),
    re.compile(r"sanitize\(", re.IGNORECASE),
    re.compile(r"escapeHtml\(", re.IGNORECASE),
    re.compile(r"DOMPurify\.sanitize\(", re.IGNORECASE),
    re.compile(r"encodeURIComponent\(", re.IGNORECASE),
    re.compile(r"parameterized|placeholders|\?\s*[,)]", re.IGNORECASE),
]

# Assignment pattern: var_name = expression
ASSIGN_RE = re.compile(r"(?:const|let|var|int|String|char|byte|long|float|double)\s+(\w+)\s*=\s*(.+)")
DESTRUCT_RE = re.compile(r"(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*(\w+(?:\.\w+)*)")

FILE_EXTENSIONS = {
    ".ts": "typescript", ".tsx": "typescript", ".js": "javascript", ".jsx": "javascript",
    ".py": "python", ".java": "java", ".go": "go",
    ".php": "php", ".rb": "ruby", ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp",
    ".cc": "cpp", ".rs": "rust", ".swift": "swift", ".kt": "kotlin",
}

EXCLUDE_DIRS = frozenset({
    "node_modules", ".next", ".git", "dist", ".venv", "__pycache__",
    ".cache", ".nuxt", ".turbo", "coverage", ".ruff_cache", "build",
})


def _detect_language(file_path: str) -> str | None:
    ext = os.path.splitext(file_path)[1].lower()
    return FILE_EXTENSIONS.get(ext)


def _find_source_files(target: str) -> list[str]:
    files = []
    abs_target = os.path.abspath(target)
    for root, dirs, filenames in os.walk(abs_target):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in filenames:
            if os.path.splitext(f)[1].lower() in FILE_EXTENSIONS:
                files.append(os.path.join(root, f))
    return files


def _extract_tainted_vars(line: str, line_no: int, lang: str) -> list[tuple[str, int, str]]:
    """Extract tainted variable names from a line that matches source patterns."""
    results = []
    for pattern, desc in SOURCES.get(lang, []):
        m = re.search(pattern, line)
        if m:
            if m.lastindex and m.group(1):
                var_name = m.group(1)
            else:
                var_name = m.group(0)
            results.append((var_name, line_no, desc))

    # Direct assignment from source: const x = req.query.name
    assign_match = ASSIGN_RE.match(line.strip())
    if assign_match:
        var_name = assign_match.group(1)
        expr = assign_match.group(2)
        for pattern, desc in SOURCES.get(lang, []):
            if re.search(pattern, expr):
                results.append((var_name, line_no, desc))

    # Destructuring: const { id, name } = req.query
    destruct_match = DESTRUCT_RE.match(line.strip())
    if destruct_match:
        fields = [f.strip() for f in destruct_match.group(1).split(",")]
        source_expr = destruct_match.group(2)
        for pattern, desc in SOURCES.get(lang, []):
            if re.search(pattern, source_expr):
                for field in fields:
                    field = field.split("=")[0].strip()
                    if field:
                        results.append((field, line_no, desc))

    return results


def _check_sink(line: str, tainted_vars: set[str], lang: str) -> list[tuple[str, str, str]]:
    """Check if a line contains a sink that uses a tainted variable."""
    findings = []
    for category, config in SINK_CATEGORIES.items():
        for pattern, desc in config["patterns"]:
            if re.search(pattern, line):
                for var in tainted_vars:
                    if re.search(r'\b' + re.escape(var) + r'\b', line):
                        findings.append((category, desc, var))
                        break
                if findings and findings[-1][0] == category:
                    break
    return findings


def _is_sanitized(line: str) -> bool:
    return any(p.search(line) for p in SANITIZER_PATTERNS)


def _get_lines(file_path: str) -> list[tuple[int, str]]:
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as fh:
            return [(i + 1, line) for i, line in enumerate(fh.readlines())]
    except OSError:
        return []


def _relative_path(file_path: str, target: str) -> str:
    try:
        return os.path.relpath(file_path, os.path.abspath(target))
    except ValueError:
        return file_path


def track_taint(file_path: str, lang: str | None = None) -> list[dict]:
    """Run single-file taint tracking. Returns list of findings."""
    if lang is None:
        lang = _detect_language(file_path)
    if lang is None:
        return []

    lines = _get_lines(file_path)
    if not lines:
        return []

    # Phase 1: Collect all tainted variables
    tainted: dict[str, tuple[int, str]] = {}  # var_name → (line_no, source_desc)
    for line_no, line in lines:
        for var_name, src_line, desc in _extract_tainted_vars(line, line_no, lang):
            tainted[var_name] = (src_line, desc)

    if not tainted:
        return []

    # Phase 2: Propagate through assignments
    for line_no, line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
            continue

        # Check if RHS references any tainted variable
        assign_match = ASSIGN_RE.match(stripped)
        if assign_match:
            lhs_var = assign_match.group(1)
            rhs = assign_match.group(2)
            if lhs_var not in tainted:
                for tvar in tainted:
                    if re.search(r'\b' + re.escape(tvar) + r'\b', rhs):
                        tainted[lhs_var] = (line_no, f"derived from {tvar}")
                        break

    # Phase 3: Find sinks that use tainted variables
    findings = []
    current_tainted = set(tainted.keys())

    for line_no, line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            continue

        if _is_sanitized(stripped):
            # Remove variables that are sanitized on this line
            for var in list(current_tainted):
                if re.search(r'\b' + re.escape(var) + r'\b', stripped):
                    current_tainted.discard(var)
            continue

        sink_hits = _check_sink(stripped, current_tainted, lang)
        for category, sink_desc, var in sink_hits:
            config = SINK_CATEGORIES[category]
            src_line_no, src_desc = tainted.get(var, (0, "unknown"))

            source_snippet = lines[src_line_no - 1][1].strip() if 0 < src_line_no <= len(lines) else ""
            sink_snippet = stripped

            dataflow = []
            if src_line_no > 0:
                dataflow.append({
                    "file": "",
                    "line": src_line_no,
                    "snippet": source_snippet,
                    "message": f"source: {src_desc}",
                })
            # Add intermediate assignments
            for tvar, (tlno, tdesc) in sorted(tainted.items(), key=lambda x: x[1][0]):
                if tlno > src_line_no and tlno < line_no and "derived" in tdesc:
                    dataflow.append({
                        "file": "",
                        "line": tlno,
                        "snippet": lines[tlno - 1][1].strip() if tlno <= len(lines) else "",
                        "message": tdesc,
                    })
            dataflow.append({
                "file": "",
                "line": line_no,
                "snippet": sink_snippet,
                "message": f"sink: {sink_desc}",
            })

            finding = _build(
                tool="taint-tracker",
                rule_id=f"taint.{category}",
                title=config["title"],
                severity="high",
                file_path=file_path,
                start_line=line_no,
                end_line=line_no,
                message=f"{src_desc} '{var}' flows to {sink_desc} without validation",
                cwe=config["cwe"],
                owasp=config["owasp"],
                evidence={
                    "source": source_snippet,
                    "sink": sink_snippet,
                    "dataflow": dataflow,
                },
                recommendation=config["recommendation"],
                language=lang,
                confidence="medium",
            )
            findings.append(finding)

    return findings


def track_project(target: str, project: dict) -> list[dict]:
    """Run taint tracking across all source files in a project."""
    source_files = _find_source_files(target)
    logger.info("Taint tracking: scanning %d source files", len(source_files))

    all_findings: list[dict] = []
    for fp in source_files:
        findings = track_taint(fp)
        if findings:
            rel = _relative_path(fp, target)
            for f in findings:
                f["file"] = rel
            all_findings.extend(findings)

    logger.info("Taint tracking: found %d data flow issues", len(all_findings))
    return all_findings
