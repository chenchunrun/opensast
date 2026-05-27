"""Generate, apply, and verify security fixes for SAST findings.

Three-tier fix workflow:
  Phase A — Template match (keyword-based fix templates for known vuln classes)
  Phase B — LLM custom fix (Claude-generated fix for non-template vulns)
  Phase C — Verify (targeted re-scan + optional test generation)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from typing import Any


SKILL_DIR = os.path.dirname(os.path.dirname(__file__))
RUNNER_PATH = os.path.join(SKILL_DIR, "tools", "sast_runner.py")

# ---------------------------------------------------------------------------
# Extended fix templates covering all 13 discover types
# ---------------------------------------------------------------------------

FIX_TEMPLATES: list[tuple[tuple[str, ...], dict[str, Any]]] = [
    # SQL Injection (discover_sql_injection)
    (
        ("sql", "cwe-89", "queryraw", "select *", "queryrawunsafe"),
        {
            "summary": "Replace string-built queries with parameterized queries or ORM placeholders.",
            "fix_steps": [
                "Move user-controlled values out of SQL string interpolation.",
                "Use parameter binding supported by the database client or ORM.",
                "Validate identifiers separately if table or column names are dynamic.",
            ],
            "example_before": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
            "example_after": 'cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])',
        },
    ),
    # Command Injection (discover_global_sweep)
    (
        ("command", "shell=true", "subprocess", "exec", "cwe-78", "os.system"),
        {
            "summary": "Avoid shell interpretation and pass arguments as a fixed array.",
            "fix_steps": [
                "Replace shell command strings with explicit argument lists.",
                "Allowlist user-selectable subcommands or flags.",
                "Prefer native library APIs over shelling out when possible.",
            ],
            "example_before": 'subprocess.run(f"grep {user_input} file.txt", shell=True)',
            "example_after": 'subprocess.run(["grep", user_input, "file.txt"], check=True)',
        },
    ),
    # XSS (discover_global_sweep)
    (
        ("xss", "innerhtml", "render", "template", "cwe-79", "dangerouslysetinnerhtml"),
        {
            "summary": "Ensure untrusted data is escaped or rendered through safe templating primitives.",
            "fix_steps": [
                "Route output through framework auto-escaping where available.",
                "Avoid assigning user input directly to raw HTML sinks.",
                "Add contextual escaping for HTML, attribute, or JavaScript contexts.",
            ],
            "example_before": "element.innerHTML = userBio",
            "example_after": "element.textContent = userBio",
        },
    ),
    # Path Traversal
    (
        ("path traversal", "cwe-22", "../", "filepath", "open(", "directory traversal"),
        {
            "summary": "Normalize paths and enforce that resolved files stay within an allowed base directory.",
            "fix_steps": [
                "Resolve the candidate path with realpath/resolve.",
                "Compare the resolved path against an allowlisted base directory.",
                "Reject paths that escape the intended root or contain unexpected path segments.",
            ],
            "example_before": "open(os.path.join(base_dir, user_path))",
            "example_after": "candidate = os.path.realpath(os.path.join(base_dir, user_path))\nassert candidate.startswith(base_dir)",
        },
    ),
    # Deserialization
    (
        ("deserial", "pickle", "yaml.load", "unserialize", "cwe-502"),
        {
            "summary": "Replace unsafe deserialization with safe parsers and explicit schemas.",
            "fix_steps": [
                "Avoid general object deserialization for untrusted input.",
                "Use safe loader variants such as yaml.safe_load or typed JSON parsing.",
                "Validate the decoded structure before use.",
            ],
            "example_before": "data = yaml.load(body, Loader=yaml.Loader)",
            "example_after": "data = yaml.safe_load(body)",
        },
    ),
    # Hardcoded Secrets (discover_credentials, discover_config_security)
    (
        ("secret", "credential", "password", "token", "api key", "cwe-798", "hardcoded"),
        {
            "summary": "Move embedded secrets out of source code and into environment-backed secret management.",
            "fix_steps": [
                "Replace the hardcoded value with an environment or secret manager lookup.",
                "Fail closed if the secret is missing instead of falling back to insecure defaults.",
                "Rotate the exposed credential if it was ever real.",
            ],
            "example_before": 'SECRET_KEY = "dev-secret"',
            "example_after": 'SECRET_KEY = os.environ["SECRET_KEY"]',
        },
    ),
    # IDOR (discover_idor)
    (
        ("idor", "ownership", "cwe-639", "access control", "unauthorized access"),
        {
            "summary": "Bind record lookup or mutation to the authenticated principal, not only to a raw object identifier.",
            "fix_steps": [
                "Add ownership or tenant filters to record fetches and updates.",
                "Reject access when the resource does not belong to the caller.",
                "Keep authorization checks close to the data access boundary.",
            ],
            "example_before": "record = db.orders.find_unique(where={'id': order_id})",
            "example_after": "record = db.orders.find_first(where={'id': order_id, 'user_id': auth_user.id})",
        },
    ),
    # SSRF (discover_ssrf)
    (
        ("ssrf", "cwe-918", "server-side request", "fetch url", "internal network"),
        {
            "summary": "Validate and restrict outbound HTTP requests to prevent server-side request forgery.",
            "fix_steps": [
                "Maintain an explicit allowlist of permitted destination hosts/IPs.",
                "Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x).",
                "Prefer server-side URL construction over accepting raw URLs from users.",
            ],
            "example_before": "resp = requests.get(user_provided_url)",
            "example_after": "resp = requests.get(validate_url_against_allowlist(user_provided_url, ALLOWED_HOSTS))",
        },
    ),
    # CSRF (discover_csrf)
    (
        ("csrf", "cwe-352", "cross-site request", "anti-forgery", "xsrf"),
        {
            "summary": "Add CSRF token validation to all state-changing endpoints with cookie-based auth.",
            "fix_steps": [
                "Generate a cryptographically random CSRF token per session.",
                "Validate the token on every POST/PUT/DELETE/PATCH request.",
                "Use SameSite=Strict or Lax cookie attribute as defense-in-depth.",
            ],
            "example_before": "app.post('/api/transfer', transferHandler)",
            "example_after": "app.post('/api/transfer', csrfProtection, transferHandler)",
        },
    ),
    # Rate Limiting (discover_rate_limiting)
    (
        ("rate limit", "cwe-770", "throttl", "brute force", "dos"),
        {
            "summary": "Add rate limiting to all authentication and sensitive endpoints.",
            "fix_steps": [
                "Apply per-IP and per-user rate limits to login, registration, and password reset.",
                "Use a persistent store (Redis) for rate counters, not in-memory.",
                "Block spoofed IP headers (X-Forwarded-For) or validate against trusted proxies.",
            ],
            "example_before": "app.post('/api/login', loginHandler)",
            "example_after": "app.post('/api/login', rateLimit({ windowMs: 15*60*1000, max: 5 }), loginHandler)",
        },
    ),
    # Mass Assignment (discover_mass_assignment)
    (
        ("mass assignment", "cwe-915", "whitelist", "field binding", "over-posting"),
        {
            "summary": "Explicitly whitelist fields that may be set through request bodies.",
            "fix_steps": [
                "Define a strict allowlist of fields the user may modify.",
                "Strip or reject any fields not on the allowlist before DB write.",
                "Use DTO/pick schemas instead of spreading the entire request body.",
            ],
            "example_before": "user.update(**request.body)",
            "example_after": "allowed = {'name', 'email'}\nuser.update(**{k: v for k, v in request.body.items() if k in allowed})",
        },
    ),
    # Security Headers (discover_security_headers)
    (
        ("security header", "cwe-693", "csp", "hsts", "x-frame", "content-type-options"),
        {
            "summary": "Configure standard security headers to harden HTTP responses.",
            "fix_steps": [
                "Set Content-Security-Policy to restrict resource origins.",
                "Enable Strict-Transport-Security with a minimum 1-year max-age.",
                "Add X-Content-Type-Options: nosniff and X-Frame-Options: DENY.",
            ],
            "example_before": "// No security headers configured",
            "example_after": "app.use(helmet())  // Sets CSP, HSTS, X-Frame-Options, etc.",
        },
    ),
    # Crypto Weakness (discover_crypto)
    (
        ("crypto", "cwe-321", "cwe-330", "encrypt", "decrypt", "aes", "rsa", "hash", "salt"),
        {
            "summary": "Use strong, modern cryptographic primitives and proper key management.",
            "fix_steps": [
                "Replace hardcoded keys/salts with securely generated, per-deployment values.",
                "Use authenticated encryption (AES-GCM) instead of bare AES-CBC.",
                "Store keys in a vault or HSM, never in source code or config files.",
            ],
            "example_before": 'crypto.createCipheriv("aes-256-cbc", "hardcoded-key-123!", iv)',
            "example_after": 'crypto.createCipheriv("aes-256-gcm", getKeyFromVault("encryption-key"), iv)',
        },
    ),
    # Auth Chain / Timing Attack (discover_auth_chain)
    (
        ("timing", "cwe-208", "timing-safe", "constant time", "token comparison"),
        {
            "summary": "Use constant-time comparison for all secret/token validation.",
            "fix_steps": [
                "Replace == or === with hmac.compare_digest or crypto.timingSafeEqual.",
                "Ensure the comparison is applied to the full-length expected value.",
                "Avoid short-circuit comparison that leaks length information.",
            ],
            "example_before": 'if (token === expectedToken) { ... }',
            "example_after": 'if (crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expectedToken))) { ... }',
        },
    ),
    # Config Security / CLI Config (discover_config_security, discover_cli_config)
    (
        ("config", "cwe-426", "placeholder", "change-me", "default secret", "cors *"),
        {
            "summary": "Replace placeholder secrets and insecure defaults with proper configuration.",
            "fix_steps": [
                "Replace all change-me / default / placeholder secrets with real values from env or vault.",
                "Disable debug flags in production.",
                "Restrict CORS to specific origins instead of using wildcard.",
            ],
            "example_before": 'NEXTAUTH_SECRET = "change-me-secret"',
            "example_after": 'NEXTAUTH_SECRET = os.environ["NEXTAUTH_SECRET"]  # Must be set before deploy',
        },
    ),
]

GENERIC_TEMPLATE: dict[str, Any] = {
    "summary": "Validate the data flow, remove unsafe assumptions, and replace the sink with a safer primitive.",
    "fix_steps": [
        "Confirm the true source of attacker-controlled input.",
        "Add validation or authorization before the dangerous sink.",
        "Replace the risky API or pattern with a safer equivalent where possible.",
    ],
    "example_before": None,
    "example_after": None,
}


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def load_findings(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        findings = data.get("findings", [])
        return findings if isinstance(findings, list) else []
    return data if isinstance(data, list) else []


def find_finding(findings: list[dict], identifier: str) -> dict | None:
    for finding in findings:
        if identifier in {
            finding.get("id"),
            finding.get("fingerprint"),
            finding.get("fingerprint_v1"),
        }:
            return finding
    return None


def _fix_template(finding: dict) -> dict[str, Any]:
    haystack = " ".join(
        str(part or "")
        for part in [
            finding.get("rule_id"),
            finding.get("title"),
            finding.get("message"),
            " ".join(finding.get("cwe", [])),
        ]
    ).lower()

    for keywords, template in FIX_TEMPLATES:
        if any(keyword in haystack for keyword in keywords):
            return template

    return dict(GENERIC_TEMPLATE)


def read_code_context(repo_root: str, finding: dict, radius: int = 5) -> dict[str, Any]:
    rel_path = finding.get("file", "")
    if not rel_path:
        return {"path": None, "lines": []}
    abs_path = rel_path if os.path.isabs(rel_path) else os.path.join(repo_root, rel_path)
    if not os.path.isfile(abs_path):
        return {"path": abs_path, "lines": []}

    start_line = max(int(finding.get("start_line") or 1), 1)
    begin = max(1, start_line - radius)
    end = start_line + radius
    with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    excerpt = []
    for line_no in range(begin, min(end, len(lines)) + 1):
        excerpt.append(
            {
                "line": line_no,
                "text": lines[line_no - 1].rstrip("\n"),
                "highlight": line_no == start_line,
            }
        )
    return {"path": abs_path, "lines": excerpt}


# ---------------------------------------------------------------------------
# Phase A: Template-based fix
# ---------------------------------------------------------------------------

def build_fix_report(
    finding: dict,
    repo_root: str,
    apply_requested: bool = False,
    rerun_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    template = _fix_template(finding)
    context = read_code_context(repo_root, finding)
    location = f"{finding.get('file', '?')}:{finding.get('start_line', '?')}"

    return {
        "finding_id": finding.get("id"),
        "fingerprint": finding.get("fingerprint"),
        "title": finding.get("title") or finding.get("rule_id") or "Untitled finding",
        "rule_id": finding.get("rule_id"),
        "severity": finding.get("severity", "info"),
        "confidence": finding.get("confidence", "unknown"),
        "location": location,
        "message": finding.get("message", ""),
        "recommendation": finding.get("recommendation"),
        "cwe": finding.get("cwe", []),
        "apply_requested": apply_requested,
        "apply_supported": True,
        "phase": "A",
        "fix_summary": template["summary"],
        "fix_steps": template["fix_steps"],
        "example_before": template.get("example_before"),
        "example_after": template.get("example_after"),
        "context": context,
        "rerun": rerun_result,
    }


# ---------------------------------------------------------------------------
# Phase B: LLM-guided fix analysis
# ---------------------------------------------------------------------------

def generate_llm_fix_prompt(finding: dict, repo_root: str) -> dict[str, Any]:
    """Build a structured prompt for LLM-based fix generation.

    The caller (Claude via SKILL.md) uses this prompt to produce a custom fix
    when the Phase A template is too generic.
    """
    template = _fix_template(finding)
    context = read_code_context(repo_root, finding, radius=10)

    return {
        "finding": {
            "id": finding.get("id"),
            "fingerprint": finding.get("fingerprint"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "cwe": finding.get("cwe", []),
            "message": finding.get("message"),
            "file": finding.get("file"),
            "start_line": finding.get("start_line"),
        },
        "template_hint": {
            "summary": template["summary"],
            "steps": template["fix_steps"],
        },
        "code_context": context,
        "instructions": (
            "Generate a minimal, safe fix for this vulnerability. "
            "The fix must: (1) address only the security issue, "
            "(2) preserve existing business logic, "
            "(3) not introduce new dependencies without justification. "
            "Output: fix_summary, fix_steps, example_before, example_after, "
            "and a confidence score (0.0-1.0) for fix correctness."
        ),
    }


# ---------------------------------------------------------------------------
# Phase C: Verification helpers
# ---------------------------------------------------------------------------

def rerun_targeted_scan(
    repo_root: str,
    finding: dict,
    profile: str = "quick",
    output_dir: str | None = None,
) -> dict[str, Any]:
    lang = finding.get("language") or "auto"
    file_path = finding.get("file") or ""
    scan_target = repo_root
    if file_path:
        abs_file = file_path if os.path.isabs(file_path) else os.path.join(repo_root, file_path)
        if os.path.isfile(abs_file):
            scan_target = os.path.dirname(abs_file) or repo_root

    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="opensast-fix-rerun-")

    cmd = [
        sys.executable,
        RUNNER_PATH,
        scan_target,
        "--profile",
        profile,
        "--format",
        "json",
        "--output-dir",
        output_dir,
    ]
    if lang and lang != "unknown":
        cmd.extend(["--lang", lang])

    result = subprocess.run(cmd, capture_output=True, text=True)
    return {
        "command": cmd,
        "scan_target": scan_target,
        "output_dir": output_dir,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def validate_fix(
    findings_before: list[dict],
    findings_after: list[dict],
    fingerprint: str,
) -> dict[str, Any]:
    """Compare scan results before and after a fix to determine if the finding was resolved."""
    fp_before = {f.get("fingerprint") for f in findings_before}
    fp_after = {f.get("fingerprint") for f in findings_after}

    still_present = fingerprint in fp_after
    new_findings = [f for f in findings_after if f.get("fingerprint") not in fp_before]

    return {
        "fingerprint": fingerprint,
        "resolved": not still_present,
        "new_findings_count": len(new_findings),
        "new_findings": [
            {"fingerprint": f.get("fingerprint"), "title": f.get("title"), "severity": f.get("severity")}
            for f in new_findings
        ],
    }


# ---------------------------------------------------------------------------
# Apply helpers
# ---------------------------------------------------------------------------

def apply_fix(
    repo_root: str,
    finding: dict,
    fixed_content: str,
    backup_suffix: str = ".opensast-bak",
) -> dict[str, Any]:
    """Write a fix to the vulnerable file with automatic backup."""
    rel_path = finding.get("file", "")
    if not rel_path:
        return {"applied": False, "error": "No file path in finding"}

    abs_path = rel_path if os.path.isabs(rel_path) else os.path.join(repo_root, rel_path)
    if not os.path.isfile(abs_path):
        return {"applied": False, "error": f"File not found: {abs_path}"}

    backup_path = abs_path + backup_suffix

    # Create backup
    with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
        original = f.read()
    with open(backup_path, "w", encoding="utf-8") as f:
        f.write(original)

    # Write fix
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(fixed_content)

    return {
        "applied": True,
        "file": abs_path,
        "backup": backup_path,
        "original_size": len(original),
        "fixed_size": len(fixed_content),
    }


def rollback_fix(repo_root: str, finding: dict, backup_suffix: str = ".opensast-bak") -> dict[str, Any]:
    """Restore the original file from backup."""
    rel_path = finding.get("file", "")
    if not rel_path:
        return {"rolled_back": False, "error": "No file path in finding"}

    abs_path = rel_path if os.path.isabs(rel_path) else os.path.join(repo_root, rel_path)
    backup_path = abs_path + backup_suffix

    if not os.path.isfile(backup_path):
        return {"rolled_back": False, "error": f"Backup not found: {backup_path}"}

    with open(backup_path, "r", encoding="utf-8") as f:
        original = f.read()
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(original)
    os.remove(backup_path)

    return {"rolled_back": True, "file": abs_path, "backup_removed": True}


# ---------------------------------------------------------------------------
# Git branch helpers
# ---------------------------------------------------------------------------

def create_fix_branch(fingerprint: str) -> dict[str, Any]:
    """Create a git branch for fix isolation."""
    short_fp = fingerprint[:12] if fingerprint else "unknown"
    branch_name = f"sast-fix/{short_fp}"

    try:
        subprocess.run(["git", "checkout", "-b", branch_name], capture_output=True, text=True, check=True)
        return {"created": True, "branch": branch_name}
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        return {"created": False, "error": str(exc)}


def commit_fix(fingerprint: str, message: str) -> dict[str, Any]:
    """Stage and commit the fix on the current branch."""
    short_fp = fingerprint[:12] if fingerprint else "unknown"
    full_msg = message or f"fix: resolve SAST finding {short_fp}"

    try:
        subprocess.run(["git", "add", "-A"], capture_output=True, text=True, check=True)
        result = subprocess.run(
            ["git", "commit", "-m", full_msg],
            capture_output=True, text=True,
        )
        return {
            "committed": result.returncode == 0,
            "message": full_msg,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        return {"committed": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Test generation helpers
# ---------------------------------------------------------------------------

def generate_test_stub(finding: dict, repo_root: str) -> dict[str, Any]:
    """Generate a test stub skeleton for a vulnerability finding.

    The stub includes the test structure; the caller fills in the assertions.
    """
    lang = (finding.get("language") or "unknown").lower()
    file_path = finding.get("file", "")
    title = finding.get("title") or "vulnerability"
    severity = finding.get("severity", "high")
    cwe_list = finding.get("cwe", [])

    stub: dict[str, Any] = {
        "language": lang,
        "source_file": file_path,
        "cwe": cwe_list,
        "test_type": "security_regression",
    }

    if lang in ("python",):
        stub["test_code"] = _python_test_stub(file_path, title, severity, cwe_list)
    elif lang in ("typescript", "javascript", "ts", "js"):
        stub["test_code"] = _ts_test_stub(file_path, title, severity, cwe_list)
    elif lang in ("go",):
        stub["test_code"] = _go_test_stub(file_path, title, severity, cwe_list)
    elif lang in ("java",):
        stub["test_code"] = _java_test_stub(file_path, title, severity, cwe_list)
    else:
        stub["test_code"] = f"# TODO: Generate security regression test for {title} ({severity})"

    return stub


def _python_test_stub(file_path: str, title: str, severity: str, cwe_list: list[str]) -> str:
    cwe_tag = ",".join(cwe_list) if cwe_list else "unknown"
    return (
        f'"""Security regression test for: {title} (CWE: {cwe_tag})"""\n'
        f"import pytest\n"
        f"\n"
        f"\n"
        f"def test_{title.lower().replace(' ', '_').replace('-', '_')}_is_fixed():\n"
        f"    # Arrange: set up the malicious input that triggered the finding\n"
        f"    malicious_input = ...\n"
        f"\n"
        f"    # Act: call the vulnerable code path\n"
        f"    # result = vulnerable_function(malicious_input)\n"
        f"\n"
        f"    # Assert: verify the fix prevents exploitation\n"
        f"    # The vulnerability ({title}, {severity}) should NOT be exploitable\n"
        f"    assert False  # Replace with actual assertion\n"
    )


def _ts_test_stub(file_path: str, title: str, severity: str, cwe_list: list[str]) -> str:
    title_lower = title.lower()
    return (
        f"// Security regression test for: {title} ({severity})\n"
        f"// CWE: {', '.join(cwe_list) or 'unknown'}\n"
        f"describe('{title} security fix', () => {{\n"
        f"  it('should prevent {title_lower}', async () => {{\n"
        f"    // Arrange\n"
        f"    const maliciousInput = ...;\n"
        f"    // Act\n"
        f"    // const result = await vulnerableFunction(maliciousInput);\n"
        f"    // Assert\n"
        f"    // expect(result).toBe...;\n"
        f"    expect(true).toBe(true); // Replace with actual assertion\n"
        f"  }});\n"
        f"}});\n"
    )


def _go_test_stub(file_path: str, title: str, severity: str, cwe_list: list[str]) -> str:
    func_name = title.lower().replace(" ", "").replace("-", "")
    return (
        f"package security_test\n"
        f"\n"
        f"import \"testing\"\n"
        f"\n"
        f"// Security regression test for: {title} ({severity})\n"
        f"// CWE: {', '.join(cwe_list) or 'unknown'}\n"
        f"func Test{func_name.capitalize()}Fix(t *testing.T) {{\n"
        f"    // Arrange\n"
        f"    maliciousInput := ...\n"
        f"    // Act\n"
        f"    // result, err := vulnerableFunc(maliciousInput)\n"
        f"    // Assert\n"
        f"    t.Fatal(\"replace with actual assertion\")\n"
        f"}}\n"
    )


def _java_test_stub(file_path: str, title: str, severity: str, cwe_list: list[str]) -> str:
    class_name = title.replace(" ", "").replace("-", "")
    return (
        f"// Security regression test for: {title} ({severity})\n"
        f"// CWE: {', '.join(cwe_list) or 'unknown'}\n"
        f"public class {class_name}SecurityTest {{\n"
        f"    // @Test\n"
        f"    public void test{class_name}IsFixed() {{\n"
        f"        // Arrange\n"
        f"        String maliciousInput = ...;\n"
        f"        // Act\n"
        f"        // Assert\n"
        f"        // assertFalse(...);\n"
        f"    }}\n"
        f"}}\n"
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_markdown(report: dict[str, Any]) -> str:
    rerun = report.get("rerun") or {}
    lines = [
        f"# Fix for finding: {report['fingerprint'] or report['finding_id'] or report['rule_id']}",
        "",
        "## Vulnerability",
        f"- Type: {report['title']}",
        f"- Rule: {report.get('rule_id') or 'n/a'}",
        f"- Severity: {str(report['severity']).upper()}",
        f"- Confidence: {report['confidence']}",
        f"- File: {report['location']}",
        f"- CWE: {', '.join(report.get('cwe', [])) or 'n/a'}",
        f"- Phase: {report.get('phase', 'A')}",
        "",
        "## Analysis",
        report["message"] or "No additional scanner message provided.",
        "",
        "## Proposed fix",
        report["fix_summary"],
        "",
    ]

    if report["fix_steps"]:
        lines.append("### Steps")
        for step in report["fix_steps"]:
            lines.append(f"- {step}")
        lines.append("")

    if report["example_before"] or report["example_after"]:
        lines.extend(["### Example", "```text"])
        if report["example_before"]:
            lines.append(f"- {report['example_before']}")
        if report["example_after"]:
            lines.append(f"+ {report['example_after']}")
        lines.extend(["```", ""])

    context = report.get("context") or {}
    if context.get("lines"):
        lines.extend(["## Local context", "```text"])
        for item in context["lines"]:
            marker = ">" if item["highlight"] else " "
            lines.append(f"{marker} {item['line']:>4}: {item['text']}")
        lines.extend(["```", ""])

    apply_info = report.get("apply_info") or {}
    if apply_info.get("applied"):
        lines.extend([
            "## Applied",
            f"- File: `{apply_info['file']}`",
            f"- Backup: `{apply_info['backup']}`",
            f"- Original size: {apply_info['original_size']} bytes",
            f"- Fixed size: {apply_info['fixed_size']} bytes",
            "",
        ])

    validation = report.get("validation") or {}
    if validation:
        lines.extend([
            "## Fix validation",
            f"- Finding resolved: {'Yes' if validation.get('resolved') else 'No'}",
            f"- New findings introduced: {validation.get('new_findings_count', 0)}",
            "",
        ])

    lines.extend(
        [
            "## Validation",
            f"- [{'x' if report.get('apply_info', {}).get('applied') else ' '}] Fix applied",
            f"- [{'x' if rerun else ' '}] Scan re-run",
            f"- [{'x' if rerun.get('returncode') == 0 else ' '}] Re-scan passed without blocking errors",
            f"- [{'x' if validation.get('resolved') else ' '}] Finding resolved",
        ]
    )

    if rerun:
        command_str = " ".join(rerun["command"])
        lines.extend(
            [
                "",
                "### Re-scan result",
                f"- Command: `{command_str}`",
                f"- Exit code: {rerun['returncode']}",
                f"- Output dir: `{rerun['output_dir']}`",
            ]
        )

    if report.get("test_stub"):
        lines.extend(["", "## Generated test stub", "```", report["test_stub"], "```"])

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate, apply, or verify security fixes for OpenSAST findings")
    parser.add_argument("identifier", help="Finding id or fingerprint")
    parser.add_argument("--findings", default=".claude/sast/results/findings.json", help="Findings JSON path")
    parser.add_argument("--repo-root", default=".", help="Repository root for reading code context")
    parser.add_argument("--apply", action="store_true", help="Enter fix-apply mode")
    parser.add_argument("--test", action="store_true", help="Re-run a targeted scan after preparing the fix guidance")
    parser.add_argument("--generate-test", action="store_true", help="Generate a test stub for the finding")
    parser.add_argument("--create-branch", action="store_true", help="Create a git branch for the fix")
    parser.add_argument("--rollback", action="store_true", help="Rollback to the backup file")
    parser.add_argument("--test-profile", choices=["quick", "standard", "deep"], default="quick")
    parser.add_argument("--output", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--output-file", help="Optional report output path")
    parser.add_argument("--phase", choices=["A", "B", "C"], default="A", help="Fix phase: A=template, B=LLM prompt, C=verify")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    findings = load_findings(args.findings)
    finding = find_finding(findings, args.identifier)
    if not finding:
        parser.error(f"finding not found: {args.identifier}")

    repo_root = os.path.abspath(args.repo_root)

    if args.rollback:
        result = rollback_fix(repo_root, finding)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result.get("rolled_back") else 1

    if args.create_branch:
        result = create_fix_branch(finding.get("fingerprint", ""))
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result.get("created") else 1

    # Phase B: output LLM prompt
    if args.phase == "B":
        prompt = generate_llm_fix_prompt(finding, repo_root)
        output = json.dumps(prompt, indent=2, ensure_ascii=False)
        if args.output_file:
            with open(args.output_file, "w", encoding="utf-8") as f:
                f.write(output)
        else:
            print(output)
        return 0

    rerun_result = None
    if args.test:
        rerun_result = rerun_targeted_scan(repo_root, finding, profile=args.test_profile)

    report = build_fix_report(
        finding,
        repo_root=repo_root,
        apply_requested=args.apply,
        rerun_result=rerun_result,
    )

    if args.generate_test:
        stub = generate_test_stub(finding, repo_root)
        report["test_stub"] = stub.get("test_code", "")

    rendered = render_markdown(report) if args.output == "markdown" else json.dumps(report, indent=2, ensure_ascii=False)
    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as f:
            f.write(rendered)
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
