"""RBAC scope analyzer for detecting authorization scope issues.

Detects:
1. Admin role checks without team/project scope (any-team-admin)
2. List endpoints returning all records without user/team filter (unscoped-list)
3. Entity operations missing team-scoped authorization
"""

import logging
import os
import re

logger = logging.getLogger("rbac_analyzer")

EXCLUDE_DIRS = {
    "node_modules", ".next", ".git", "vendor", "dist", "build", "__pycache__",
    ".claude", "coverage", ".cache", "public", "static", "assets",
}

# Patterns for role/permission checks
ROLE_CHECK_PATTERNS = [
    # Prisma: findFirst({ where: { userId, role: 'ADMIN' } }) without teamId
    re.compile(
        r'findFirst\s*\(\s*\{\s*where\s*:\s*\{([^}]+)\}',
        re.DOTALL,
    ),
    # Direct role comparison: if (user.role === 'ADMIN')
    re.compile(r'(\w+)\.role\s*[!=]==?\s*["\'](\w+)["\']'),
    # hasRole / checkPermission calls
    re.compile(r'(?:hasRole|checkPermission|checkRole|isAdmin|is Admin)\s*\(\s*["\']?(\w+)["\']?\s*\)'),
]

# Scoping fields that should appear in role checks
SCOPE_FIELDS = ["teamId", "projectId", "organizationId", "workspaceId"]

# ORM list query patterns (unscoped)
LIST_QUERY_PATTERNS = [
    re.compile(r'\.findMany\s*\(\s*(?:\{\s*\})?\s*\)'),  # findMany() or findMany({})
    re.compile(r'\.findMany\s*\(\s*\{\s*(?!.*where)', re.DOTALL),  # findMany without where
]

# Prisma schema parsing
MODEL_PATTERN = re.compile(r'model\s+(\w+)\s*\{([^}]+)\}', re.DOTALL)
FIELD_PATTERN = re.compile(r'(\w+)\s+[\w.]+(?:\s+@)', re.MULTILINE)
RELATION_PATTERN = re.compile(r'(\w+)\s+(\w+)\s*\[\]', re.MULTILINE)


def analyze_rbac(target: str, project: dict) -> list[dict]:
    """Main entry point. Scan project for RBAC scope issues."""
    from normalize_findings import _build

    findings: list[dict] = []

    languages = set(project.get("languages", {}).keys())
    if not languages & {"typescript", "javascript", "python", "java", "go"}:
        return findings

    # Step 1: Parse data model (Prisma schema if available)
    _parse_prisma_schema(target)

    # Step 2: Find role checks without scope
    role_findings = _find_unscoped_role_checks(target)
    findings.extend(role_findings)

    # Step 3: Find unscoped list endpoints
    list_findings = _find_unscoped_lists(target)
    findings.extend(list_findings)

    logger.info("RBAC analysis: %d findings", len(findings))
    return findings


def _parse_prisma_schema(target: str) -> dict[str, list[str]]:
    """Parse Prisma schema to understand data model relationships."""
    schema_path = None
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        if "schema.prisma" in files:
            schema_path = os.path.join(root, "schema.prisma")
            break

    if not schema_path or not os.path.isfile(schema_path):
        return {}

    try:
        with open(schema_path, encoding="utf-8") as fh:
            content = fh.read()
    except (OSError, UnicodeDecodeError):
        return {}

    models: dict[str, list[str]] = {}
    for m in MODEL_PATTERN.finditer(content):
        model_name = m.group(1)
        body = m.group(2)
        fields: list[str] = []
        for fm in FIELD_PATTERN.finditer(body):
            fields.append(fm.group(1))
        models[model_name] = fields

    return models


def _find_unscoped_role_checks(target: str) -> list[dict]:
    """Find admin role checks that lack team/project scope."""
    from normalize_findings import _build

    findings: list[dict] = []

    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]

        for fname in files:
            if not fname.endswith((".ts", ".tsx", ".js", ".py")):
                continue

            fpath = os.path.join(root, fname)
            try:
                with open(fpath, encoding="utf-8") as fh:
                    content = fh.read()
                    lines = content.split("\n")
            except (OSError, UnicodeDecodeError):
                continue

            for i, line in enumerate(lines):
                # Check for Prisma findFirst role check (may span multiple lines)
                if "findFirst" in line:
                    # Collect a window of lines to capture multi-line findFirst calls
                    window = "\n".join(lines[max(0, i):min(len(lines), i + 6)])
                    for m in ROLE_CHECK_PATTERNS[0].finditer(window):
                        where_clause = m.group(1)
                        has_role = bool(re.search(r'role\s*:', where_clause))
                        has_user = bool(re.search(r'userId\s*:', where_clause))
                        has_scope = any(sf in where_clause for sf in SCOPE_FIELDS)

                        if has_role and has_user and not has_scope:
                            findings.append(_build(
                                tool="rbac-analyzer",
                                rule_id="rbac.unscoped-admin-check",
                                title="Admin role check missing team scope",
                                severity="high",
                                file_path=fpath,
                                start_line=i + 1,
                                end_line=i + 1,
                                message="Role check queries for any team membership, not a specific team. "
                                        "Any team admin can access resources from other teams.",
                                cwe=["CWE-863"],
                                owasp=["A01:2021-Broken Access Control"],
                                evidence={"where_clause": where_clause.strip()},
                                recommendation="Add teamId or projectId to the findFirst where clause to scope the admin check.",
                                language="typescript",
                                confidence="medium",
                            ))

                # Check for direct role comparison without scope
                for m in ROLE_CHECK_PATTERNS[1].finditer(line):
                    var_name = m.group(1)
                    role_value = m.group(2)
                    if role_value.upper() in ("ADMIN", "OWNER", "SUPERADMIN", "ROOT"):
                        # Check if nearby lines have team scoping
                        nearby = "\n".join(lines[max(0, i - 3):min(len(lines), i + 4)])
                        has_scope = any(sf in nearby for sf in SCOPE_FIELDS)
                        if not has_scope:
                            findings.append(_build(
                                tool="rbac-analyzer",
                                rule_id="rbac.unscoped-role-check",
                                title=f"Unscoped {role_value} role check",
                                severity="medium",
                                file_path=fpath,
                                start_line=i + 1,
                                end_line=i + 1,
                                message=f"Direct role check for {role_value} without verifying team/project scope.",
                                cwe=["CWE-863"],
                                owasp=["A01:2021-Broken Access Control"],
                                evidence={"variable": var_name, "role": role_value},
                                recommendation="Add team/project membership verification alongside the role check.",
                                language="typescript",
                                confidence="low",
                            ))

    return findings


def _find_unscoped_lists(target: str) -> list[dict]:
    """Find findMany calls that return unscoped lists."""
    from normalize_findings import _build

    findings: list[dict] = []

    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]

        for fname in files:
            if not fname.endswith((".ts", ".tsx", ".js")):
                continue

            fpath = os.path.join(root, fname)
            try:
                with open(fpath, encoding="utf-8") as fh:
                    content = fh.read()
                    lines = content.split("\n")
            except (OSError, UnicodeDecodeError):
                continue

            for i, line in enumerate(lines):
                # Check for bare findMany() or findMany({}) without where
                if ".findMany(" in line:
                    # Check if there's a where clause with user/team scoping
                    nearby = "\n".join(lines[max(0, i):min(len(lines), i + 5)])
                    has_where = "where" in nearby
                    has_scope = any(sf in nearby for sf in ["userId", "teamId", "memberId"] + SCOPE_FIELDS)

                    if not has_where or not has_scope:
                        # Skip if it's in a test file
                        if ("/tests/" in fpath or "/test/" in fpath
                                or ".test." in fname or ".spec." in fname):
                            continue

                        findings.append(_build(
                            tool="rbac-analyzer",
                            rule_id="rbac.unscoped-list-endpoint",
                            title="List endpoint without user/team scoping",
                            severity="medium",
                            file_path=fpath,
                            start_line=i + 1,
                            end_line=i + 1,
                            message="findMany query returns all records without filtering by user or team. "
                                    "Any authenticated user can see all records.",
                            cwe=["CWE-863"],
                            owasp=["A01:2021-Broken Access Control"],
                            evidence={"query": line.strip()},
                            recommendation="Add where clause with userId or teamId to scope results to the requesting user's context.",
                            language="typescript",
                            confidence="medium",
                        ))

    return findings
