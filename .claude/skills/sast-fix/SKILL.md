---
name: sast-fix
description: Generate or apply security fixes for SAST findings using a three-tier workflow (template → LLM → verify). Use when the user asks to fix a specific vulnerability found by /sast-scan.
when_to_use: Use when the user asks to fix, remediate, or patch a SAST finding, or says "fix this vulnerability".
argument-hint: "<finding-id|fingerprint> [--apply] [--test] [--generate-test] [--create-branch] [--phase A|B|C]"
allowed-tools:
  - Read
  - Grep
  - Glob
  - Edit
  - Write
  - Bash
---

# SAST Finding Fix (Three-Tier Workflow)

Generate, apply, and verify security fixes for specific SAST findings using a three-tier approach:

1. **Phase A — Template Match** — keyword-based fix templates for 15 vulnerability classes
2. **Phase B — LLM Custom Fix** — Claude-generated fix for non-template or complex vulns
3. **Phase C — Verify** — targeted re-scan + validation + optional test generation

## Required input files

| File | Required | Purpose |
|------|----------|---------|
| `.claude/sast/results/findings.json` | Yes (or `llm-findings.json`) | Lookup finding by id/fingerprint |
| `.claude/sast/results/summary.json` | Optional | Scan profile context |

Resolve the target fingerprint from triage output or:

```bash
python3 .claude/skills/sast-scan/tools/session_status.py --results .claude/sast/results
```

## Input

User arguments:

```text
$ARGUMENTS
```

## Safety principles

- **Default mode**: Propose patches only, do NOT apply without explicit `--apply` flag.
- **Minimal change**: Fix only the security issue, no refactoring.
- **Preserve behavior**: The fix must not change existing business logic.
- **No new dependencies**: Unless the user explicitly approves.
- **Backup before apply**: Always create `.opensast-bak` backup before modifying files.
- **Rollback available**: `--rollback` restores the original file from backup.
- **Branch isolation**: `--create-branch` creates a git branch for fix isolation.

## Workflow

### Step 1: Run the fix helper

```bash
# Phase A: template-based fix (default)
python3 .claude/skills/sast-scan/tools/fix_finding.py <finding-id-or-fingerprint>

# Phase B: generate LLM fix prompt
python3 .claude/skills/sast-scan/tools/fix_finding.py <finding-id-or-fingerprint> --phase B

# Phase C: verify with re-scan
python3 .claude/skills/sast-scan/tools/fix_finding.py <finding-id-or-fingerprint> --test
```

### Step 2: Phase A — Template Match

Read findings from `.claude/sast/results/findings.json` or `.claude/sast/results/llm-findings.json`.

For each finding, the helper matches against 15 template categories:

| Category | CWE | Keywords |
|----------|-----|----------|
| SQL Injection | CWE-89 | sql, queryraw, select * |
| Command Injection | CWE-78 | subprocess, exec, shell=True |
| XSS | CWE-79 | innerhtml, render, template |
| Path Traversal | CWE-22 | ../, filepath, directory traversal |
| Deserialization | CWE-502 | pickle, yaml.load, unserialize |
| Hardcoded Secrets | CWE-798 | secret, credential, password |
| IDOR | CWE-639 | idor, ownership, access control |
| SSRF | CWE-918 | server-side request, fetch url |
| CSRF | CWE-352 | anti-forgery, xsrf |
| Rate Limiting | CWE-770 | throttle, brute force, dos |
| Mass Assignment | CWE-915 | whitelist, field binding, over-posting |
| Security Headers | CWE-693 | csp, hsts, x-frame |
| Crypto Weakness | CWE-321/330 | encrypt, decrypt, aes, salt |
| Timing Attack | CWE-208 | timing-safe, constant time |
| Config Security | CWE-426 | placeholder, change-me, cors * |

If a template matches, the fix guidance includes:
- Fix summary and steps
- Before/after code example
- Code context from the vulnerable file

### Step 3: Phase B — LLM Custom Fix

If the template is too generic (no keyword match) or the vulnerability is complex:

1. Run `--phase B` to generate an LLM fix prompt with code context.
2. Use Claude to analyze the prompt and generate a custom fix:
   - Read the vulnerable file with surrounding context (10 lines radius).
   - Identify the exact source-to-sink data flow.
   - Generate a minimal fix that addresses the specific vulnerability.
   - Provide a confidence score for fix correctness.
3. The custom fix should include:
   - `fix_summary`: What the fix does
   - `fix_steps`: Ordered steps to apply
   - `example_before` / `example_after`: Code diff showing the change
   - `confidence`: 0.0-1.0 score

### Step 4: Phase C — Verify

After applying a fix (or to verify a manual fix):

1. **Re-scan**: Run `--test` to re-scan the affected file/directory.
2. **Validate**: Compare findings before and after to confirm the issue is resolved.
3. **Generate test**: Run `--generate-test` to create a security regression test stub.
4. **Check for regressions**: Ensure no new findings were introduced.

```bash
# Verify fix with targeted re-scan
python3 .claude/skills/sast-scan/tools/fix_finding.py <id> --test --test-profile quick

# Generate test stub
python3 .claude/skills/sast-scan/tools/fix_finding.py <id> --generate-test
```

### Step 5: Apply (with explicit permission)

Only when the user provides explicit permission:

1. **Create branch** (recommended):
   ```bash
   python3 .claude/skills/sast-scan/tools/fix_finding.py <id> --create-branch
   ```

2. **Apply the fix** using Edit tool with the generated code change.

3. **Verify** with `--test` flag.

4. **Commit** with descriptive message.

5. **Rollback** if verification fails:
   ```bash
   python3 .claude/skills/sast-scan/tools/fix_finding.py <id> --rollback
   ```

## Fix templates by vulnerability type

### SQL Injection
- Replace f-string/format SQL with parameterized queries
- Use ORM if available
- Validate table/column names separately

### Command Injection
- Replace `shell=True` with argument arrays
- Use `shlex.quote()` if shell is unavoidable
- Prefer native APIs over subprocess

### XSS
- Use template engine auto-escaping
- Use `textContent` instead of `innerHTML`
- Set Content-Security-Policy headers

### Path Traversal
- Validate and normalize paths with `os.path.realpath`
- Ensure resolved path stays within allowed directory
- Use allowlist of permitted characters

### IDOR
- Add ownership/tenant filters to DB queries
- Use `find_first` with composite `where` clauses
- Check authorization at the data access layer

### SSRF
- Maintain explicit allowlist of permitted hosts
- Block private IP ranges (10.x, 172.16-31.x, 192.168.x)
- Prefer server-side URL construction

### CSRF
- Add CSRF token validation to state-changing endpoints
- Use SameSite cookie attribute
- Validate Origin/Referer headers

### Rate Limiting
- Apply per-IP and per-user rate limits
- Use persistent store (Redis) for counters
- Validate trusted proxy headers

### Mass Assignment
- Explicitly whitelist allowed fields
- Use DTO/pick schemas instead of spreading request body
- Reject unknown fields

### Timing Attack
- Use `hmac.compare_digest` or `crypto.timingSafeEqual`
- Ensure full-length comparison
- Avoid short-circuit evaluation

### Crypto Weakness
- Replace hardcoded keys with vault lookups
- Use authenticated encryption (AES-GCM)
- Generate unique salts per operation

### Config Security
- Replace placeholder secrets with env variable references
- Disable debug flags in production
- Restrict CORS to specific origins

## Output format

```markdown
# Fix for finding: <fingerprint>

## Vulnerability
- Type: ...
- Severity: CRITICAL/HIGH/MEDIUM/LOW
- Confidence: ...
- File: path/to/file:line
- CWE: CWE-<ID> (e.g., CWE-89 for SQL Injection)
- Phase: A/B/C

## Analysis
...

## Proposed fix
### Steps
- ...

### Example
```diff
- vulnerable code
+ fixed code
```

## Validation
- [ ] Fix applied
- [ ] Scan re-run
- [ ] Finding resolved
- [ ] No new findings introduced

## Generated test stub (if --generate-test)
```

## Remediation policy

Only propose patches unless the user explicitly asks to modify code.

When fixing:

1. Make the smallest safe change.
2. Preserve existing behavior.
3. Add or update tests when appropriate (`--generate-test`).
4. Re-run the relevant scan to verify (`--test`).
5. Summarize what changed.

## Integration with other skills

- **Input from**: `/sast-scan` findings, `/sast-triage` prioritized findings
- **Output to**: Git commit, test suite, `/sast-baseline` suppression (if fix is deferred)

## Next Skill (required at end of fix response)

```markdown
## Next steps
1. **Verify:** re-run with `--test` if not already done
2. **Quick re-scan:** `/sast-scan --changed-only --profile quick`
3. **Defer risk:** `/sast-baseline suppress --fingerprint <fp> --reason "accepted risk"`
```
