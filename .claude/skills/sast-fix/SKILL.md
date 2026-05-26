---
name: sast-fix
description: Generate or apply security fixes for SAST findings. Use when the user asks to fix a specific vulnerability found by /sast-scan.
when_to_use: Use when the user asks to fix, remediate, or patch a SAST finding, or says "fix this vulnerability".
argument-hint: "<finding-id|fingerprint> [--apply] [--test]"
allowed-tools:
  - Read
  - Grep
  - Glob
  - Edit
  - Write
  - "Bash(python3 .claude/skills/sast-scan/tools/sast_runner.py *)"
  - "Bash(python3 .claude/skills/sast-scan/tools/fix_finding.py *)"
---

# SAST Finding Fix

Generate or apply security fixes for specific SAST findings.

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
- **Test after fix**: If `--test` flag is set, re-run the relevant scan after fixing.

## Workflow

1. Run the fix helper when possible:

```bash
python3 .claude/skills/sast-scan/tools/fix_finding.py <finding-id-or-fingerprint>
```

2. Read findings from `.claude/sast/results/findings.json`.
3. Locate the specific finding by ID or fingerprint.
4. Read the vulnerable code file and surrounding context.
5. Analyze the vulnerability:
   - What is the source of tainted data?
   - What is the dangerous sink?
   - What sanitization or validation is missing?
6. Generate a minimal fix:
   - Prefer parameterized queries over string formatting
   - Prefer allowlists over blocklists
   - Prefer safe APIs over dangerous ones
   - Add input validation when needed
7. If `--apply`: only enter explicit fix mode; the helper still produces guidance rather than editing files automatically.
8. If `--test`: re-run a targeted scan to verify the fix area.
9. Report the result.

## Fix templates by vulnerability type

### SQL Injection
- Replace f-string/format SQL with parameterized queries
- Use ORM if available

### Command Injection
- Replace `shell=True` with argument arrays
- Use `shlex.quote()` if shell is unavoidable
- Prefer native Python APIs over subprocess

### XSS
- Use template engine auto-escaping
- Use `markupsafe.escape()` for manual escaping
- Set Content-Security-Policy headers

### Path Traversal
- Validate and normalize paths with `os.path.realpath`
- Ensure resolved path stays within allowed directory
- Use allowlist of permitted characters

### Insecure Deserialization
- Replace `pickle`/`yaml.load` with safe alternatives
- Use `json` for data interchange
- Use `yaml.safe_load()` instead of `yaml.load()`

### Hardcoded Secrets
- Move to environment variables
- Use secret manager
- Update config to reference vault

## Output format

```markdown
# Fix for finding: <finding-id>

## Vulnerability
- Type: ...
- File: ...
- Line: ...

## Analysis
...

## Proposed fix
```diff
- vulnerable code
+ fixed code
```

## Validation
- [ ] Fix applied
- [ ] Scan re-run
- [ ] Finding resolved
```
