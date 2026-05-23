# Rule Authoring Guide

## Semgrep Custom Rules

Custom Semgrep rules go in `.claude/skills/sast-scan/rules/semgrep/<language>/`.

### Rule Structure

```yaml
rules:
  - id: org.security.<language>.<category>.<specific-rule>
    languages: [python]
    severity: ERROR
    message: "Description of the vulnerability"
    metadata:
      category: security
      cwe:
        - "CWE-78"
      owasp:
        - "A03:2021-Injection"
      confidence: HIGH
      likelihood: MEDIUM
      impact: HIGH
      references:
        - "https://example.com/security-advisory"
    patterns:
      - pattern: dangerous_function(...)
      - pattern-not: dangerous_function("safe_constant", ...)
```

### Required Metadata

Every custom rule must include:

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier: `org.security.<lang>.<category>.<name>` |
| `languages` | Yes | Target language list |
| `severity` | Yes | `ERROR` (high), `WARNING` (medium), `INFO` (low) |
| `message` | Yes | Clear vulnerability description |
| `category` | Yes | Always `security` for SAST rules |
| `cwe` | Yes | CWE identifier(s) |
| `owasp` | Recommended | OWASP Top 10 mapping |
| `confidence` | Recommended | `HIGH`, `MEDIUM`, or `LOW` |

### Writing Patterns

Semgrep supports three matching modes:

```yaml
# Exact pattern match
patterns:
  - pattern: eval($INPUT)

# Negative match (exclude safe cases)
patterns:
  - pattern: subprocess.run($CMD, shell=True, ...)
  - pattern-not: subprocess.run("...", shell=True, ...)

# Taint tracking (source to sink)
mode: taint
pattern-sources:
  - pattern: request.args.get(...)
pattern-sinks:
  - pattern: subprocess.run(..., shell=True, ...)
```

### Testing Rules

Test files go in `.claude/skills/sast-scan/rules/tests/`:

```
rules/tests/
├── vulnerable/       # Files that SHOULD trigger the rule
│   └── test_cmd_injection.py
└── safe/             # Files that should NOT trigger the rule
    └── test_safe_subprocess.py
```

Each test must include:
1. At least one positive case (should trigger)
2. At least one negative case (should not trigger)
3. Expected line numbers
4. Fix suggestion as a comment

### Validating Rules

```bash
# Validate rule syntax
semgrep --validate --config .claude/skills/sast-scan/rules/semgrep/python/rules.yml

# Test against vulnerable code
semgrep --config .claude/skills/sast-scan/rules/semgrep/python/rules.yml tests/fixtures/vulnerable-python/

# Test against safe code (should find nothing)
semgrep --config .claude/skills/sast-scan/rules/semgrep/python/rules.yml rules/tests/safe/
```

## CWE/OWASP Mapping

### Common Mappings

| CWE | OWASP | Category |
|-----|-------|----------|
| CWE-78 | A03: Injection | OS Command Injection |
| CWE-79 | A03: Injection | XSS |
| CWE-89 | A03: Injection | SQL Injection |
| CWE-22 | A01: Broken Access Control | Path Traversal |
| CWE-787 | A04: Insecure Design | Buffer Overflow |
| CWE-502 | A08: Data Integrity | Deserialization |
| CWE-798 | A07: Auth Failures | Hardcoded Credentials |
| CWE-918 | A10: SSRF | Server-Side Request Forgery |

Full mapping table in `.claude/skills/sast-scan/config/language-map.yml`.

## Adding Rules for a New Language

1. Create directory: `rules/semgrep/<language>/`
2. Write rules following the structure above
3. Add positive test in `rules/tests/vulnerable/`
4. Add negative test in `rules/tests/safe/`
5. Validate with `semgrep --validate`
6. Run against test fixtures
