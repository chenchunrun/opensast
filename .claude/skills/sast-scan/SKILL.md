---
name: sast-scan
description: Run multi-language Static Application Security Testing for the current repository or selected paths. Use when the user asks to scan code for vulnerabilities, review security issues, analyze Git changes, generate SARIF, triage findings, or prepare CI security gates.
when_to_use: Use this skill for SAST, static code analysis, secure code review, vulnerability scanning, Semgrep, Gitleaks, Checkov, SARIF reports, CWE/OWASP mapping, and security fix recommendations.
argument-hint: "[target] [--profile quick|standard|deep] [--changed-only] [--format markdown|json|sarif|all] [--fail-on low|medium|high|critical]"
allowed-tools:
  - Read
  - Grep
  - Glob
  - "Bash(git status --short)"
  - "Bash(git diff --name-only *)"
  - "Bash(python3 .claude/skills/sast-scan/tools/sast_runner.py *)"
  - "Bash(python3 .claude/skills/sast-scan/tools/detect_project.py *)"
---

# Multi-language SAST Scan

You are running a controlled Static Application Security Testing workflow.

## Operating principles

- Treat the scan as a security-sensitive workflow.
- Do not read `.env`, private keys, credentials, or secret files unless the user explicitly authorizes it.
- Do not print raw secrets in the response.
- Prefer local scanning; do not upload code externally.
- Do not install tools automatically unless the user explicitly asks.
- Do not modify source code unless the user explicitly asks for remediation.
- If scanner output and code context disagree, explain the uncertainty.
- Prioritize actionable findings over noisy findings.

## Input

User arguments:

```text
$ARGUMENTS
```

If no target is provided, scan the current repository root (`.`).

## Workflow

1. Determine the scan target and profile from arguments.
2. Inspect the repository structure using `detect_project.py`.
3. Identify languages, frameworks, package managers, and IaC files.
4. Run the SAST wrapper with the requested profile:

```bash
python3 .claude/skills/sast-scan/tools/sast_runner.py $ARGUMENTS
```

5. Read the generated summary at `.claude/sast/results/summary.json`.
6. Read the generated report at `.claude/sast/results/report.md`.
7. Explain the most important findings to the user.
8. Highlight blocking issues based on the configured gate.
9. Provide remediation guidance with code examples.
10. Ask for explicit permission before applying any code changes.

## Scan profiles

| Profile | Use case | Tools | Time |
|---------|----------|-------|------|
| quick | Pre-commit check | Semgrep + Gitleaks | Seconds to 2 min |
| standard | Regular scan | Semgrep + Gitleaks + Checkov | 2-10 min |
| deep | Security audit | All tools + CodeQL | 10+ min |

## Finding explanation format

For each important finding, explain:

- **Title**: What was found
- **Severity**: critical / high / medium / low
- **Confidence**: How likely this is a real issue
- **File and line**: Where in the code
- **CWE / OWASP**: Standard vulnerability classification
- **Why it matters**: Business impact and exploitability
- **Evidence**: Source-to-sink data flow
- **Recommended fix**: Specific code change to resolve
- **Validation steps**: How to verify the fix works

## Remediation policy

Only propose patches unless the user explicitly asks to modify code.

When fixing:

1. Make the smallest safe change.
2. Preserve existing behavior.
3. Add or update tests when appropriate.
4. Re-run the relevant scan to verify.
5. Summarize what changed.

## Configuration

Default config: `.claude/skills/sast-scan/config/default.yml`
User config: `.claude/sast/config.yml`

User config overrides default config.

## CI integration

To generate GitHub Actions config, create `.github/workflows/sast.yml` based on the template in `.claude/skills/sast-scan/templates/ci-github-actions.yml`.
