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

# Multi-language SAST Scan (LLM-Primary Architecture)

You are running an LLM-primary SAST workflow. Rule-based tools produce raw signals;
YOU (Claude) are the primary analyzer that validates, contextualizes, and enriches them.

## Operating principles

- Treat the scan as a security-sensitive workflow.
- Do not read `.env`, private keys, credentials, or secret files unless the user explicitly authorizes it.
- Do not print raw secrets in the response.
- Prefer local scanning; do not upload code externally.
- Do not install tools automatically unless the user explicitly asks.
- Do not modify source code unless the user explicitly asks for remediation.
- Treat deep CodeQL builds as trust-sensitive. Do not enable repository-local build commands unless the repository is trusted.
- If scanner output and code context disagree, explain the uncertainty.
- Prioritize actionable findings over noisy findings.
- **You are the primary analyzer** — rule findings are INPUT for your validation, not final output.

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
7. **LLM-Centered Analysis** — Read `.claude/sast/results/llm-analysis-plan.json`.

   This is the CORE analysis step. The plan contains TWO types of targets:
   - `analysis_targets` (type: `validate_finding`): Rule findings that need validation
   - `discover_targets` (type: `discover_*`): Security areas that rules CANNOT detect

   Process in this order:

   **Phase A: Quick-Dismiss Rule Findings** (`analysis_targets`)

   For each `validate_finding` target (process in priority order):
   - Read the `archetype_context` — this tells you if the pattern is normal or suspicious
   - Read the `analysis_prompt` — follow the specific guidance
   - Quick-dismiss obvious false positives (exec.Command in CLI tool, filepath.Join alone, etc.)
   - Only do deep analysis for targets where the prompt suggests real risk
   - Record dismissals in `dismissed_targets` with reason

   **Phase B: Independent Security Discovery** (`discover_targets`)

   This is where you add the most value — these are vulnerability classes that rules miss entirely:

   For each `discover_*` target, READ the actual code and analyze:
   - `discover_idor`: Read API routes with path params. Check if `findUnique({ id })` has
     userId/ownership filter. If not, it's IDOR — users can access other users' data.
   - `discover_credentials`: Read .env files. Are there REAL credentials (SMTP passwords,
     database passwords, API keys)? Are auth secrets using placeholder values?
     IMPORTANT: Never display actual secret values — reference by variable name only.
   - `discover_auth_chain`: Read middleware. Is it actually connected? Does it use
     timing-safe comparison? Are security headers present?
   - `discover_crypto`: Read encryption code. Hardcoded keys? Weak algorithms?
     Fallback to insecure decryption? Weak key derivation?
   - `discover_ssrf`: Find HTTP calls where URL comes from user-controlled sources
     (database settings, user input). Is there URL allowlisting?
   - `discover_sql_injection`: Find raw queries ($queryRawUnsafe, etc.).
     Is user input parameterized or concatenated?

   **Phase C: Save results** to `.claude/sast/results/llm-findings.json`:
   ```json
   {
     "project_archetype": "web-app",
     "llm_analysis_complete": true,
     "validate_targets_analyzed": 15,
     "discover_targets_analyzed": 8,
     "findings_validated": 3,
     "findings_dismissed": 12,
     "findings_discovered": 7,
     "findings": [...],
     "dismissed_targets": [{"target_id": "T-003", "reason": "..."}],
     "analysis_notes": "Summary"
   }
   ```

   **Time budget**: Spend 30% on Phase A (quick dismiss). Spend 70% on Phase B (real analysis).
   Phase B findings are the highest value — they find what no rule can.

8. If the user wants the LLM findings merged into the main pipeline, re-run `/sast-scan`
   with `--llm-findings .claude/sast/results/llm-findings.json`.
9. Explain the most important findings to the user, grouped by severity.
10. Highlight blocking issues based on the configured gate.
11. Provide remediation guidance with code examples.
12. Ask for explicit permission before applying any code changes.

## Scan profiles

| Profile | Use case | Tools | LLM Analysis |
|---------|----------|-------|-------------|
| quick | Pre-commit check | Semgrep + Gitleaks | No |
| standard | Regular scan | Semgrep + Gitleaks + Checkov | Yes (validate + discover) |
| deep | Security audit | All tools + CodeQL | Yes (deep validation + discover) |

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
