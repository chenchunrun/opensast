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

# Multi-language SAST Scan (Rules + LLM + AI Agent Architecture)

You are running a three-tier SAST workflow combining rule engines, LLM analysis, and AI agent reasoning:

1. **Rule Engine** (Semgrep/Gitleaks/Checkov) — pattern matching for known vulnerability signatures
2. **LLM Analysis** (Claude structured discover) — 10 structured vulnerability class analyses
3. **AI Agent Review** (Claude free-form reasoning) — holistic security review with cross-module reasoning

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
- **You are the primary analyzer** — rule findings are INPUT, not final output.

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
7. Execute the three-tier analysis pipeline:

---

### Phase A: Quick-Dismiss Rule Findings

Read `.claude/sast/results/llm-analysis-plan.json`. For each `validate_finding` target:

- Read the `archetype_context` — this tells you if the pattern is normal or suspicious
- Read the `analysis_prompt` — follow the specific guidance
- Quick-dismiss obvious false positives (exec.Command in CLI tool, filepath.Join alone, etc.)
- Only do deep analysis for targets where the prompt suggests real risk
- Record dismissals in `dismissed_targets` with reason

---

### Phase B: Structured Security Discovery (10 discover types)

For each `discover_*` target in the plan, READ the actual code and analyze:

- `discover_idor`: Read API routes with path params. Check if `findUnique({ id })` has
  userId/ownership filter. If not, it's IDOR.
- `discover_credentials`: Read .env files. Real credentials? Placeholder secrets?
  Check pre-scanned `weakness_indicators`. Never display actual secret values.
- `discover_auth_chain`: Read middleware. Is it connected? Timing-safe comparison?
  If NO middleware exists, check individual routes for timing-unsafe token comparisons.
- `discover_crypto`: Hardcoded keys? Weak algorithms? Insecure fallback? Default salt?
- `discover_ssrf`: HTTP calls where URL comes from user-controlled sources. URL allowlisting?
- `discover_sql_injection`: Raw queries ($queryRawUnsafe, etc.). Parameterized or concatenated?
- `discover_csrf`: Write-method endpoints with cookie auth. CSRF token? Disabled in dev?
- `discover_rate_limiting`: Rate limiting coverage. Auth endpoints? IP spoofing? In-memory?
- `discover_mass_assignment`: Request body spreading into DB without field whitelisting.
- `discover_security_headers`: CSP, HSTS, X-Frame-Options, X-Content-Type-Options.
- `discover_config_security`: Placeholder secrets (change-me patterns). Debug flags? CORS *?
- `discover_cli_config`: Config resolver evaluates $(cmd)? Weak key derivation?
  Untrusted config from cloned repos? File permissions?
- `discover_global_sweep`: Cross-cutting: email XSS, header injection, legacy crypto,
  comment authorization, rate limiter IP spoofing.

---

### Phase C: AI Agent Security Review (Free-Form Reasoning)

This is the critical differentiator — a free-form AI agent review that catches what
structured checklists cannot. Structured discover types find known vulnerability classes,
but miss issues requiring **cross-module reasoning** and **intent understanding**.

**Execute Phase C AFTER Phase B** by spawning a security-reviewer agent:

```
Use the Agent tool with subagent_type="security-reviewer" to perform a holistic security review.
```

The agent prompt MUST include:

1. **Project context**: archetype (web-app / cli-tool / library / serverless), languages, frameworks
2. **Phase B findings summary**: a brief list of findings already discovered (so the agent avoids duplication)
3. **Instruction**: Find vulnerabilities NOT covered by the Phase B checklist. Focus on:
   - Cross-module data flows: how user/LLM input flows across files to dangerous sinks
   - Business logic flaws: authorization gaps that require understanding the application's intent
   - Implementation-specific weaknesses: SSH argument injection, command blocklist bypass,
     unbounded resource consumption, sensitive data in logs/audit trails
   - Interaction between components: how policy → permission → execution chain works together
   - Edge cases in the specific codebase that no generic checklist would catch
4. **Constraint**: Only report NEW findings not already found in Phase B. Each finding must have
   file:line, CWE, severity, and a TRUE/FALSE POSITIVE verdict.

**The agent prompt template** (adapt to project type):

```
You are the AI Agent security reviewer — the final analysis tier in a three-tier SAST pipeline.
You cover what structured checklists miss: cross-module reasoning, intent understanding, and
edge cases specific to this codebase.

Project: {project_root}
Archetype: {archetype}
Languages: {languages}
Frameworks: {frameworks}

Phase B findings already discovered (DO NOT re-report these):
{phase_b_findings_summary}

YOUR MISSION: Find security vulnerabilities that the structured Phase B analysis missed.
Focus on patterns that require cross-file reasoning or understanding code intent:

1. DATA FLOW CHAINS: Trace how user-controlled or LLM-generated data flows across multiple
   files/functions to reach a dangerous sink (command execution, file write, HTTP call, DB query).
   Phase B checks individual endpoints; you trace the full chain.

2. AUTHORIZATION GAPS IN BUSINESS LOGIC: Not just "does this route check auth?" but
   "does the authorization model have gaps when operations span multiple resources?"
   Example: Can a user with role X perform action Y that indirectly affects resource Z?

3. IMPLEMENTATION WEAKNESSES IN SECURITY CONTROLS: The security controls themselves may
   have flaws — blocklist bypass (path variants, encoding, variable indirection), race
   conditions in permission checks, bypass of risk assessment through obfuscation.

4. EDGE CASES SPECIFIC TO THIS CODEBASE: What makes THIS project unique? For a CLI tool:
   how does it handle untrusted config from cloned repos? For a web app: how does it handle
   multi-tenant data? For an API: how does pagination/filtering affect authorization?

5. RESOURCE MANAGEMENT: Unbounded downloads/uploads, memory exhaustion via large inputs,
   timeout bypass through slow trickle attacks, disk space exhaustion.

6. SENSITIVE DATA EXPOSURE: Data that appears in logs, audit trails, error messages,
   or API responses that should be redacted. Check for credentials in debug output,
   stack traces in error responses, or PII in telemetry.

For each finding report: severity (CRITICAL/HIGH/MEDIUM/LOW), CWE, file:line, and whether
it's a TRUE POSITIVE. Be specific — reference actual code, not theoretical risks.
```

---

### Phase D: Merge & Save Results

Save all findings to `.claude/sast/results/llm-findings.json`:
```json
{
  "project_archetype": "web-app",
  "llm_analysis_complete": true,
  "validate_targets_analyzed": 15,
  "discover_targets_analyzed": 19,
  "agent_review_complete": true,
  "findings_validated": 3,
  "findings_dismissed": 12,
  "findings_discovered": 27,
  "findings": [...],
  "dismissed_targets": [{"target_id": "T-003", "reason": "..."}],
  "analysis_notes": "Summary"
}
```

**Time budget**:
- Phase A: 10% (quick dismiss rule findings)
- Phase B: 50% (structured discover analysis)
- Phase C: 40% (AI agent free-form review — this is where the unique findings live)

---

8. If the user wants the LLM findings merged into the main pipeline, re-run `/sast-scan`
   with `--llm-findings .claude/sast/results/llm-findings.json`.
9. Explain the most important findings to the user, grouped by severity.
10. Highlight blocking issues based on the configured gate.
11. Provide remediation guidance with code examples.
12. Ask for explicit permission before applying any code changes.

## Scan profiles

| Profile | Use case | Tools | LLM | Agent |
|---------|----------|-------|-----|-------|
| quick | Pre-commit check | Semgrep + Gitleaks | No | No |
| standard | Regular scan | Semgrep + Gitleaks + Checkov | Phase A+B | Phase C |
| deep | Security audit | All tools + CodeQL | Phase A+B (deep) | Phase C |

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
