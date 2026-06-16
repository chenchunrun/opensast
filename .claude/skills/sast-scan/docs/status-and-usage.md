# OpenSAST Status And Usage

## Product positioning

OpenSAST is a **Claude Code native multi-layer SAST Skill platform**. CI runs Layer 1 (rules) for gating; Layer 2/3 (LLM + Agent) run inside Skill sessions, not as unattended CI jobs.

### When to use / when not to

| Scenario | Use | Notes |
|----------|-----|-------|
| Security review in Claude Code | ✅ Skills | `scan → triage → baseline → fix` |
| PR rule gate + SARIF | ✅ CI `standard` | `--fail-on`, no auto LLM |
| Trusted repo audit | ✅ `deep` + Skill | CodeQL may build |
| Unattended CI LLM analysis | ❌ | Out of scope |
| `deep` on untrusted repos | ❌ | Use `quick` / `standard` |
| Standalone SaaS console | ❌ | Out of scope |

## Current Status

As of 2026-06-16, the repository has the following verified state (auto-synced from `metrics_summary.py`):

<!-- metrics:auto:start -->
- Rule coverage audit: `269 / 269 = 100.0%`
- Full local test suite: `397 passed` (pytest collected count)
- Metrics snapshot: `python3 .claude/skills/sast-scan/tools/metrics_summary.py`
- OWASP Benchmark v1.2 (Java rules): **+39.6%** score (TPR 61.8%, FPR 22.3%)
<!-- metrics:auto:end -->

Regenerate this block:

```bash
python3 .claude/skills/sast-scan/tools/metrics_summary.py --sync-status-doc
```
- All four SAST skills at 100% maturity
- Reports, PR comments, gate summaries, and JSON output all expose:
  - finding origin
  - triage status
  - evidence strength
  - gate mode

## Skill Maturity

| Skill | Maturity | Workflow | Tests | Key Features |
|-------|----------|----------|-------|-------------|
| `/sast-scan` | 100% | Three-tier (Rules + LLM + AI Agent) | 277 | 13 discover types, 3-phase analysis, CI integration |
| `/sast-triage` | 100% | Three-phase (auto-bucket → LLM validate → recommend) | 15 | Confidence scoring, bulk triage, baseline export |
| `/sast-fix` | 100% | Three-tier (template → LLM → verify) | 38 | 15 templates, apply/rollback, git branch, test generation |
| `/sast-baseline` | 100% | Full lifecycle (10 commands) | 27 | diff, stats, audit, cleanup, import, audit trail |

## Closed Loops

The following chains are now covered end to end:

1. Rule findings
   - scanner SARIF -> normalize -> dedup -> baseline -> gate -> report

2. External LLM findings
   - `llm-findings.json` -> schema validation -> normalize -> dedup -> baseline -> gate -> report

3. Rule asset quality
   - rule discovery -> rule tests -> coverage audit -> CI artifact

4. Triage and review semantics
   - confidence / suppression / review status -> enrichment summary -> report / PR comment / gate mode

5. Fix lifecycle
   - template match → LLM custom fix → apply with backup → verify with re-scan → rollback if needed

6. Baseline lifecycle
   - create → suppress FPs → update → diff new findings → cleanup expired → audit trail

## Command Maturity

- `/sast-scan`
  - Three-tier architecture: Rules Engine → LLM Structured Analysis (13 discover types) → AI Agent Free-Form Review
  - Fully integrated execution path with runner, reports, gate, CI, enrichment, and external LLM findings import.

- `/sast-triage`
  - Three-phase triage: auto-bucket by severity → LLM validate TP/FP with confidence scoring → recommend fix priority and export FPs to baseline.
  - Supports bulk triage with code context enrichment.

- `/sast-fix`
  - Three-tier fix: template match (15 vulnerability classes) → LLM custom fix prompt → verify with targeted re-scan.
  - Supports `--apply` (with backup), `--rollback`, `--create-branch`, `--generate-test`.
  - 15 template categories: SQL Injection, Command Injection, XSS, Path Traversal, Deserialization, Hardcoded Secrets, IDOR, SSRF, CSRF, Rate Limiting, Mass Assignment, Security Headers, Crypto, Timing Attack, Config Security.

- `/sast-baseline`
  - 10 commands: create, update, show, suppress, unsuppress, diff, stats, audit, cleanup, import.
  - Audit trail records all suppression changes with timestamp, action, and owner.

## Results artifacts (`.claude/sast/results/`)

| File | Produced by | Key fields / purpose |
|------|-------------|----------------------|
| `summary.json` | `sast_runner.py` | `profile`, `tools_executed`, `tool_outcomes`, `next_steps`, `severity_counts`, `gate_result`, `llm_analysis_targets` |
| `findings.json` | `sast_runner.py` | Normalized findings + `analysis_enrichment` |
| `llm-analysis-plan.json` | `sast_runner.py` (`standard`/`deep`) | `session_id`, `completed_phases`, `analysis_targets`, `discover_targets` |
| `llm-findings.json` | Skill session (manual save) | Phase A–C output; import via `--llm-findings` |
| `report.md` | `sast_runner.py` | Human-readable report |
| `merged.sarif` | `sast_runner.py` | GitHub Code Scanning upload |

Session handoff:

```bash
python3 .claude/skills/sast-scan/tools/session_status.py --results .claude/sast/results
```

## Recommended Usage

### Local developer check

Use:

```bash
/sast-scan --changed-only --profile quick
```

This is the safest default for normal development flow.

Recommended follow-up:

```bash
python3 .claude/skills/sast-scan/tools/fix_finding.py <finding-id-or-fingerprint> --test
```

### Repository scan

Use:

```bash
/sast-scan . --profile standard --format all
```

This is the recommended default for most repositories.

Recommended follow-up:

```bash
# Triage with LLM validation
python3 .claude/skills/sast-scan/tools/triage_findings.py \
  --findings .claude/sast/results/findings.json --bulk --repo-root .

# Check baseline
python3 .claude/skills/sast-scan/tools/baseline_manager.py show
```

### Deep scan on trusted repositories

Use:

```bash
/sast-scan . --profile deep --format all
```

Only use this on repositories you trust. `deep` enables CodeQL and may need build context.

Recommended follow-up:

```bash
/sast-scan . --profile deep --format all --fail-on high
```

### Merge external LLM findings

Use:

```bash
/sast-scan . --llm-findings .claude/sast/results/llm-findings.json
```

Imported LLM findings are validated before merge. Invalid payloads are rejected.

## End-to-End Workflow

For a full repository review, the recommended sequence is:

1. Scan

```bash
/sast-scan . --profile standard --format all
```

2. Triage (with LLM validation)

```bash
python3 .claude/skills/sast-scan/tools/triage_findings.py \
  --findings .claude/sast/results/findings.json --bulk --repo-root .
```

3. Suppress accepted noise or known risk

```bash
python3 .claude/skills/sast-scan/tools/baseline_manager.py suppress \
  --fingerprint <fingerprint> --reason "documented false positive"
```

4. Fix real issues

```bash
# Template-based fix
python3 .claude/skills/sast-scan/tools/fix_finding.py <finding-id-or-fingerprint> --test

# LLM custom fix
python3 .claude/skills/sast-scan/tools/fix_finding.py <finding-id-or-fingerprint> --phase B

# Apply with branch isolation
python3 .claude/skills/sast-scan/tools/fix_finding.py <finding-id-or-fingerprint> --create-branch
```

5. Periodic baseline review

```bash
python3 .claude/skills/sast-scan/tools/baseline_manager.py stats
python3 .claude/skills/sast-scan/tools/baseline_manager.py cleanup
python3 .claude/skills/sast-scan/tools/baseline_manager.py audit
```

## Gate Modes

### Standard mode

Default behavior:

```yaml
gate:
  review_findings_blocking: false
```

- Confirmed blocking findings fail CI
- `needs-review` findings are advisory

### Strict mode

Enable:

```yaml
gate:
  review_findings_blocking: true
```

- Confirmed blocking findings fail CI
- `needs-review` findings also fail CI

## Supplemental Native Tools (auto-run when installed)

| Language | Tool | Runner | Notes |
|----------|------|--------|-------|
| Python | Bandit | `run_bandit.py` | Wired |
| Go | gosec | `run_gosec.py` | Wired |
| JS/TS | ESLint | `run_eslint_security.py` | Requires `package.json` |
| Ruby | Brakeman | `run_brakeman.py` | Wired |
| C/C++ | cppcheck | `run_cppcheck.py` | Wired |
| Rust | cargo-audit | `run_cargo_audit.py` | Requires `Cargo.toml` |
| Swift | SwiftLint | `run_swiftlint.py` | Wired |
| PHP | PHPStan | `run_phpstan.py` | Requires `vendor/bin/phpstan` |
| Java | SpotBugs | — | Use CodeQL `deep` profile instead |
| C# | Roslyn analyzers | — | Use CodeQL `deep` profile instead |

All supplemental tools skip gracefully when not installed (skill-friendly: no hard dependency).

## Known Limits

### Local Semgrep environment

On this machine, the default `semgrep` CLI entry path can still be fragile because of local trust-store and user-home assumptions:

- `ca-certs: empty trust anchors`
- default writes to `~/.semgrep/semgrep.log`

OpenSAST now works around this by:

- preferring `pysemgrep` when available
- forcing a writable `HOME` under the system temp directory (never inside rule trees)
- disabling metrics and version checks
- setting a stable certificate path when possible

With that runtime environment in place, the repository test suite now passes locally. The remaining risk is mainly for users who invoke `semgrep` directly outside the OpenSAST wrappers.

### LLM findings import

The runner now validates external `llm-findings.json`, but it does not generate those findings by itself. The producing step still needs to exist outside the runner or in a future integrated workflow.

## What To Trust

High confidence:

- rule coverage status
- normalization / dedup / baseline / gate / report chain
- gate mode behavior
- external LLM findings import and validation
- all four skills at feature parity with complete test coverage

Still environment-dependent:

- direct manual Semgrep CLI behavior outside the OpenSAST wrapper
- availability of optional external tools
- CodeQL deep scan behavior on untrusted or partially buildable repositories
