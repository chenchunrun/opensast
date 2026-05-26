# OpenSAST Status And Usage

## Current Status

As of 2026-05-26, the repository has the following verified state:

- Rule coverage audit: `235 / 235 = 100%`
- Full local test suite: `270 passed, 7 skipped`
- External LLM findings can be imported into the main finding pipeline
- Reports, PR comments, gate summaries, and JSON output all expose:
  - finding origin
  - triage status
  - evidence strength
  - gate mode

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

## Command Maturity

- `/sast-scan`
  - Fully integrated execution path with runner, reports, gate, CI, enrichment, and external LLM findings import.
- `/sast-triage`
  - Now includes a structured triage helper for findings classification and report output.
- `/sast-fix`
  - Now includes a fix helper that resolves a finding, reads local context, generates structured remediation guidance, and can trigger a targeted re-scan.
- `/sast-baseline`
  - Now includes a baseline manager helper for create/update/show/suppress/unsuppress, but is not yet at `/sast-scan` parity for end-to-end productization.

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
python3 .claude/skills/sast-scan/tools/triage_findings.py --findings .claude/sast/results/findings.json --focus all
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

2. Triage

```bash
python3 .claude/skills/sast-scan/tools/triage_findings.py --findings .claude/sast/results/findings.json --focus all
```

3. Suppress accepted noise or known risk

```bash
python3 .claude/skills/sast-scan/tools/baseline_manager.py suppress --fingerprint <fingerprint> --reason "documented false positive"
```

4. Prepare remediation guidance for real issues

```bash
python3 .claude/skills/sast-scan/tools/fix_finding.py <finding-id-or-fingerprint> --test
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

## Known Limits

### Local Semgrep environment

On this machine, direct `semgrep --validate` / `semgrep --test` may fail because of a local certificate store issue:

- `ca-certs: empty trust anchors`

Repository tests already handle this by skipping unhealthy local Semgrep execution paths where appropriate. CI should still run in a healthy environment.

### LLM findings import

The runner now validates external `llm-findings.json`, but it does not generate those findings by itself. The producing step still needs to exist outside the runner or in a future integrated workflow.

## What To Trust

High confidence:

- rule coverage status
- normalization / dedup / baseline / gate / report chain
- gate mode behavior
- external LLM findings import and validation

Still environment-dependent:

- local Semgrep binary health
- availability of optional external tools
- CodeQL deep scan behavior on untrusted or partially buildable repositories
