---
name: sast-baseline
description: Manage SAST scan baselines - create, update, or view baseline of known findings. Use to suppress accepted risks and focus on new issues.
when_to_use: Use when the user asks to manage SAST baselines, suppress findings, accept known risks, or review suppression lists.
argument-hint: "[create|update|show|suppress|unsuppress] [--fingerprint fp] [--reason text] [--output path]"
allowed-tools:
  - Read
  - Glob
  - "Bash(python3 .claude/skills/sast-scan/tools/sast_runner.py *)"
---

# SAST Baseline Management

Manage the baseline of known SAST findings to suppress accepted risks and focus on new issues.

## Input

User arguments:

```text
$ARGUMENTS
```

## Commands

### create
Generate a new baseline from the latest scan results:
```bash
python3 .claude/skills/sast-scan/tools/baseline_manager.py create
```

### show
Display the current baseline:

```bash
python3 .claude/skills/sast-scan/tools/baseline_manager.py show
```

### update
Refresh the baseline with the latest findings:

```bash
python3 .claude/skills/sast-scan/tools/baseline_manager.py update
```

### suppress
Add a suppression for a specific finding fingerprint:
- Requires `--fingerprint` and `--reason`
- Optional `--expires-at` for temporary suppressions

### unsuppress
Remove a suppression by fingerprint.

## Workflow

1. Parse the command from user arguments.
2. Execute the appropriate baseline operation.
3. Display results.

## Suppression policy

Suppressions should include:
- **reason**: Why the finding is accepted (false positive, accepted risk, mitigated elsewhere)
- **owner**: Who approved the suppression
- **expires_at**: When to re-review (mandatory for accepted risks, optional for false positives)

## Guidelines

- Never suppress findings without a documented reason.
- Prefer fixing over suppressing.
- Review suppressions quarterly.
- Temporary suppressions must have an expiry date.
- False positive suppressions should include evidence of why it's a FP.
