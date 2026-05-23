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
python3 -c "
import sys; sys.path.insert(0, '.claude/skills/sast-scan/tools')
from baseline import generate_baseline, save_baseline
import json
findings = json.load(open('.claude/sast/results/findings.json'))
data = findings.get('findings', findings) if isinstance(findings, dict) else findings
bl = generate_baseline(data)
save_baseline('.claude/sast/baseline.json', bl)
print(f'Baseline created with {len(bl[\"fingerprints\"])} entries')
"
```

### show
Display the current baseline:

```bash
python3 -c "
import sys; sys.path.insert(0, '.claude/skills/sast-scan/tools')
from baseline import load_baseline
import json
bl = load_baseline('.claude/sast/baseline.json')
print(f'Baseline: {len(bl[\"fingerprints\"])} known findings')
print(f'Suppressions: {len(bl.get(\"suppressions\", []))}')
"
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
