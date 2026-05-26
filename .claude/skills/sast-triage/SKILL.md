---
name: sast-triage
description: Triage SAST findings - analyze false positives, prioritize by risk, and generate triage report. Use after running /sast-scan when findings need review.
when_to_use: Use when the user asks to triage SAST results, review findings, identify false positives, or prioritize security issues.
argument-hint: "[--findings path] [--focus critical|high|medium|low|all] [--output markdown|json]"
allowed-tools:
  - Read
  - Grep
  - Glob
---

# SAST Finding Triage

Analyze SAST scan results for false positives, prioritize by risk, and produce a triage report.

## Input

User arguments:

```text
$ARGUMENTS
```

## Workflow

1. Run the structured triage helper when possible:

```bash
python3 .claude/skills/sast-scan/tools/triage_findings.py --findings .claude/sast/results/findings.json --focus all --output markdown
```

2. Read the findings from `.claude/sast/results/findings.json` (or specified path).
3. For each finding, assess:
   - **False positive likelihood**: Is the input actually user-controlled? Is there a sanitizer?
   - **Exploitability**: Can an attacker actually reach this code path?
   - **Business impact**: What data or functionality is at risk?
   - **Confidence**: How certain is the scanner about this finding?
4. Categorize findings into:
   - **Priority**: critical/high issues that should block or be fixed first
   - **Important**: medium/low issues that are still actionable
   - **Needs Review**: not clearly false, but needs manual validation
   - **False Positive / Suppressed**: can be suppressed with evidence
   - **Informational**: low-value context
5. For true positives, suggest:
   - Priority order for fixing
   - Estimated effort (low/medium/high)
   - Whether it needs a code fix or configuration change
6. Output a triage summary.

## Output format

```markdown
# SAST Triage Report

## Summary
- Total findings: X
- True positives: X
- Likely false positives: X
- False positives: X

## Priority Fix List
1. [CRITICAL] Title — File:Line — Why it matters
2. [HIGH] Title — File:Line — Why it matters
...

## False Positive Analysis
1. Title — File:Line — Why it's likely FP

## Recommended Suppressions
- fingerprint: ... — Reason: ...
```

## Triage criteria

When evaluating false positives, consider:
- Is the source actually user-controlled? (request params, file uploads, API input)
- Is there a sanitizer or validator between source and sink?
- Is the code path reachable from an external entry point?
- Is the finding in test code or dead code?
- Does the framework provide built-in protection?

## Suppression recommendations

For findings you believe are false positives, generate suppression entries:

```json
{
  "fingerprint": "...",
  "reason": "Explanation of why this is a false positive",
  "owner": "triage-analyst",
  "expires_at": "2026-12-31"
}
```
