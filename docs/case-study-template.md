# Case Study Template (MarqDex / SecOpsCode / custom)

Use this template for **Skill session vs rules-only CI** comparisons. See also [skill-vs-ci-comparison.md](../../docs/skill-vs-ci-comparison.md) for reference numbers (MarqDex, SecOpsCode, OWASP).

## Metadata

| Field | Value |
|-------|-------|
| Project | |
| Archetype | web-app / cli-tool / library |
| Date | |
| Scanner profile | quick / standard / deep |
| Skill session? | yes / no (rules-only) |

## Results summary

| Layer | Findings | True positives | False positives | Complementary (other layer only) |
|-------|----------|----------------|-----------------|--------------------------------|
| Rules (Layer 1) | | | | |
| LLM structured (Layer 2) | | | | |
| Agent (Layer 3) | | | | |

## Timing

| Step | Duration |
|------|----------|
| Rule scan | |
| LLM Phase A–C | |
| Triage | |
| Fix + re-scan | |

## Notable complementary findings

1. 
2. 

## Repro commands

```bash
/sast-scan . --profile standard --format all
python3 .claude/skills/sast-scan/tools/session_status.py --results .claude/sast/results
```

## Honest limits

- Do not claim global FP rates; scope to this project and layer.
- Rules-only CI numbers ≠ full Skill session detection depth.
