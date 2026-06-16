# OpenSAST Minimal Examples

Three tiny vulnerable projects for trying `/sast-scan` in Claude Code.

| Example | Path | Expected rule hits (standard) |
|---------|------|-------------------------------|
| Python SQLi + command injection | `python-sqli/` | `python.security.*`, taint rules |
| Node XSS + command injection | `js-xss/` | `javascript.security.*`, taint rules |
| Go command injection | `go-cmdi/` | `go.security.*` |

## Try it

```bash
# From repo root in Claude Code
/sast-scan examples/python-sqli --profile quick --format all
/sast-scan examples/js-xss --profile quick --format all
/sast-scan examples/go-cmdi --profile quick --format all
```

## Expected artifacts

Each scan writes to `.claude/sast/results/`:

- `report.md` — top **Next Steps** section with triage/fix commands
- `findings.json` — normalized findings
- `summary.json` — `tool_outcomes`, `next_steps`

```bash
python3 .claude/skills/sast-scan/tools/session_status.py --results .claude/sast/results
```
