# SAST Scan - Multi-language Security Scanning Skill

Claude Code Skill for running Static Application Security Testing across multiple languages.

## Quick Start

```
/sast-scan .
/sast-scan src --profile quick
/sast-scan . --profile deep --format sarif
/sast-scan --changed-only --fail-on high
```

## Scan Profiles

| Profile | Speed | Tools | Use Case |
|---------|-------|-------|----------|
| quick | Seconds | Semgrep + Gitleaks | Pre-commit check |
| standard | 2-10 min | Semgrep + Gitleaks + Checkov | Regular scan |
| deep | 10+ min | All + CodeQL | Security audit |

## Supported Languages

P0: JavaScript/TypeScript, Python, Java/Kotlin, Go, C#
P1: C/C++, PHP, Ruby, Rust, Swift, Terraform/IaC

## Output Formats

- **Markdown** — Human-readable report with findings and fix suggestions
- **JSON** — Structured `findings.json` and `summary.json`
- **SARIF 2.1.0** — `merged.sarif` compatible with GitHub code scanning

## Configuration

Default: `.claude/skills/sast-scan/config/default.yml`
User override: `.claude/sast/config.yml`

## Tools Required

| Tool | Install | Required |
|------|---------|----------|
| Semgrep | `pip install semgrep` | Yes |
| Gitleaks | See [gitleaks docs](https://github.com/gitleaks/gitleaks) | Recommended |
| Checkov | `pip install checkov` | Optional (IaC) |
| CodeQL | See [codeql docs](https://codeql.github.com) | Optional (deep) |
| Bandit | `pip install bandit` | Optional (Python) |
| gosec | See [gosec docs](https://github.com/securego/gosec) | Optional (Go) |

Missing tools are gracefully skipped with a warning.

## Auxiliary Commands

| Command | Purpose |
|---------|---------|
| `/sast-triage` | Analyze false positives and prioritize findings |
| `/sast-fix <id>` | Generate or apply fix for a specific finding |
| `/sast-baseline` | Manage baseline suppressions |

## CI Integration

See [ci-integration.md](docs/ci-integration.md) for GitHub Actions and GitLab CI setup.
