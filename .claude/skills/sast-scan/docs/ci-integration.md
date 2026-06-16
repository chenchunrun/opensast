# CI Integration Guide

## Scope

**CI runs Layer 1 only** — `sast_runner.py` with `standard` (or `quick`) profile, `--fail-on`, and SARIF upload.

- **Do not** automate Claude API / Layer 2–3 analysis in CI. Run `/sast-scan` in a Claude Code session for LLM and Agent tiers.
- **`deep` profile** enables CodeQL and may execute package-manager builds. Use only on **trusted** repositories. Default CI workflows should use `standard`.
- Docker image (`Dockerfile.sast`) is a **rules-layer sidecar** for CI, not a full Skill runtime.

## GitHub Actions

A ready-to-use workflow is provided at `.github/workflows/sast.yml`.

For current capability status, gate mode behavior, and environment caveats, also read:

- `.claude/skills/sast-scan/docs/status-and-usage.md`

### Setup

1. Copy the workflow file to your repository:
   ```bash
   cp .github/workflows/sast.yml your-repo/.github/workflows/sast.yml
   ```

2. Ensure your repository has the Skill files:
   ```bash
   cp -r .claude/skills/sast-scan your-repo/.claude/skills/sast-scan
   ```

3. Push and the workflow runs on every PR and push to `main`.

### Configuration

The workflow uses `standard` profile and fails on `high` severity. Edit `sast.yml` to change:

```yaml
- name: Run SAST
  run: |
    python3 .claude/skills/sast-scan/tools/sast_runner.py \
      --target . \
      --profile standard \
      --format all \
      --fail-on high
```

### SARIF Upload

Findings are uploaded to GitHub code scanning via `github/codeql-action/upload-sarif@v3`. Results appear in the **Security** tab of your repository.

### Required Permissions

```yaml
permissions:
  security-events: write
  actions: read
  contents: read
```

## GitLab CI

### Basic Configuration

Add to `.gitlab-ci.yml`:

```yaml
sast:
  stage: test
  image: python:3.12-slim
  before_script:
    - apt-get update && apt-get install -y git curl
    - pip install --no-cache-dir pyyaml semgrep checkov
    - curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/install.sh | sh -s -- -b /usr/local/bin
  script:
    - >
      python3 .claude/skills/sast-scan/tools/sast_runner.py
      --target .
      --profile standard
      --format all
      --fail-on high
  artifacts:
    when: always
    paths:
      - .claude/sast/results/
    reports:
      sast: .claude/sast/results/merged.sarif
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### Docker image (rules-layer sidecar)

`Dockerfile.sast` runs `sast_runner.py` only — suitable for CI gates and SARIF upload.
It does **not** include Claude Code or LLM/Agent analysis. Use Skills in the IDE for Layer 2/3.

Build and use directly:

```yaml
sast:
  stage: test
  image: your-registry/opensast:latest
  script:
    - >
      --target .
      --profile standard
      --format all
      --fail-on high
  artifacts:
    when: always
    paths:
      - .claude/sast/results/
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan complete, no blocking findings |
| 1 | Scan complete, blocking findings found |
| 2 | Invalid arguments |
| 3 | Required tool missing |
| 4 | Scanner execution failed |
| 5 | Report generation failed |
| 6 | Configuration error |

## Java / C# deep analysis (CodeQL, not SpotBugs/Roslyn)

OpenSAST intentionally **does not** ship SpotBugs or Roslyn analyzer runners in the Skill layer. They require full build graphs, slow JVM/MSBuild pipelines, and duplicate what CodeQL already covers in `deep` profile.

| Language | Rules CI (`standard`) | Deep audit (`deep` + trusted repo) |
|----------|----------------------|-------------------------------------|
| Java | Semgrep + optional Bandit-style tools | **CodeQL** (primary inter-procedural engine) |
| C# | Semgrep custom rules | **CodeQL** (primary inter-procedural engine) |

Recommended paths:

```bash
# PR / nightly gate — rules only, no build required
python3 .claude/skills/sast-scan/tools/sast_runner.py . --profile standard --format all --fail-on high

# Release audit — trusted repo, enables CodeQL
/sast-scan . --profile deep --format sarif
```

In Claude Code sessions, combine `deep` rule signals with Layer 2/3 Skill analysis (`/sast-triage`, `/sast-fix`). Do **not** wire SpotBugs/Roslyn into default CI — use CodeQL for Java/C# inter-procedural coverage when builds are acceptable.

## Baseline in CI

To avoid failing on known issues, generate a baseline first:

```bash
# Generate baseline from current findings
python3 -c "
import sys; sys.path.insert(0, '.claude/skills/sast-scan/tools')
from baseline import generate_baseline, save_baseline
import json
findings = json.load(open('.claude/sast/results/findings.json'))
data = findings.get('findings', findings) if isinstance(findings, dict) else findings
bl = generate_baseline(data)
save_baseline('.claude/sast/baseline.json', bl)
"

# Commit the baseline file
git add .claude/sast/baseline.json
git commit -m "chore: add SAST baseline"
```

In CI, add `--baseline .claude/sast/baseline.json` to the runner command.
