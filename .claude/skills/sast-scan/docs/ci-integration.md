# CI Integration Guide

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
    - python3 .claude/skills/sast-scan/tools/sast_runner.py
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

### With Docker Image

Build the included Dockerfile and use it directly:

```yaml
sast:
  stage: test
  image: your-registry/opensast:latest
  script:
    - --target .
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
