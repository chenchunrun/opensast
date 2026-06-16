# OpenSAST Quickstart (15 minutes)

## 1. Install (2 min)

```bash
pip install -r requirements.txt
pip install semgrep   # required
bash scripts/configure-sast-tools.sh   # optional: check supplemental tools
```

Copy skills into your project (or use this repo as-is):

```bash
cp -r .claude/skills/sast-scan your-repo/.claude/skills/sast-scan
cp -r .claude/skills/sast-triage your-repo/.claude/skills/sast-triage
cp -r .claude/skills/sast-fix your-repo/.claude/skills/sast-fix
cp -r .claude/skills/sast-baseline your-repo/.claude/skills/sast-baseline
```

## 2. First scan in Claude Code (5 min)

```bash
/sast-scan . --profile standard --format all
```

Read `.claude/sast/results/report.md` — top section lists **Next Steps**.

## 3. Session status (1 min)

```bash
python3 .claude/skills/sast-scan/tools/session_status.py --results .claude/sast/results
```

## 4. Triage and fix (5 min)

```bash
/sast-triage --findings .claude/sast/results/findings.json --bulk --repo-root .
/sast-fix <fingerprint> --test
```

## 5. CI gate (optional)

Copy `.github/workflows/sast.yml` — runs rule layer only (`standard`, `--fail-on high`).

**Note:** LLM / Agent analysis runs inside Claude Code Skill sessions, not in CI.
