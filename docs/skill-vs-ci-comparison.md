# Skill Session vs Rules-Only CI

This chapter documents **what CI can and cannot detect** compared to a full Claude Code Skill session. Use it when writing case studies or explaining OpenSAST to security stakeholders.

## Two operating modes

| Mode | Where it runs | Layers active | Typical profile |
|------|---------------|---------------|-----------------|
| **Rules-only CI** | GitHub Actions / GitLab / Docker sidecar | Layer 1 only | `standard`, `--fail-on high` |
| **Skill session** | Claude Code IDE | Layer 1 + 2 + 3 | `standard` or `deep` + `/sast-triage` + `/sast-fix` |

CI is a **gate and artifact archive**. Detection depth for auth chains, business logic, and cross-module flows lives in the Skill session.

## Reference comparison (published benchmarks)

Numbers below come from project benchmark reports. They are **project-specific**, not global FP rates.

### MarqDex (Next.js web app, ~30K LOC)

| Approach | Findings | True positives | False positives | Notes |
|----------|----------|----------------|-----------------|-------|
| Rules only (Layer 1) | 17 | 0 | 17 | 100% FP on this codebase |
| OpenSAST Skill (Layers 1–3) | 29 | 28 | 1 | ~3% FP at LLM-validated layer |
| Claude native scan | 27 | — | — | Fewer complementary auth/IDOR hits |

**Takeaway:** Rules-only CI would have blocked nothing useful and flooded review. The Skill session added validated business-logic findings rules missed entirely.

### SecOpsCode (CLI tool)

| Approach | Findings | Notes |
|----------|----------|-------|
| Rules + LLM Phase B | 11 | Structured discover coverage |
| + Agent (Layer 3) | +10 complementary | CLI argument parsing, cross-module paths |

**Takeaway:** Agent tier matters for non-web codebases where discover templates under-cover CLI patterns.

### OWASP Benchmark v1.2 (Java rules layer only)

| Metric | OpenSAST rules |
|--------|----------------|
| Benchmark score (TPR − FPR) | **+39.6%** |
| TPR | 61.8% |
| FPR | 22.3% |

Regenerate: `python3 benchmark/run_owasp_benchmark.py`

**Takeaway:** Rule layer has industry-benchmarked signal for Java injection/crypto categories; it is still not a substitute for Skill-layer triage on real repos.

## Same repository, two workflows

### A. CI rules gate (recommended default)

```yaml
# .github/workflows/sast.yml pattern
python3 .claude/skills/sast-scan/tools/sast_runner.py \
  --target . \
  --profile standard \
  --format all \
  --fail-on high
```

Produces: `findings.json`, `merged.sarif`, `report.md` (Layer 1). No LLM cost, fully reproducible.

### B. Developer Skill session (recommended for review)

```text
/sast-scan . --profile standard --format all
/sast-triage
/sast-fix <finding-id> --test
```

Check handoff state:

```bash
python3 .claude/skills/sast-scan/tools/session_status.py --results .claude/sast/results
```

Produces: `llm-analysis-plan.json`, `llm-findings.json`, triage buckets, optional fixes. Layer 2/3 artifacts can be merged back via `--llm-findings`.

## When to use which

| Goal | Use |
|------|-----|
| Block merges on known vulnerability classes | CI `standard` + baseline |
| Reduce alert fatigue before fix | Skill `/sast-triage` |
| Auth / IDOR / SSRF / business logic | Skill Layer 2 discover + Layer 3 Agent |
| Audit trail / compliance SARIF | CI upload + `--format sarif` |
| Java/C# inter-procedural (trusted repo) | Skill or CI `deep` + CodeQL — not SpotBugs/Roslyn runners |

## Document your own comparison

Copy [case-study-template.md](case-study-template.md) and fill the "Skill session? yes/no" column for both runs on the **same commit**.

Honest limits:

- Do not extrapolate MarqDex 3% FP to all projects.
- Rules-only numbers from CI ≠ full Skill detection depth.
- `deep` + CodeQL requires trusted repositories and build context.

## Single source for live metrics

```bash
python3 .claude/skills/sast-scan/tools/metrics_summary.py
python3 .claude/skills/sast-scan/tools/metrics_summary.py --sync-status-doc
```

Promotion slides and `status-and-usage.md` should cite numbers from this script, not hand-edited counts.
