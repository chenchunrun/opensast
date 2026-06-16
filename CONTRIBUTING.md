# Contributing to OpenSAST

## Rule contributions

1. Add or edit rules under `.claude/skills/sast-scan/rules/semgrep/<language>/`.
2. Add matching fixtures in `<language>/tests/` with `# ruleid:` / `# ok:` (or `//` for C-style).
3. Run validation and tests:

```bash
python3 .claude/skills/sast-scan/tools/test_rules.py \
  --rules-dir .claude/skills/sast-scan/rules/semgrep \
  --test
```

4. Run corpus check (requires Semgrep):

```bash
python3 .claude/skills/sast-scan/tools/corpus_report.py
pytest tests/test_corpus.py -q
```

5. Run the full suite:

```bash
pytest tests/ -q
```

## Taint rules

- Use `taint-rules.yml` for cross-statement flows; keep syntactic rules in `rules.yml`.
- Document known limits (e.g. cross-file helpers) in rule comments.
- OWASP Benchmark regression: `python3 benchmark/run_owasp_benchmark.py` (Java, score ≥ +39.6%).

## Skill / docs changes

- Keep README, `status-and-usage.md`, and roadmap metrics aligned.
- Regenerate metrics block: `python3 .claude/skills/sast-scan/tools/metrics_summary.py`

## CI workflow templates

- **Rules gate:** `.claude/skills/sast-scan/templates/ci-github-actions-gate.yml`
- **Skill dev:** `.claude/skills/sast-scan/templates/ci-github-actions-skill-dev.yml`

## Pull requests

- One concern per PR when possible (rules vs Skill vs CI).
- Include test evidence in the PR description.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
