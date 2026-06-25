# OpenSAST — Backlog Issues

Actionable work items derived from the end-to-end assessment (install → scan →
triage → fix). Each item is written as a ready-to-file GitHub issue (title,
labels, body) so they can be created with `gh issue create` once authenticated.

These complement the high-level phased plan in
[`roadmap-claude-sast-platform.md`](./roadmap-claude-sast-platform.md): that doc
describes *direction*, this doc tracks *concrete tickets*.

> **Status legend:** ✅ done this session · 🔧 in progress · 📋 open

---

## ✅ Bug — `triage_findings.py` crashes in `--bulk` (missing `import os`)

- **Labels:** `bug`, `tooling`
- **Fixed:** added `import os` (used by `os.path.abspath` in `bulk_triage`).
- **Also found & fixed a sibling latent crash:** `detect_project.py` used
  `sys.argv`/`sys.stderr`/`sys.exit` in its `__main__` block without
  `import sys` → NameError when run as a script. Added `import sys`.
- **Hardening follow-up:** add a CI lint that imports every module in
  `tools/` and smoke-runs each `__main__` entry point so missing imports are
  caught before merge.

---

## ✅ Bug — `sast_runner.py` exit-code / "CI gate" messaging (P2)

- **Labels:** `bug`, `ux`, `tooling`
- **Symptom:** `--profile standard` exited `1` on any HIGH+ finding and printed
  "CI gate FAILED/PASSED" even in a local, interactive scan.
- **Fixed:** gate enforcement is now scenario-aware.
  - New `is_ci_environment()` detects CI via `CI`, `GITHUB_ACTIONS`,
    `GITLAB_CI`, `JENKINS_HOME`, `BUILDKITE`, `CIRCLECI`, `TF_BUILD`.
  - New `--ci` flag forces gate enforcement locally (opt-in).
  - Gate is enforced (non-zero exit) **only** when in CI, `--ci` is set, or
    `--fail-on` is explicitly passed. Otherwise findings are reported but the
    process exits 0 with guidance ("would fail CI — re-run with --ci").
  - Wording dropped the unconditional "CI gate" prefix for local runs.
- **Tests:** added `test_is_ci_environment_detects_ci`; existing
  `test_run_merges_external_llm_findings_end_to_end` (explicit `fail_on="high"`)
  still asserts exit 1 deterministically.

---

## ✅ Rule precision — HIGH-severity false positives (P1, most severe)

- **Labels:** `rules`, `false-positive`, `precision`
- **Symptom:** end-to-end scan had >60% FP rate at HIGH severity.
- **Fixed this session (JavaScript):**

| Rule | Before | Root cause | Fix |
|------|:------:|-----------|-----|
| `js.security.hardcoded-iv` | 8/8 FP | `let $IV = "..."` matched any string literal incl. `''` | Require the value to be 16+ hex chars; empty/short strings no longer match |
| `javascript.security.eval-usage` | FP | `setTimeout($VAR,...)` / `setInterval($VAR,...)` treated as eval | Removed timers from the rule — function-arg timers are not eval |
| `javascript.security.ssrf-fetch` | 7/7 FP | `$CLIENT.get($USER_INPUT)` matched `Map.get`/`ref.current.get` | Replaced generic client with named HTTP clients (fetch, axios, got, http, https, request) |
| `javascript.security.deserialize-unsafe` | FP | `JSON.parse` flagged as CWE-502 | Removed `JSON.parse` (parses data only, no code execution); kept real RCE sink `serialize.unserialize` |

- **Verification:** regression target of the exact FP patterns → **0 findings**;
  positive control of real vulns → all 4 classes still fire (8 findings). All
  fixtures green (`semgrep --test`).

### 📋 Open — Systematic FP reduction (structural)

- **Labels:** `rules`, `false-positive`, `enhancement`
- Apply the same "data-flow context, not just AST shape" discipline across the
  other language rule sets (Python, Java, Go, PHP, Ruby, C#). Repeat the
  end-to-end FP-rate measurement on the same real target and track the number.
- Add a **FP baseline** mechanism: after a confirmed-FP set, auto-suppress
  matching fingerprints so they don't re-surface every scan.
- Add rule **modes**: `--strict` / `--conservative` (default) / `--noisy`, so
  teams can trade recall for precision. Map confidence/precision metadata to
  the default mode.

---

## 📋 Issue — Install experience & Python-version compatibility

- **Labels:** `install`, `ux`
- On Python 3.14 + PEP 668, `pip install semgrep` fails to locate a wheel;
  requires `pipx` or `brew`. Dependency install does not detect Python version.
- **Proposal:** ship `install.sh` that:
  - detects Python version and picks `pipx` / `brew` / `venv` automatically,
  - installs the core scanner (semgrep) + optional scanners
    (gitleaks, checkov, bandit, gosec, eslint-security) behind opt-in flags,
  - verifies each binary is on `PATH` afterward.
- **Proposal:** add `--install-deps` / a `sast-setup` command that installs the
  optional supplemental tools on demand (today they print "not installed" but
  never auto-install).

---

## 📋 Issue — `fix_finding.py` batch mode

- **Labels:** `tooling`, `ux`
- `fix_finding.py` accepts a single finding id; 3 CRITICAL findings need 3 runs.
- **Proposal:** support `--all-critical`, `--severity high+`, and a `--batch`
  mode that iterates findings and applies the template fix per item, with a
  per-finding confirmation/summary. Keep the single-id path as the default.

---

## 📋 Issue — Standalone CLI documentation

- **Labels:** `docs`
- README is heavily Skill-oriented (`/sast-scan`, `/sast-triage`, `/sast-fix`);
  the standalone `python3 sast_runner.py` path is a single line.
- **Proposal:** add `docs/cli-usage.md` documenting the standalone runner:
  positional `target` arg, every flag (`--profile`, `--changed-only`, `--lang`,
  `--format`, `--fail-on`, `--ci`, `--baseline`, `--llm-findings`,
  `--pr-comment`), output formats, exit codes, and env-var behavior. Cross-link
  from README so the two entry points (Skill vs CLI) are equally discoverable.
- **Also:** normalize arg naming in docs — README examples use `--target` but
  `target` is positional. Align docs with actual argparse definition.

---

## 📋 Issue — First-scan baseline initialization

- **Labels:** `tooling`, `ux`
- First scan surfaced 27 findings, ~17 of them FPs; suppressing them one-by-one
  is high-friction.
- **Proposal:** add `--first-scan` that auto-marks findings at or below a given
  severity (e.g. medium and below, or all non-new) as the initial baseline, so
  subsequent scans surface only *deltas*. Pair with the FP-baseline mechanism
  above.

---

## 📋 Issue — Output verbosity control

- **Labels:** `ux`
- A single scan dumps logs, rule-parse errors, tool-skip notices, scoring, top
  findings, next steps — high information density that dilutes signal.
- **Proposal:** introduce `--quiet` (summary + top findings only) and
  `--verbose` (full detail) modes; default to quiet for interactive use and
  verbose for CI/logs.

---

## Filing these as GitHub issues

`gh` is not authenticated in this session. To file, authenticate (interactive,
no token pasted in chat):

```
! gh auth login
```

Then, for each 📋 item above:

```
gh issue create --title "<title>" --label "bug,rules" --body-file <(echo "<body>")
```

A throwaway script to file them in batch can be generated from this doc on
request.
