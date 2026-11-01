# Field study: KoKoApp (scan of 2026-10-31)

A single-project, real-world calibration record. This complements
[LAYER_COMPARISON.md](LAYER_COMPARISON.md), which is the *reproducible*
instrument (pinned whitebox-v1 dataset, hash-verified, repeatable). A field
study is not reproducible by third parties — the target is private code and
adjudication happened once, in session. Treat it as calibration data, not a
benchmark: **n = 1 project, 1 adjudication pass**.

## Scan configuration

- Date: 2026-10-31; profile `standard`, `--format all`; three-tier analysis
  (Phase A–D) completed in the same session.
- Target: mid-size TypeScript/Node web app (BFF + Next.js + ops scripts),
  per-project config excluding `docs/`, `.worktrees/`, vendored `codex-main/`.
- Artifacts: `findings.json`, `llm-findings.json` (schema v1.0) under the
  target's `.claude/sast/results/`.

## Headline numbers

| Measure | Value |
|---|---|
| Raw findings reaching the report | 1126 (Semgrep 1110, ESLint 10, Gitleaks 6) |
| Gate severities | 6 critical, 567 high, 474 medium, 79 info |
| Adjudicated ground truth (3-tier complete) | **7 findings: 3 medium, 4 low** |
| Gate criticals surviving adjudication | 0 of 6 |
| Rule-layer precision (exact-site) | 11/1126 = **0.98%** |
| Rule-layer site recall | **6 of 7** ground-truth sites located |
| Phase A validate targets confirmed TP | 0 of 20 (all dismissed with reason) |

The rule pack is a **locator, not an adjudicator**: it put 6 of 7 real sites on
the table, wrapped in ~1115 false positives. The precision floor is consistent
with the literature ceiling for generic rules (PrimeVul point F1 ≈ 3%, ICSE
2025); the recall is why the rules layer still exists.

## Where the 1126 lived: path-class buckets

| Bucket | Share | Mechanism |
|---|---|---|
| Test-shaped paths (dirs/suffixes) | 39.9% | fixtures, `.spec.ts`, `__tests__/`, `e2e/` |
| `scripts/`-only paths | 23.0% | ops/smoke scripts, not production surface |
| **Combined non-production** | **62.9%** | deployment artifact, not detection signal |

The then-deployed test filter missed most of the test bucket (no `.mjs`, no
kebab-case spec names, no `e2e/`/`cypress/`). Nearly two-thirds of raw volume
said nothing about production code — this is noise that never reaches an
adjudicator if filtering is right, and the single largest FP class if it isn't.

## FP-mechanism taxonomy (per top rule)

| Rule (count) | Mechanism | Class |
|---|---|---|
| `nextjs.validation.missing-zod-parse` (208) | Next.js handlers where zod does not apply | wrong-layer validation |
| `javascript.security.ssrf-fetch` (201) | any non-literal URL matches | pattern-without-flow |
| `javascript.security.path-traversal` (171) | any non-literal path matches | pattern-without-flow |
| `soc2.access-control-missing-auth` (146) | regex lookahead only checked first middleware arg; fired *despite* `requireAuth` | guard-blind |
| `iso27001.a8-12-hardcoded-secrets` (131) | fake tokens committed in test fixtures | test-fixture secrets |
| `nist800-53.au2-no-audit-log` (49) | fires on every `app.post` | audit sweep |
| `javascript.security.timing-attack` (45) | `typeof` guards, null probes, status enums | name-overmatch |
| `taint-xss` (12 of 16) | SSE `data: ${JSON.stringify(...)}` frames — the *safe* idiom | event-protocol mismatch |

## Pattern vs taint siblings

| Vulnerability class | Pattern twin | Taint sibling | Ground truth |
|---|---|---|---|
| SSRF | `ssrf-fetch`: 201 (~100% FP) | `taint-ssrf`: 2 | matches taint sibling |
| Path traversal | `path-traversal`: 171 (~100% FP) | `taint-path-traversal`: 0 | none in scope |
| Reflected XSS | `xss-response-send`: 32 | `taint-xss`: 16 | matches taint sibling |

Dataflow-evidence fraction: taint-mode rules are 11.8% of the 364-rule pack
but produced 1.7% of findings — and essentially all of the rule layer's true
sites. A generic pattern rule with a taint sibling is strictly dominated;
the two pattern twins above were deleted on 2026-11-01 (−372 findings, zero
recall loss). `xss-response-send` (32, SSE-frame FP signature) is the next
candidate for the same treatment.

## Layer triage load and severity inflation

| Layer | Input | Output |
|---|---|---|
| Rules | full repo | 1126 findings, 6C/567H/474M |
| Phase A (validate) | 20 targets sampled from rules | 20/20 dismissed FP |
| Phase B (discover ×9 targets) | source, not rule output | 7 findings (3M/4L) |
| Phase C (agent review) | Phase B + cross-module | confirmed + widened evidence |

Severity inflation gate → adjudicated: **6C/567H → 0C/0H**. Every gate
critical was a rule artifact (regex overreach, test fixture, duplicated
snapshot). No generic severity label survived contact with a human-quality
adjudicator.

## Post-fix regression (rules changed 2026-11-01, same target)

| Rule | Before | After | Notes |
|---|---|---|---|
| `soc2.access-control-missing-auth` | 146 | **29** (−80%) | 13 in `server/bff/index.mjs`, all in-handler-auth routes (`requireBridgeSync`, webhook HMAC, `/health`, `/auth/refresh`) — the intended review-candidate class, not blanket noise |
| `javascript.security.timing-attack` | 45 | **8** non-test | 3 in `bff/index.mjs` are real secret comparisons (dev-default `JWT_SECRET`, dev-default sync token, timing-unsafe token compare at :3044 — adjudicated TP) |
| `taint-xss` SSE class | 12 | **0** of that class | frame-scoped sanitizer (exact ``data: ${JSON.stringify(...)}`` shape); HTML-context `res.send(JSON.stringify(...))` stays detected — a bare JSON.stringify sanitizer was rejected in review as an XSS false negative. 7 non-test unsanitized-interpolation candidates remain (real review items) |
| pattern twins (ssrf+traversal) | 372 | **0** | deleted; their sink lists (write/unlink fs sinks, got/http/https/request clients) were ported into the taint siblings after review flagged the coverage gap. `taint-ssrf` non-test went 1→11: the new sinks reach ops scripts building URLs from CLI/config — review candidates in locator volume, not HTTP-input flows |
| test-path fast filter | missed `.mjs`/kebab/e2e | drops 62.9% bucket | Gitleaks/CodeQL exempt — a secret in a test file is still a secret |

Duplicate-source note: without the per-project `docs/` exclude, archived
evidence-snapshot copies of the same BFF file inflate counts ~1.9× (soc2
29→55). Per-project exclude hygiene is worth as much as rule fixes.

## Caveats

- **Adjudication independence: not established.** The same session produced
  the ground-truth labels *and* tuned the rules against them. Post-fix numbers
  inherit that circularity; the reproducible instrument for claims remains
  LAYER_COMPARISON.md with an independent analysis session.
- n = 1 project, one archetype (Node web app), single run, no repeats.
- Severity mapping informal (rule severity ≠ adjudicated severity).

## Reproduce the rule-layer numbers

```bash
semgrep scan --config .claude/skills/sast-scan/rules/semgrep/javascript \
  --config .claude/skills/sast-scan/rules/semgrep/compliance/soc2.yml \
  <target> --json --quiet --exclude docs --exclude node_modules ...
```

Path-class buckets and taint-mode fractions recompute from the target's
`.claude/sast/results/findings.json` with the regexes documented above.
