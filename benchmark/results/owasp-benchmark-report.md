# OWASP Benchmark v1.2 — OpenSAST Rule Engine Score

- Rules: `.claude/skills/sast-scan/rules/semgrep/java`
- Test cases: 2,740 (1,415 true vulnerabilities / 1,325 false-positive traps)
- Raw semgrep findings: 44121
- Scan wall time: 57s

## Per-category results

| Category | Cases | TP | FN | FP | TN | TPR | FPR | Precision | F1 | Score(TPR-FPR) |
|----------|------:|---:|---:|---:|---:|----:|----:|----------:|---:|---------------:|
| cmdi | 251 | 52 | 74 | 42 | 83 | 41.3% | 33.6% | 55.3% | 0.47 | +7.7% |
| crypto | 246 | 97 | 33 | 0 | 116 | 74.6% | 0.0% | 100.0% | 0.85 | +74.6% |
| hash | 236 | 89 | 40 | 0 | 107 | 69.0% | 0.0% | 100.0% | 0.82 | +69.0% |
| ldapi | 59 | 17 | 10 | 15 | 17 | 63.0% | 46.9% | 53.1% | 0.58 | +16.1% |
| pathtraver | 268 | 74 | 59 | 60 | 75 | 55.6% | 44.4% | 55.2% | 0.55 | +11.2% |
| securecookie | 67 | 36 | 0 | 0 | 31 | 100.0% | 0.0% | 100.0% | 1.00 | +100.0% |
| sqli | 504 | 160 | 112 | 109 | 123 | 58.8% | 47.0% | 59.5% | 0.59 | +11.8% |
| trustbound | 126 | 26 | 57 | 8 | 35 | 31.3% | 18.6% | 76.5% | 0.44 | +12.7% |
| weakrand | 493 | 193 | 25 | 0 | 275 | 88.5% | 0.0% | 100.0% | 0.94 | +88.5% |
| xpathi | 35 | 12 | 3 | 9 | 11 | 80.0% | 45.0% | 57.1% | 0.67 | +35.0% |
| xss | 455 | 119 | 127 | 52 | 157 | 48.4% | 24.9% | 69.6% | 0.57 | +23.5% |

`*` = no OpenSAST rule fired in this category (out of rule coverage).

## Overall — All 11 categories

- TP 875 / FN 540 / FP 295 / TN 1030
- Recall (TPR): **61.8%**
- FPR: **22.3%**
- Precision: **74.8%**
- F1: **0.68**
- OWASP Benchmark score (TPR-FPR): **+39.6%**

## Overall — Covered categories only

- TP 875 / FN 540 / FP 295 / TN 1030
- Recall (TPR): **61.8%**
- FPR: **22.3%**
- Precision: **74.8%**
- F1: **0.68**
- OWASP Benchmark score (TPR-FPR): **+39.6%**

Reference points (official OWASP Benchmark scorecards, full toolset): free SAST tools typically score between 0% and ~35%; commercial tool average is ~26%; SpotBugs+FindSecBugs ~39%.

## Before / after taint rules

| Metric | Syntactic rules only | + taint rules (`taint-rules.yml`) |
|--------|---------------------:|----------------------------------:|
| Categories covered | 0 / 11 | **11 / 11** |
| Recall (TPR) | 0.0% | **61.8%** |
| FPR | 0.0% | 22.3% |
| Precision | — | **74.8%** |
| F1 | 0.00 | **0.68** |
| Benchmark score | 0.0% | **+39.6%** |

What changed:

1. **New `java/taint-rules.yml`** — 7 taint-mode rules (sqli, cmdi, pathtraver,
   ldapi, xpathi, xss, trustbound) tracking servlet sources
   (`getParameter` / `getHeader` / cookies / query string) through variable
   indirection, string concatenation, and collection propagators
   (`List.add`, `StringBuilder.append`) into the dangerous sinks; plus 2 new
   syntactic rules (`weak-cipher-algorithm` CWE-327, `insecure-cookie` CWE-614).
2. **Fixed existing rules for fully-qualified names** — Benchmark code uses
   `new java.util.Random()` / `java.security.MessageDigest.getInstance(...)`
   without imports; the original patterns only matched the short forms.

Why not 100%:

- Remaining FNs are mostly flows through Benchmark helper classes
  (`SeparateClassRequest`, `ThingFactory`, properties files) that require
  cross-file analysis — out of scope for single-file Semgrep taint mode.
- Remaining FPs are false-positive traps whose sanitizers (custom `replace`
  chains, value-switching) we deliberately do not model as universal
  sanitizers, to avoid masking real issues on production code.

Score context: +39.6% is at the level of SpotBugs+FindSecBugs (~39%), above
the commercial-tool average (~26%) on this benchmark, with the usual caveat
that Benchmark-tuned comparisons favor whoever tuned last.
