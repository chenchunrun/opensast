# Evidence Contract and Layer Comparison Implementation Plan

> **For agentic workers:** Use executing-plans to implement task by task with TDD and independent final review.

**Goal:** Make whitebox findings auditable and measure the incremental value of rules, LLM review, and Agent review on the same pinned dataset.

**Architecture:** Extend existing findings with a versioned verification object and evidence-gap assessment while preserving legacy evidence and fingerprints. Add an offline benchmark preparation/comparison CLI: a real Semgrep baseline, blind analysis packets, explicitly incomplete AI templates, and scoring of independently produced complete layer snapshots.

**Tech Stack:** Python 3.11+, standard library, existing PyYAML/Semgrep adapters, pytest.

**Spec:** The accepted P0 recommendations in this chat: unified evidence/verification states and a reproducible three-layer comparison reporting detections, false positives, duration, cost, and repeatability.

## Global Constraints

- Preserve existing uncommitted fixes and existing fingerprints; no source edits to targets.
- Keep legacy findings importable; confidence and source snippets never imply verification.
- Preserve the Skill-first product boundary: AI runs in the Skill session; never call a paid API automatically.
- Keep confirmed facts, review decisions, missing evidence, and runtime proof distinct.
- Run all layers against the same content digest; do not expose ground-truth labels in AI packets.
- Missing runs, failed scans, unknown costs, and placeholder AI outputs must not become successful zero-finding measurements.

## Review Focus

1. Dedup/import/triage must not lose explicit verification decisions or inflate proof strength.
2. Fixed/confirmed claims require rationale; fixed claims require actual verification artifacts.
3. Benchmark matching must include file, CWE, and line range; duplicate findings cannot inflate recall.
4. Negative cases contribute to false positives; unmatched findings remain unadjudicated by default because partial labels cannot prove they are false. Stale or incomplete snapshots cannot be scored.
5. Model/rules/config provenance and repeatability must distinguish different experiments, and missing cost stays unknown.

## Tasks

- [x] 1. Add `finding_evidence.py`: versioned verification normalization/validation and evidence gaps; test legacy compatibility, explicit decisions, invalid proof, and non-mutation.
- [x] 2. Integrate into normalization, triage, reports, and fix results; test end-to-end propagation without changing fingerprints or legacy gate behavior.
- [x] 3. Add `benchmark/layer_benchmark.py` comparison core: strict pinned snapshots, location/CWE matching, precision/recall/FPR, duplicate handling, missing stages, and stability; write failing tests first.
- [x] 4. Add preparation/comparison CLI and pinned JS/TS, Python, Java positive/negative examples; test real preparation, blind packets, placeholders, content invalidation, and output errors.
- [x] 5. Document schemas, commands, evidence limits, cost semantics, and Skill production of real AI snapshots; add optional benchmark workflow.
- [x] 6. Run full pytest, real rule baseline and incomplete comparison, and independent code review. Address important findings and record actual validation results.

Implementation is authorized by the user's “接受你的建议，开工吧”; execute inline in the current checkout to retain the preceding fixes. No automatic commit, API calls, or target-code execution is required.

## Validation and review record

- Unified evidence/verification is integrated into normalization, deduplication, triage, JSON/Markdown reports, CI gates, session status and fix results. Existing fingerprints remain unchanged.
- Independent review found and resolved partial-scan success, silent parent-candidate deletion, inadequate fixed artifacts, stale triage suppression and status-precedence bugs. Fixed findings also leave pending repair recommendations; source paths require valid locations before stronger evidence labels.
- Final real Semgrep preparation: three runs under `.claude/sast/results-whitebox/p0-20261016-verified`, all pinned files covered, diagnostics clear. Results repeat exactly (Jaccard 1.0): TP 5, FN 2, FP 1, TN 6; scoped precision 0.8333, recall 0.7143, FPR 0.1429, average 3.4656 seconds. Ten extra findings per run remain unadjudicated and excluded from scoped precision.
- Actual malformed Java input was rejected despite Semgrep exit 0; no successful baseline artifact was written.
- The comparison command exits 3 and explicitly reports AI layers pending. A fresh label-blind Skill session is still required to measure those layers; this implementation does not assert AI uplift or invent costs.
- Python compilation and `git diff --check` pass. Full suite: 496 passed; focused checks after the final report-recommendation adjustment: 67 passed.
