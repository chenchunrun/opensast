# Reproducible whitebox layer comparison

This measures a fixed rule baseline, then the incremental effect of structured
LLM review and Agent review. It does not invoke AI APIs or execute target code.
AI analysis remains inside the Skill session.

Field studies of real (private) targets are recorded separately, e.g.
[FIELD_STUDY_KOKOAPP_2026-10-31.md](FIELD_STUDY_KOKOAPP_2026-10-31.md) —
calibration data with known circularity limits, never a substitute for this
reproducible instrument.

## Dataset and scope

`datasets/whitebox-v1/manifest.json` pins 14 small, synthetic paired cases across
Python, JavaScript/TypeScript, and Java: SQL injection, command injection, and
resource ownership. Seven are positive and seven negative. Labels include file,
CWE, line range, and a SHA-256 of the whole source file.

These are regression samples, not a representative real-world benchmark or a
claim of framework completeness. The baseline is **this repository's Semgrep
rules**, not every optional scanner supported by OpenSAST. It is separate from
the Java OWASP Benchmark. Do not tune production rules to maximize this toy set.

## 1. Prepare a real rule baseline and blind inputs

From repository root, with Python dependencies and Semgrep installed:

```bash
python3 benchmark/layer_benchmark.py prepare \
  --dataset benchmark/datasets/whitebox-v1/manifest.json \
  --output-dir .claude/sast/results-whitebox/run1
```

The command verifies source hashes, stages only the pinned sources, runs local
rules, and writes:

- `rules.json`: measured rule findings, engine version, rule digest and duration.
- `raw/`: the actual scanner output.
- `analysis-packet.json`: sources and rule candidates, without ground-truth cases.
- `rules-llm.template.json` / `full.template.json`: explicitly incomplete templates.

Use a fresh output directory per experiment. Failed scans do not produce a
successful baseline. Preparation rejects scanner diagnostics, unsuccessful SARIF
invocations, skipped rules, or missing coverage of any pinned source file.
Hash mismatches require reviewing and versioning the
dataset; regenerating labels blindly would defeat the pin.

## 2. Produce actual AI snapshots in a Skill session

Use a fresh analysis session that has not read the manifest, expected answers,
or this dataset's authoring history. Supply only the analysis packet. The packet
avoids labels; this is not a filesystem sandbox, so prevent the analysis session
from independently reading the ground-truth manifest.

1. Structured review: inspect every supplied file, validate rule candidates and
   discover additional issues. Copy the template to `rules-llm.json`, preserve
   the dataset/engine/rule identifiers, and set its parent to the rule run ID.
2. Record the **cumulative** findings after that review, retaining every earlier
   candidate's file, line range, CWE, rule ID and fingerprint, plus new discoveries.
   Dismissed candidates remain in the snapshot with explicit false-positive
   verification rationale. Silent deletion is rejected. Do not submit only new discoveries.
3. Free-form Agent review: consume the same sources and the completed structured
   snapshot. Write `full.json` with the structured snapshot's `parent_run_id`.
4. Fill actual provider, model, model version, effective prompt SHA-256 and model
   parameters for each phase. Use `model_version: not-exposed-by-provider` when
   the provider does not expose a build version; do not invent a version.
5. Record cumulative wall time and cumulative API USD, including earlier phases.
   Record `null` for unknown cost. Local API cost may be zero; this excludes
   hardware, electricity, and human review cost.
6. Choose a unique run ID and set `complete: true` only after actual review.
   Placeholder metadata, incomplete templates, missing parents and stale digests
   cannot be scored as successful zero-finding scans.

Model metadata and AI measurements are supplied by the session; the comparator
validates consistency, not that a remote model actually ran. Keep execution logs
and raw responses with experiment artifacts for independent audit.

## 3. Compare

```bash
python3 benchmark/layer_benchmark.py compare \
  --dataset benchmark/datasets/whitebox-v1/manifest.json \
  --run .claude/sast/results-whitebox/run1/rules.json \
  --run .claude/sast/results-whitebox/run1/rules-llm.json \
  --run .claude/sast/results-whitebox/run1/full.json \
  --output-dir .claude/sast/results-whitebox/comparison
```

Outputs: `comparison.json` and `comparison.md`. Supplying only `rules.json` is
valid: the other layers are pending and the command exits 3. No AI improvement is
claimed until real completed snapshots are provided.

Exit codes: **0** all three completed layer snapshots supplied; **3** missing
layers with a partial report; **2** invalid inputs, stale data, failed preparation,
or output errors. A complete report does not imply the scanner found every bug.

## Metrics and attribution

- A detection must match **file + CWE + overlapping line range**.
- Repeated detections of a labeled case count once. Positive labels give TP/FN;
  negative labels give FP/TN. Explicit FP/fixed review records are excluded.
- `unmatched_policy: unscored` is the safe default for partially labeled corpora:
  additional findings are retained as unadjudicated, excluded from scoped
  precision, and reported as gaps. Review them before claiming repository-wide
  precision. `false-positive` is only appropriate for exhaustively labeled sets.
- Precision = TP/(TP+FP), recall = TP/(TP+FN), F1 = 2TP/(2TP+FP+FN).
  FPR uses only labeled negative cases. Undefined ratios remain null.
- Duration/cost deltas compare means of cumulative snapshots against rules.
  These descriptive differences are not significance tests or causal estimates.
- Repeat each configuration at least three times, preserving parent relationships,
  then pass all snapshots using repeated `--run`. The comparator reports pairwise
  mean Jaccard over detected labels and unmatched findings. One run has no
  repeatability estimate. Model/rule configuration must match within a layer;
  compare different models in separate reports.

Expand later with version-pinned real repositories/CVE fixes, independently
reviewed labels, authorization paths, framework variants, and unchanged safe code.
