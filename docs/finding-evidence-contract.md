# Finding evidence and verification contract v1.0

OpenSAST preserves the existing `evidence.source`, `sink`, `dataflow`, finding IDs,
fingerprints, and triage formats. Normalized JSON findings now also contain
`verification` and `evidence_assessment`. Old imports remain valid.

## Review decisions

| `verification.status` | Meaning |
|---|---|
| `needs-review` | A candidate or conflicting decisions requiring review |
| `confirmed` | An explicit reviewer decision with rationale |
| `false-positive` | An explicit reviewer dismissal with rationale |
| `fixed` | A completed verification with a recorded scan/test artifact |
| `unavailable` | Verification could not be performed; the reason is recorded |

Confidence does not change review status. Suppression may represent accepted risk
and does not imply a false positive. Legacy `triage.status` decisions migrate as
manual review; missing supporting evidence remains visible. New explicit
verification takes precedence. Conflicting deduplicated decisions retain their
history under `verification.reviews` and become `needs-review`.

```json
{
  "verification": {
    "schema_version": "1.0",
    "status": "confirmed",
    "method": "manual-review",
    "rationale": "An authenticated user supplies another owner's document ID; no ownership condition exists on the query path.",
    "reviewer": "security-reviewer",
    "artifacts": [{"kind": "source", "path": "src/documents.ts"}]
  },
  "evidence": {
    "source": "req.params.id",
    "sink": "db.document.findUnique(...) ",
    "attacker_control": "The authenticated caller controls the route parameter",
    "preconditions": ["The caller has a valid session", "Another owner's document ID is known"],
    "sanitizers": ["requireAuth verifies identity but does not enforce ownership"],
    "trust_boundaries": ["HTTP request to database access"],
    "dataflow": [
      {"file": "src/routes.ts", "line": 10, "snippet": "loadDocument(req.params.id)"},
      {"file": "src/documents.ts", "line": 21, "snippet": "db.document.findUnique({where: {id}})"}
    ]
  }
}
```

Methods are `unreviewed`, `manual-review`, `static-analysis`, and `runtime-test`.
Artifacts use `kind: source|test|log|scan`, a nonempty `path`, and optionally a
64-character lowercase `sha256`. Reviewed decisions require rationale. A fixed
claim additionally requires a SHA-256-pinned `scan` artifact for `static-analysis`,
or a SHA-256-pinned `test` artifact for `runtime-test`. Source excerpts and logs
alone cannot establish a fix.
Imported artifact references are declarations; the importer does not execute them
or certify their contents. No runtime proof is inferred from a model's assertion.

## Evidence assessment

`evidence_assessment.level` is `none`, `source`, or `static-path`. A static path
requires at least two dataflow steps with real filenames and positive line numbers.
`gaps` identifies missing source, sink, attacker control, preconditions, or a code
location. Gaps are evidence-collection guidance, not a universal vulnerability
checklist: a hardcoded credential does not need the same proof as SQL injection.
`runtime_proven` remains false: this assessment evaluates recorded source context.

JSON includes per-finding records and `verification_summary`. Markdown includes a
verification/evidence table. The legacy enrichment fields remain available.
New evidence/review text is covered by secret redaction.

## Gate and fix semantics

An ordinary unreviewed HIGH rule signal still blocks at the configured threshold.
Explicit false-positive/fixed review decisions are excluded; unavailable
verification does not silently dismiss a finding. `needs-review` continues to use
the existing `review_findings_blocking` policy. Scanner execution failures always
remain errors independently of findings.

`fix-result.json` records a separate verification record. Successful targeted
re-scan records `static-analysis`, the scan artifact path/hash and `fixed` only
when the original finding is absent and no new findings appear. This is static
re-scan evidence, not a runtime exploit proof. Missing originating scanners,
failed scans, or missing result artifacts produce `unavailable`.
