"""Evidence is traceable context; review decisions are explicit, versioned facts."""

from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".claude/skills/sast-scan/tools"))

from finding_evidence import assess_evidence, enrich_finding, normalize_verification, validate_verification
from normalize_findings import compute_fingerprint, normalize_llm_findings, validate_llm_findings
from normalize_findings import deduplicate_findings
from triage_findings import apply_triage_verdicts
from report_writer import generate_json_summary, generate_markdown_report
from redact import redact_findings
from ci_gate import evaluate_gate


def finding(**updates):
    data = {"tool": "semgrep", "rule_id": "python.sqli", "title": "SQL injection", "severity": "high",
            "confidence": "high", "file": "app.py", "start_line": 4, "message": "input in query",
            "evidence": {"source": "request.args['id']", "sink": "execute(query)", "dataflow": []}}
    data.update(updates)
    return data


def test_confidence_and_context_do_not_imply_confirmation():
    f = finding()
    assert normalize_verification(f)["status"] == "needs-review"
    assert assess_evidence(f)["level"] == "source"


def test_legacy_review_decision_is_preserved_without_inventing_runtime_proof():
    f = finding(triage={"status": "confirmed", "rationale": "request reaches query without binding"})
    result = enrich_finding(f)
    assert result["verification"]["status"] == "confirmed"
    assert result["verification"]["method"] == "manual-review"
    assert result["evidence_assessment"]["level"] != "runtime"


def test_enrichment_does_not_mutate_input_or_change_fingerprint():
    f = finding()
    before = deepcopy(f)
    enriched = enrich_finding(f)
    assert f == before
    assert compute_fingerprint(enriched) == compute_fingerprint(f)
    assert enriched["evidence"]["source"] == f["evidence"]["source"]


def test_suppression_is_not_a_false_positive_verdict():
    assert normalize_verification(finding(is_suppressed=True))["status"] == "needs-review"


def test_explicit_verification_takes_precedence_over_legacy_triage():
    f = finding(triage={"status": "confirmed"}, verification={"schema_version": "1.0",
                "status": "unavailable", "method": "static-analysis", "rationale": "CodeQL did not run"})
    assert normalize_verification(f)["status"] == "unavailable"


@pytest.mark.parametrize("verification", [
    {"schema_version": "2.0", "status": "confirmed", "method": "manual-review", "rationale": "reviewed"},
    {"status": "confirmed", "method": "manual-review", "rationale": ""},
    {"status": "fixed", "method": "static-analysis", "rationale": "gone", "artifacts": []},
    {"status": "fixed", "method": "unreviewed", "rationale": "gone", "artifacts": [{"kind": "log", "path": "log"}]},
    {"status": "invented", "method": "unreviewed"},
    {"status": [], "method": "manual-review"},
    {"status": "needs-review", "reviews": ["invalid"]},
])
def test_rejects_invalid_verification_claims(verification):
    assert validate_verification(verification)
    ok, errors = validate_llm_findings([finding(verification=verification)])
    assert not ok and errors


def test_dataflow_requires_real_locations_to_raise_evidence_level():
    from report_writer import classify_evidence_strength
    f = finding(evidence={"dataflow": [{"file": "a.py", "line": 1}, {"file": "b.py", "line": 9}],
                          "source": "input", "sink": "execute", "attacker_control": "query param",
                          "preconditions": ["authenticated user"]})
    assert assess_evidence(f)["level"] == "static-path"
    f["evidence"]["dataflow"] = [{"file": "a.py", "line": 0}, {"file": "b.py", "line": 0}]
    assert assess_evidence(f)["level"] == "source"
    assert classify_evidence_strength(f) != "dataflow-trace"


def test_llm_import_preserves_review_and_missing_evidence():
    f = finding(verification={"schema_version": "1.0", "status": "confirmed", "method": "manual-review",
                              "rationale": "reviewed complete call chain", "reviewer": "analyst"})
    result = normalize_llm_findings([f])[0]
    assert result["verification"]["reviewer"] == "analyst"
    assert "attacker_control" in result["evidence_assessment"]["gaps"]


def test_triage_updates_explicit_verification():
    f = enrich_finding(finding(fingerprint="fp-1"))
    results = apply_triage_verdicts([f], [{"fingerprint": "fp-1", "verdict": "FP", "rationale": "bound query"}])
    assert results[0]["verification"]["status"] == "false-positive"
    assert results[0]["verification"]["rationale"] == "bound query"


def test_conflicting_reviews_survive_dedup_as_review_needed():
    a = enrich_finding(finding(triage={"status": "confirmed", "rationale": "path reachable"}))
    b = enrich_finding(finding(triage={"status": "false-positive", "rationale": "guard in middleware"}))
    result = deduplicate_findings([a, b])[0]
    assert result["verification"]["status"] == "needs-review"
    assert {v["status"] for v in result["verification"]["reviews"]} == {"confirmed", "false-positive"}


def test_reports_expose_verification_and_evidence_gaps(tmp_path):
    f = finding()
    summary = {"total_findings": 1, "gate_result": {"passed": True}, "severity_counts": {"high": 1}}
    result = generate_json_summary(summary, [f], str(tmp_path / "findings.json"))
    assert result["verification_summary"]["by_status"]["needs-review"] == 1
    assert result["findings"][0]["evidence_assessment"]["gaps"]
    text = generate_markdown_report(summary, [f], str(tmp_path / "report.md"))
    assert "Verification" in text and "attacker_control" in text


def test_new_evidence_metadata_is_redacted_without_changing_identity():
    secret = "ghp_" + "a" * 36
    f = enrich_finding(finding(fingerprint="original-fingerprint", verification={"status": "confirmed", "method": "manual-review",
                       "rationale": "leaked " + secret}, evidence={"source": secret, "preconditions": [secret]}))
    result = redact_findings([f])[0]
    assert secret not in str(result)
    assert result["fingerprint"] == "original-fingerprint"


def test_gate_respects_explicit_review_but_unreviewed_rule_signals_still_block():
    f = enrich_finding(finding())
    assert not evaluate_gate([f])["passed"]
    f["verification"] = {"status": "false-positive", "method": "manual-review", "rationale": "query is parameterized"}
    assert evaluate_gate([f])["passed"]
    f["verification"] = {"status": "unavailable", "method": "static-analysis", "rationale": "missing scanner"}
    assert not evaluate_gate([f])["passed"]


@pytest.mark.parametrize("artifact", [{"kind": "source", "path": "app.py"}, {"kind": "log", "path": "scan.log"},
                                      {"kind": "scan", "path": "scan.json"}, {"kind": [], "path": "x"}])
def test_fixed_requires_hashed_scan_or_test_artifact(artifact):
    assert validate_verification({"status": "fixed", "method": "static-analysis", "rationale": "rescanned", "artifacts": [artifact]})


@pytest.mark.parametrize("status,method", [("confirmed", "manual-review"), ("unavailable", "unreviewed")])
def test_authoritative_decision_prevents_stale_false_positive_suppression(tmp_path, status, method):
    from triage_findings import triage_findings, auto_suppress_false_positives, export_triage_to_baseline
    from report_writer import resolve_triage_status
    from session_status import count_unfixed_high
    f = finding(fingerprint="fp", triage={"status": "false-positive", "confidence": .99},
                verification={"status": status, "method": method, "rationale": "current decision"})
    assert not evaluate_gate([f])["passed"]
    assert resolve_triage_status(f) == status
    assert count_unfixed_high([f]) == 1
    assert not triage_findings([f])["false_positives"]
    assert auto_suppress_false_positives([f], str(tmp_path / "a.json"))["suppressed_count"] == 0
    assert export_triage_to_baseline([f], str(tmp_path / "b.json"))["exported_count"] == 0


def test_fixed_findings_are_excluded_from_pending_repairs():
    from triage_findings import triage_findings
    from session_status import count_unfixed_high
    from report_writer import build_report_next_steps
    f = finding(verification={"status": "fixed", "method": "static-analysis", "rationale": "clean rescan",
                              "artifacts": [{"kind": "scan", "path": "findings.json", "sha256": "a" * 64}]})
    assert not validate_verification(f["verification"])
    assert not triage_findings([f])["priority_fix_list"]
    assert count_unfixed_high([f]) == 0
    f["is_new"] = True
    assert not any("**Triage**" in step for step in build_report_next_steps({"severity_counts": {"high": 1}}, [f]))
