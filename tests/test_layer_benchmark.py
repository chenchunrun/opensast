"""Three-layer measurements must use pinned inputs and real completed snapshots."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmark"))
from layer_benchmark import build_comparison, load_dataset, prepare_benchmark, main


@pytest.fixture
def dataset(tmp_path):
    cases = []
    for name, vulnerable in [("one", True), ("two", True), ("three", False)]:
        path = tmp_path / f"{name}.py"
        path.write_text("print('fixture')\n")
        cases.append({"id": name, "file": path.name, "start_line": 1, "end_line": 1,
                      "cwe": "CWE-89", "vulnerable": vulnerable, "language": "python",
                      "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": "1.0", "id": "unit-fixtures", "unmatched_policy": "false-positive", "cases": cases}))
    return load_dataset(manifest)


def detection(file="one.py", cwe="CWE-89", line=1, **updates):
    return {"file": file, "start_line": line, "end_line": line, "cwe": [cwe], **updates}


def snapshot(dataset, layer="rules", findings=None, run_id=None, parent_run_id=None, **updates):
    phases = [] if layer == "rules" else (["llm"] if layer == "rules-llm" else ["llm", "agent"])
    value = {"schema_version": "1.0", "dataset_id": dataset["id"], "dataset_digest": dataset["_digest"],
             "layer": layer, "run_id": run_id or layer, "parent_run_id": parent_run_id,
             "complete": True, "findings": findings if findings is not None else [detection()],
             "duration_seconds": 10, "cost_usd": None,
             "provenance": {"engine": "semgrep", "engine_version": "test", "rules_digest": "a" * 64,
                            "analysis": [{"phase": p, "provider": "local", "model": "test-model",
                                          "model_version": "test-v1", "prompt_digest": "b" * 64,
                                          "parameters": {"temperature": 0}} for p in phases]}}
    value.update(updates)
    return value


def test_scores_positive_negative_and_unmatched_detections_without_duplicate_inflation(dataset):
    run = snapshot(dataset, findings=[detection(), detection(), detection("three.py"), detection("elsewhere.py")])
    result = build_comparison(dataset, [run])
    metrics = result["layers"]["rules"]["runs"][0]["metrics"]
    assert (metrics["tp"], metrics["fn"], metrics["fp"], metrics["tn"]) == (1, 1, 2, 0)
    assert metrics["precision"] == pytest.approx(1 / 3)
    assert metrics["recall"] == 0.5
    assert metrics["false_positive_rate"] == 1
    assert metrics["unmatched_findings"] == 1


@pytest.mark.parametrize("finding", [detection(cwe="CWE-78"), detection(line=9)])
def test_wrong_cwe_or_location_is_not_a_true_positive(dataset, finding):
    result = build_comparison(dataset, [snapshot(dataset, findings=[finding])])
    assert result["layers"]["rules"]["runs"][0]["metrics"]["tp"] == 0


def test_partially_labeled_dataset_keeps_unmatched_findings_unadjudicated(dataset):
    dataset["unmatched_policy"] = "unscored"
    result = build_comparison(dataset, [snapshot(dataset, findings=[detection(), detection("elsewhere.py")])])
    metrics = result["layers"]["rules"]["runs"][0]["metrics"]
    assert metrics["fp"] == 0 and metrics["precision"] == 1
    assert metrics["unadjudicated_findings"] == 1


def test_missing_layers_are_pending_and_unknown_cost_is_not_zero(dataset):
    result = build_comparison(dataset, [snapshot(dataset)])
    assert result["complete"] is False
    assert result["layers"]["full"]["status"] == "pending"
    assert result["layers"]["full"]["runs"] == []
    assert result["layers"]["rules"]["mean_cost_usd"] is None


def test_three_complete_layers_have_deltas_and_repeatability(dataset):
    runs = [snapshot(dataset), snapshot(dataset, "rules-llm", parent_run_id="rules"),
            snapshot(dataset, "full", findings=[detection(), detection("two.py")], parent_run_id="rules-llm"),
            snapshot(dataset, "full", run_id="full-repeat", parent_run_id="rules-llm")]
    result = build_comparison(dataset, runs)
    assert result["complete"]
    assert result["layers"]["full"]["stability_jaccard"] == 0.5
    assert result["layers"]["rules"]["stability_jaccard"] is None
    assert result["deltas"]["full_vs_rules"]["mean_recall"] == 0.25


@pytest.mark.parametrize("updates", [
    {"dataset_digest": "0" * 64}, {"complete": False}, {"duration_seconds": -1},
    {"cost_usd": float("nan")}, {"findings": "invalid"}, {"duration_seconds": True},
])
def test_invalid_or_incomplete_measurements_cannot_be_scored(dataset, updates):
    with pytest.raises(ValueError):
        build_comparison(dataset, [snapshot(dataset, **updates)])


def test_ai_run_requires_model_provenance_and_correct_parent(dataset):
    run = snapshot(dataset, "rules-llm", parent_run_id="rules")
    run["provenance"]["analysis"] = []
    with pytest.raises(ValueError, match="analysis"):
        build_comparison(dataset, [snapshot(dataset), run])
    run = snapshot(dataset, "full", parent_run_id="rules")
    with pytest.raises(ValueError, match="parent"):
        build_comparison(dataset, [snapshot(dataset), run])


def test_different_rule_configuration_cannot_be_compared(dataset):
    run = snapshot(dataset, "rules-llm", parent_run_id="rules")
    run["provenance"]["rules_digest"] = "c" * 64
    with pytest.raises(ValueError, match="rule"):
        build_comparison(dataset, [snapshot(dataset), run])


def test_cumulative_measurements_and_parent_model_history_must_be_consistent(dataset):
    base = snapshot(dataset)
    child = snapshot(dataset, "rules-llm", parent_run_id="rules", duration_seconds=1)
    with pytest.raises(ValueError, match="cumulative"):
        build_comparison(dataset, [base, child])
    child["duration_seconds"] = 10
    full = snapshot(dataset, "full", parent_run_id="rules-llm")
    full["provenance"]["analysis"][0]["model"] = "different-model"
    with pytest.raises(ValueError, match="parent"):
        build_comparison(dataset, [base, child, full])


def test_builtin_dataset_is_balanced_and_sources_are_pinned():
    data = load_dataset(Path(__file__).resolve().parents[1] / "benchmark/datasets/whitebox-v1/manifest.json")
    assert len(data["cases"]) == 14
    assert sum(c["vulnerable"] for c in data["cases"]) == 7
    assert {c["language"] for c in data["cases"]} == {"python", "javascript", "typescript", "java"}


def test_dataset_rejects_changed_source(dataset):
    root = Path(dataset["_root"])
    (root / "one.py").write_text("changed\n")
    with pytest.raises(ValueError, match="hash"):
        load_dataset(root / "manifest.json")


def test_dataset_rejects_paths_outside_root(dataset):
    root = Path(dataset["_root"])
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["cases"][0]["file"] = "../outside.py"
    (root / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="path"):
        load_dataset(root / "manifest.json")


def test_preparation_exports_blind_packets_and_honest_pending_templates(dataset, tmp_path):
    def scan(target, output_dir, **kwargs):
        path = Path(output_dir) / "semgrep.sarif"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"version": "2.1.0", "runs": [{"invocations": [{"executionSuccessful": True}]}]}))
        raw = path.with_suffix(".json")
        raw.write_text(json.dumps({"errors": [], "paths": {"scanned": [str(p) for p in Path(target).glob("*.py")]}}))
        return {"success": True, "exit_code": 0, "version": "test", "sarif_path": str(path), "json_path": str(raw)}
    out = tmp_path / "out"
    prepare_benchmark(dataset, out, scanner=scan)
    run = json.loads((out / "rules.json").read_text())
    assert run["complete"] is True and run["cost_usd"] == 0
    assert json.loads((out / "rules-llm.template.json").read_text())["complete"] is False
    packet = json.loads((out / "analysis-packet.json").read_text())
    assert "cases" not in packet and "vulnerable" not in json.dumps(packet)
    assert len(packet["files"]) == 3
    report_dir = tmp_path / "report"
    assert main(["compare", "--dataset", str(Path(dataset["_root"]) / "manifest.json"),
                 "--run", str(out / "rules.json"), "--output-dir", str(report_dir)]) == 3
    assert (report_dir / "comparison.md").exists()
    assert json.loads((report_dir / "comparison.json").read_text())["complete"] is False


def test_failed_scan_does_not_create_successful_baseline(dataset, tmp_path):
    with pytest.raises(ValueError, match="scan"):
        prepare_benchmark(dataset, tmp_path / "out", scanner=lambda *a, **k: {
            "success": False, "exit_code": 2, "error_message": "invalid rule"})
    assert not (tmp_path / "out/rules.json").exists()


def test_child_cannot_silently_drop_parent_findings(dataset):
    base = snapshot(dataset, findings=[detection(), detection("three.py")])
    child = snapshot(dataset, "rules-llm", parent_run_id="rules")
    with pytest.raises(ValueError, match="retain"):
        build_comparison(dataset, [base, child])
    child["findings"].append(detection("three.py", verification={"status": "false-positive", "method": "manual-review", "rationale": "bound query"}))
    assert build_comparison(dataset, [base, child])["layers"]["rules-llm"]["mean_precision"] == 1


@pytest.mark.parametrize("failure", ["json-error", "coverage", "invocation", "notification", "missing-json"])
def test_partial_scan_cannot_create_complete_baseline(dataset, tmp_path, failure):
    def scan(target, output_dir, **kwargs):
        path = Path(output_dir) / "semgrep.sarif"
        path.parent.mkdir(parents=True, exist_ok=True)
        invocation = {"executionSuccessful": failure != "invocation", "toolExecutionNotifications": []}
        if failure == "notification":
            invocation["toolExecutionNotifications"] = [{"level": "warning", "message": {"text": "parse failed"}}]
        path.write_text(json.dumps({"runs": [{"invocations": [invocation]}]}))
        raw = path.with_suffix(".json")
        raw.write_text(json.dumps({"errors": [{"type": "Syntax error"}] if failure == "json-error" else [],
                                  "paths": {"scanned": [] if failure == "coverage" else [str(p) for p in Path(target).glob("*.py")]}}))
        return {"success": True, "exit_code": 0, "version": "test", "sarif_path": str(path),
                "json_path": None if failure == "missing-json" else str(raw)}
    with pytest.raises(ValueError, match="scan"):
        prepare_benchmark(dataset, tmp_path / "out", scanner=scan)
    assert not (tmp_path / "out/rules.json").exists()
