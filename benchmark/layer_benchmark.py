#!/usr/bin/env python3
"""Prepare blind whitebox inputs and compare pinned, cumulative layer snapshots.

No AI API calls, target builds, or target code execution are performed.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from copy import deepcopy
import hashlib
from itertools import combinations
import json
import math
from pathlib import Path, PurePosixPath
import re
import statistics
import sys
import tempfile
import time
import uuid

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS = REPO_ROOT / ".claude/skills/sast-scan/tools"
sys.path.insert(0, str(TOOLS))
from finding_evidence import normalize_verification

LAYERS = ("rules", "rules-llm", "full")
VERSION = "1.0"
RULES = TOOLS.parent / "rules/semgrep"
INSTRUCTIONS = (
    "Audit only the supplied source files and rule findings. Do not read benchmark labels or manifests. "
    "Trace attacker control, source-to-sink paths, preconditions and existing protections. "
    "Return a cumulative unified findings snapshot: preserve unresolved earlier findings, explicitly "
    "mark false positives with rationale, and include new discoveries. Record model/provider/version, "
    "prompt digest, parameters, cumulative duration and cumulative API cost. Mark complete only after "
    "all supplied files and required phases have been reviewed. Evidence and review state are distinct."
)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _path(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("file path must be nonempty")
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or re.match(r"^[A-Za-z]:", value):
        raise ValueError("file path must be relative and remain inside dataset")
    return str(path)


def _number(value: object, name: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{name} must be finite and nonnegative")
    return float(value)


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value.lower() in {"replace", "unknown", "pending"}:
        raise ValueError(f"{name} must contain recorded provenance")
    return value


def load_dataset(manifest_path: str | Path) -> dict:
    manifest = Path(manifest_path).resolve()
    data = json.loads(manifest.read_text())
    if not isinstance(data, dict) or data.get("schema_version") != VERSION:
        raise ValueError("unsupported dataset schema_version")
    _text(data.get("id"), "dataset id")
    if data.get("unmatched_policy", "unscored") not in {"unscored", "false-positive"}:
        raise ValueError("unmatched_policy must be unscored or false-positive")
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("dataset requires nonempty cases")
    seen = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("dataset case must be an object")
        case_id = _text(case.get("id"), "case id")
        if case_id in seen:
            raise ValueError("duplicate case id")
        seen.add(case_id)
        file = _path(case.get("file"))
        source = (manifest.parent / file).resolve()
        if not source.is_relative_to(manifest.parent):
            raise ValueError("source path escapes dataset")
        if type(case.get("start_line")) is not int or type(case.get("end_line")) is not int:
            raise ValueError("case lines must be integers")
        content = source.read_bytes()
        if not 0 < case["start_line"] <= case["end_line"] <= len(content.splitlines()):
            raise ValueError("case line range is outside source")
        if not isinstance(case.get("cwe"), str) or not re.fullmatch(r"CWE-\d+", case["cwe"]):
            raise ValueError("case requires one CWE identifier")
        if type(case.get("vulnerable")) is not bool:
            raise ValueError("case vulnerable must be boolean")
        _text(case.get("language"), "case language")
        if case.get("source_sha256") != hashlib.sha256(content).hexdigest():
            raise ValueError(f"source hash mismatch: {file}")
    for a, b in combinations(cases, 2):
        if (_path(a["file"]) == _path(b["file"]) and a["cwe"] == b["cwe"]
                and max(a["start_line"], b["start_line"]) <= min(a["end_line"], b["end_line"])):
            raise ValueError("overlapping labels for the same file and CWE")
    return {**data, "_root": str(manifest.parent), "_digest": _digest(data)}


def _validate_run(dataset: dict, run: dict) -> None:
    if not isinstance(run, dict) or run.get("schema_version") != VERSION:
        raise ValueError("unsupported run schema_version")
    if run.get("dataset_id") != dataset["id"] or run.get("dataset_digest") != dataset["_digest"]:
        raise ValueError("run dataset digest does not match pinned inputs")
    layer = run.get("layer")
    if layer not in LAYERS or run.get("complete") is not True:
        raise ValueError("only complete, recognized layer snapshots can be scored")
    _text(run.get("run_id"), "run_id")
    _number(run.get("duration_seconds"), "duration_seconds")
    if run.get("cost_usd") is not None:
        _number(run["cost_usd"], "cost_usd")
    provenance = run.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError("run requires provenance")
    for key in ("engine", "engine_version"):
        _text(provenance.get(key), key)
    if not re.fullmatch(r"[a-f0-9]{64}", str(provenance.get("rules_digest", ""))):
        raise ValueError("run requires rules_digest")
    analysis = provenance.get("analysis")
    expected = [] if layer == "rules" else (["llm"] if layer == "rules-llm" else ["llm", "agent"])
    if not isinstance(analysis, list) or [a.get("phase") for a in analysis if isinstance(a, dict)] != expected:
        raise ValueError(f"analysis phases must be {expected}")
    for model in analysis:
        for key in ("provider", "model", "model_version"):
            _text(model.get(key), f"analysis.{key}")
        if not re.fullmatch(r"[a-f0-9]{64}", str(model.get("prompt_digest", ""))):
            raise ValueError("analysis requires prompt_digest")
        if not isinstance(model.get("parameters"), dict):
            raise ValueError("analysis parameters must be recorded")
    _canonical(provenance)
    if not isinstance(run.get("findings"), list):
        raise ValueError("run findings must be a list")
    for finding in run["findings"]:
        if not isinstance(finding, dict):
            raise ValueError("finding must be an object")
        _path(finding.get("file"))
        start, end = finding.get("start_line"), finding.get("end_line", finding.get("start_line"))
        if type(start) is not int or type(end) is not int or not 0 < start <= end:
            raise ValueError("finding requires positive, ordered line range")
        cwes = finding.get("cwe", [])
        if not isinstance(cwes, list) or any(not isinstance(c, str) or not re.fullmatch(r"CWE-\d+", c) for c in cwes):
            raise ValueError("finding cwe must be a list of CWE identifiers")
        normalize_verification(finding)


def _score(dataset: dict, run: dict) -> dict:
    detected = set()
    unmatched = set()
    excluded = 0
    unique = set()
    for f in run["findings"]:
        if normalize_verification(f)["status"] in {"false-positive", "fixed"}:
            excluded += 1
            continue
        key = (_path(f["file"]), f["start_line"], f.get("end_line", f["start_line"]), tuple(sorted(f.get("cwe", []))))
        if key in unique:
            continue
        unique.add(key)
        matches = {c["id"] for c in dataset["cases"] if _path(c["file"]) == key[0] and c["cwe"] in key[3]
                   and max(c["start_line"], key[1]) <= min(c["end_line"], key[2])}
        detected.update(matches)
        if not matches:
            unmatched.add("unmatched:" + _digest(key))
    positives = {c["id"] for c in dataset["cases"] if c["vulnerable"]}
    negatives = {c["id"] for c in dataset["cases"] if not c["vulnerable"]}
    tp, fn = len(detected & positives), len(positives - detected)
    fp_negative, tn = len(detected & negatives), len(negatives - detected)
    closed_world = dataset.get("unmatched_policy", "unscored") == "false-positive"
    fp = fp_negative + (len(unmatched) if closed_world else 0)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / len(positives) if positives else None
    fpr = fp_negative / len(negatives) if negatives else None
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "precision": precision, "recall": recall,
            "false_positive_rate": fpr, "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
            "unmatched_findings": len(unmatched), "false_positive_cases": fp_negative,
            "unadjudicated_findings": 0 if closed_world else len(unmatched),
            "excluded_reviewed_findings": excluded, "detected_case_ids": sorted(detected),
            "detection_keys": sorted(detected | unmatched)}


def build_comparison(dataset: dict, runs: list[dict]) -> dict:
    grouped = defaultdict(list)
    by_id = {}
    engine_config = None
    for run in runs:
        _validate_run(dataset, run)
        if run["run_id"] in by_id:
            raise ValueError("duplicate run_id")
        by_id[run["run_id"]] = run
        config = {k: run["provenance"][k] for k in ("engine", "engine_version", "rules_digest")}
        if engine_config is not None and config != engine_config:
            raise ValueError("rule engine/version/digest must be identical across layers")
        engine_config = config
        grouped[run["layer"]].append(run)
    for run in runs:
        layer = run["layer"]
        if layer == "rules":
            if run.get("parent_run_id") is not None:
                raise ValueError("rules snapshot cannot have a parent")
        else:
            parent = by_id.get(run.get("parent_run_id"))
            expected = LAYERS[LAYERS.index(layer) - 1]
            if not parent or parent["layer"] != expected:
                raise ValueError(f"{layer} requires a completed {expected} parent snapshot")
            if run["duration_seconds"] < parent["duration_seconds"]:
                raise ValueError("cumulative duration cannot be less than the parent duration")
            if (run.get("cost_usd") is not None and parent.get("cost_usd") is not None
                    and run["cost_usd"] < parent["cost_usd"]):
                raise ValueError("cumulative cost cannot be less than the parent cost")
            previous = parent["provenance"]["analysis"]
            if run["provenance"]["analysis"][:len(previous)] != previous:
                raise ValueError("model history must preserve the parent snapshot's analysis provenance")
            def candidate_key(f):
                return (_path(f["file"]), f["start_line"], f.get("end_line", f["start_line"]),
                        tuple(sorted(f.get("cwe", []))), f.get("rule_id"), f.get("fingerprint"))
            if not {candidate_key(f) for f in parent["findings"]} <= {candidate_key(f) for f in run["findings"]}:
                raise ValueError("cumulative snapshots must retain every parent finding; record explicit review decisions to dismiss candidates")
    result = {"schema_version": VERSION, "dataset_id": dataset["id"], "dataset_digest": dataset["_digest"],
              "complete": all(grouped.get(layer) for layer in LAYERS), "layers": {}, "deltas": {}, "gaps": [],
              "unmatched_policy": dataset.get("unmatched_policy", "unscored")}
    for layer in LAYERS:
        members = grouped[layer]
        if not members:
            result["layers"][layer] = {"status": "pending", "runs": []}
            result["gaps"].append(f"{layer}: no completed measured run supplied")
            continue
        if len({_canonical(r["provenance"]) for r in members}) != 1:
            raise ValueError("repeatability requires identical model/rule configuration within a layer")
        scored = [{"run_id": r["run_id"], "parent_run_id": r.get("parent_run_id"), "metrics": _score(dataset, r),
                   "duration_seconds": r["duration_seconds"], "cost_usd": r.get("cost_usd")} for r in members]
        stability = []
        for a, b in combinations(scored, 2):
            x, y = set(a["metrics"]["detection_keys"]), set(b["metrics"]["detection_keys"])
            stability.append(len(x & y) / len(x | y) if x | y else 1.0)
        stats = {"status": "measured", "runs": scored, "provenance": members[0]["provenance"],
                 "stability_jaccard": statistics.mean(stability) if stability else None,
                 "mean_duration_seconds": statistics.mean(r["duration_seconds"] for r in members),
                 "mean_cost_usd": statistics.mean(r["cost_usd"] for r in members)
                 if all(r.get("cost_usd") is not None for r in members) else None}
        for metric in ("precision", "recall", "false_positive_rate", "f1"):
            values = [r["metrics"][metric] for r in scored]
            stats["mean_" + metric] = statistics.mean(values) if all(v is not None for v in values) else None
        result["layers"][layer] = stats
        unadjudicated = sum(r["metrics"]["unadjudicated_findings"] for r in scored)
        if unadjudicated:
            result["gaps"].append(f"{layer}: {unadjudicated} extra findings are unadjudicated and excluded from scoped precision")
    baseline = result["layers"]["rules"]
    for layer in LAYERS[1:]:
        stage = result["layers"][layer]
        if stage["status"] == baseline["status"] == "measured":
            result["deltas"][layer + "_vs_rules"] = {
                key: stage[key] - baseline[key] if stage[key] is not None and baseline[key] is not None else None
                for key in ("mean_precision", "mean_recall", "mean_false_positive_rate", "mean_duration_seconds", "mean_cost_usd")}
    return result


def _write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n")


def prepare_benchmark(dataset: dict, output_dir: str | Path, scanner=None) -> dict:
    from normalize_findings import normalize_semgrep, compute_fingerprint, compute_fingerprint_v1
    from run_semgrep import run_semgrep

    output = Path(output_dir).resolve()
    if any((output / name).exists() for name in ("rules.json", "analysis-packet.json", "rules-llm.template.json", "full.template.json")):
        raise ValueError("output already contains a benchmark run; choose a fresh output directory")
    root = Path(dataset["_root"])
    files = {_path(c["file"]): c["source_sha256"] for c in dataset["cases"]}
    sources = {}
    for file, expected in sorted(files.items()):
        content = (root / file).read_bytes()
        if hashlib.sha256(content).hexdigest() != expected:
            raise ValueError("source hash changed before scan")
        sources[file] = content.decode("utf-8")
    rules_digest = _digest({str(p.relative_to(RULES)): hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in sorted(RULES.rglob("*.yml"))})
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="opensast-layer-input-") as tmp:
        staged = Path(tmp)
        for file, content in sources.items():
            path = staged / file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content.encode("utf-8"))
        result = (scanner or run_semgrep)(str(staged), str(output / "raw"), config_paths=[str(RULES)])
        if not result.get("success") or result.get("exit_code") not in (0, 1) or not result.get("sarif_path"):
            raise ValueError(f"rule scan failed: {result.get('error_message') or result.get('exit_code')}")
        sarif = json.loads(Path(result["sarif_path"]).read_text())
        if not result.get("json_path"):
            raise ValueError("rule scan missing raw JSON coverage evidence")
        raw = json.loads(Path(result["json_path"]).read_text())
        if raw.get("errors") or raw.get("skipped_rules"):
            raise ValueError("rule scan incomplete: scanner errors or skipped rules")
        scanned = raw.get("paths", {}).get("scanned")
        if not isinstance(scanned, list):
            raise ValueError("rule scan missing scanned-file coverage")
        covered = {str((staged / p).resolve()) for p in scanned}
        if not {str((staged / f).resolve()) for f in sources} <= covered:
            raise ValueError("rule scan incomplete: dataset files were skipped")
        invocations = [i for r in sarif.get("runs", []) for i in r.get("invocations", [])]
        if not invocations or any(i.get("executionSuccessful") is not True or any(
                n.get("level", "warning") in {"warning", "error"}
                for key in ("toolExecutionNotifications", "toolConfigurationNotifications") for n in i.get(key, []))
                for i in invocations):
            raise ValueError("rule scan incomplete: SARIF execution diagnostics")
        findings = normalize_semgrep(sarif)
        for f in findings:
            path = Path(f["file"])
            if path.is_absolute():
                f["file"] = str(path.resolve().relative_to(staged.resolve()))
            f["fingerprint"] = compute_fingerprint(f)
            f["fingerprint_v1"] = compute_fingerprint_v1(f)
            f["id"] = "F-" + hashlib.sha256(f["fingerprint"].encode()).hexdigest()[:12]
            for step in f.get("evidence", {}).get("dataflow", []):
                if step.get("file") and Path(step["file"]).is_absolute():
                    step["file"] = str(Path(step["file"]).resolve().relative_to(staged.resolve()))
    run = {"schema_version": VERSION, "dataset_id": dataset["id"], "dataset_digest": dataset["_digest"],
           "layer": "rules", "run_id": "rules-" + uuid.uuid4().hex[:12], "parent_run_id": None,
           "complete": True, "findings": findings, "duration_seconds": time.monotonic() - started, "cost_usd": 0,
           "provenance": {"engine": "semgrep", "engine_version": result.get("version"),
                          "rules_digest": rules_digest, "analysis": []}}
    _validate_run(dataset, run)
    packet = {"schema_version": VERSION, "dataset_id": dataset["id"], "dataset_digest": dataset["_digest"],
              "instructions": INSTRUCTIONS, "files": [{"file": f, "content": s} for f, s in sources.items()],
              "rule_findings": findings}
    _write(output / "rules.json", run)
    _write(output / "analysis-packet.json", packet)
    for layer in LAYERS[1:]:
        template = deepcopy(run)
        template.update(layer=layer, run_id="pending-" + layer, parent_run_id=run["run_id"] if layer == "rules-llm" else None,
                        complete=False, findings=[], duration_seconds=None, cost_usd=None)
        phases = ["llm"] if layer == "rules-llm" else ["llm", "agent"]
        template["provenance"]["analysis"] = [{"phase": p, "provider": "REPLACE", "model": "REPLACE", "model_version": "REPLACE",
                                                "prompt_digest": _digest(INSTRUCTIONS), "parameters": {}} for p in phases]
        _write(output / (layer + ".template.json"), template)
    return run


def format_report(result: dict) -> str:
    def fmt(value):
        return "unreported" if value is None else f"{value:.4f}"
    lines = ["# Whitebox Layer Comparison", "", f"Dataset: `{result['dataset_id']}` / `{result['dataset_digest']}`",
             "", "| Layer | Status | Runs | Precision | Recall | FPR | Mean seconds | Mean API USD | Repeat Jaccard |",
             "|---|---|---:|---:|---:|---:|---:|---:|---:|"]
    for layer, stats in result["layers"].items():
        cells = [layer, stats["status"], str(len(stats["runs"]))]
        cells.extend(fmt(stats.get(k)) for k in ("mean_precision", "mean_recall", "mean_false_positive_rate", "mean_duration_seconds",
                                               "mean_cost_usd", "stability_jaccard"))
        lines.append("| " + " | ".join(cells) + " |")
    lines += ["", f"Unmatched finding policy: `{result['unmatched_policy']}`. FPR uses only labeled negative cases.",
              "Unscored extra findings require adjudication; scoped precision is not whole-repository precision.",
              "Durations and API costs are cumulative per snapshot; missing costs are unknown. One run cannot establish repeatability.",
              "Model runs are supplied by the Skill session; this command does not run AI.", "", "## Evidence gaps", ""]
    lines += ["- " + gap for gap in result["gaps"]] or ["- All three layers have completed snapshots."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("prepare", "compare"):
        p = sub.add_parser(command)
        p.add_argument("--dataset", required=True)
        p.add_argument("--output-dir", required=True)
        if command == "compare":
            p.add_argument("--run", action="append", required=True, help="Completed cumulative snapshot; repeat for layers/reruns")
    args = parser.parse_args(argv)
    try:
        dataset = load_dataset(args.dataset)
        if args.command == "prepare":
            run = prepare_benchmark(dataset, args.output_dir)
            print(f"Prepared real rule baseline {run['run_id']}; AI templates remain incomplete.")
            return 0
        runs = [json.loads(Path(path).read_text()) for path in args.run]
        result = build_comparison(dataset, runs)
        output = Path(args.output_dir)
        _write(output / "comparison.json", result)
        (output / "comparison.md").write_text(format_report(result))
        print(format_report(result))
        return 0 if result["complete"] else 3
    except (ValueError, OSError, TypeError, KeyError) as exc:
        print(f"Benchmark error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
