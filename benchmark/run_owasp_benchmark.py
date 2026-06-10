#!/usr/bin/env python3
"""Run OpenSAST Semgrep rules against the OWASP Benchmark (Java) and score them.

The OWASP Benchmark v1.2 ships 2,740 test cases (1,415 real vulnerabilities and
1,325 false-positive traps) across 11 vulnerability categories, with a ground
truth CSV (expectedresults-1.2.csv). This script:

1. Runs the OpenSAST Java Semgrep rules over the benchmark test cases.
2. Maps findings to benchmark categories via CWE metadata.
3. Scores per category: TP / FP / TN / FN, TPR, FPR, precision, F1, and the
   official Benchmark score (TPR - FPR).

Setup (one-time, ~5 MB sparse checkout):

    mkdir -p benchmark/.cache && cd benchmark/.cache
    git clone --depth 1 --filter=blob:none --sparse \
        https://github.com/OWASP-Benchmark/BenchmarkJava.git BenchmarkJava
    cd BenchmarkJava
    git sparse-checkout set --no-cone \
        '/src/main/java/org/owasp/benchmark/testcode/*.java' \
        '/expectedresults-1.2.csv'

Usage:

    python3 benchmark/run_owasp_benchmark.py
    python3 benchmark/run_owasp_benchmark.py --output benchmark/results/report.md
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, ".claude", "skills", "sast-scan", "tools"))

from run_semgrep import build_semgrep_env, get_semgrep_binary  # noqa: E402

DEFAULT_BENCHMARK_DIR = os.path.join(REPO_ROOT, "benchmark", ".cache", "BenchmarkJava")
DEFAULT_RULES = os.path.join(
    REPO_ROOT, ".claude", "skills", "sast-scan", "rules", "semgrep", "java"
)

# Benchmark category -> set of CWE ids accepted as a detection for it.
# Includes close children/aliases (e.g. CWE-338 is a child of CWE-330).
CATEGORY_CWES = {
    "cmdi": {77, 78},
    "crypto": {326, 327, 329},
    "hash": {327, 328, 916},
    "ldapi": {90},
    "pathtraver": {22, 23, 36},
    "securecookie": {614, 1004},
    "sqli": {89},
    "trustbound": {501},
    "weakrand": {330, 336, 338},
    "xpathi": {643},
    "xss": {79, 80},
}

TESTCASE_RE = re.compile(r"(BenchmarkTest\d{5})\.java$")


def load_expected(benchmark_dir: str) -> dict[str, dict]:
    """Load ground truth: test name -> {category, real (bool), cwe}."""
    csv_path = os.path.join(benchmark_dir, "expectedresults-1.2.csv")
    expected: dict[str, dict] = {}
    with open(csv_path, encoding="utf-8") as fh:
        reader = csv.reader(fh)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            name, category, real, cwe = row[0].strip(), row[1].strip(), row[2].strip(), row[3].strip()
            expected[name] = {
                "category": category,
                "real": real.lower() == "true",
                "cwe": int(cwe),
            }
    return expected


def run_semgrep_scan(rules_path: str, testcode_dir: str, timeout: int = 1800) -> list[dict]:
    """Run semgrep over the benchmark test cases, return raw findings."""
    semgrep_bin = get_semgrep_binary()
    if not semgrep_bin:
        raise SystemExit("semgrep is not installed (pip install semgrep)")

    cmd = [
        semgrep_bin,
        "--config", rules_path,
        "--json",
        "--no-git-ignore",
        "--metrics", "off",
        "--timeout", "30",
        testcode_dir,
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
        env=build_semgrep_env(),
    )
    if result.returncode not in (0, 1, 2):
        raise SystemExit(
            f"semgrep failed (exit {result.returncode}):\n{result.stderr[-2000:]}"
        )
    data = json.loads(result.stdout)
    return data.get("results", [])


def extract_rule_cwes(finding: dict) -> set[int]:
    """Pull CWE ids out of a semgrep finding's rule metadata."""
    cwes: set[int] = set()
    meta = finding.get("extra", {}).get("metadata", {})
    raw = meta.get("cwe", [])
    if isinstance(raw, str):
        raw = [raw]
    for item in raw:
        m = re.search(r"(\d+)", str(item))
        if m:
            cwes.add(int(m.group(1)))
    return cwes


def collect_detections(findings: list[dict]) -> dict[str, set[int]]:
    """Map test case name -> set of CWE ids reported in that file."""
    detections: dict[str, set[int]] = {}
    for f in findings:
        m = TESTCASE_RE.search(f.get("path", ""))
        if not m:
            continue
        detections.setdefault(m.group(1), set()).update(extract_rule_cwes(f))
    return detections


def score(expected: dict[str, dict], detections: dict[str, set[int]]) -> dict:
    """Score detections against ground truth, per category and aggregate."""
    cats: dict[str, dict] = {
        c: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for c in CATEGORY_CWES
    }
    for name, truth in expected.items():
        category = truth["category"]
        accepted = CATEGORY_CWES.get(category, {truth["cwe"]})
        detected = bool(detections.get(name, set()) & accepted)
        bucket = cats[category]
        if truth["real"]:
            bucket["tp" if detected else "fn"] += 1
        else:
            bucket["fp" if detected else "tn"] += 1

    def derive(b: dict) -> dict:
        tp, fp, tn, fn = b["tp"], b["fp"], b["tn"], b["fn"]
        tpr = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        precision = tp / (tp + fp) if tp + fp else 0.0
        f1 = 2 * precision * tpr / (precision + tpr) if precision + tpr else 0.0
        return {
            **b,
            "tpr": tpr, "fpr": fpr, "precision": precision, "f1": f1,
            "benchmark_score": tpr - fpr,
            "total": tp + fp + tn + fn,
        }

    per_category = {c: derive(b) for c, b in cats.items()}
    covered = {c: v for c, v in per_category.items() if v["tp"] + v["fp"] > 0}

    def aggregate(rows: dict) -> dict:
        agg = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        for v in rows.values():
            for k in agg:
                agg[k] += v[k]
        return derive(agg)

    return {
        "per_category": per_category,
        "overall_all_categories": aggregate(per_category),
        "overall_covered_categories": aggregate(covered) if covered else None,
        "covered_categories": sorted(covered),
    }


def format_report(result: dict, elapsed: float, n_findings: int, rules_path: str) -> str:
    lines = [
        "# OWASP Benchmark v1.2 — OpenSAST Rule Engine Score",
        "",
        f"- Rules: `{os.path.relpath(rules_path, REPO_ROOT)}`",
        f"- Test cases: 2,740 (1,415 true vulnerabilities / 1,325 false-positive traps)",
        f"- Raw semgrep findings: {n_findings}",
        f"- Scan wall time: {elapsed:.0f}s",
        "",
        "## Per-category results",
        "",
        "| Category | Cases | TP | FN | FP | TN | TPR | FPR | Precision | F1 | Score(TPR-FPR) |",
        "|----------|------:|---:|---:|---:|---:|----:|----:|----------:|---:|---------------:|",
    ]
    for cat in sorted(result["per_category"]):
        v = result["per_category"][cat]
        covered = "" if cat in result["covered_categories"] else " *"
        lines.append(
            f"| {cat}{covered} | {v['total']} | {v['tp']} | {v['fn']} | {v['fp']} | {v['tn']} "
            f"| {v['tpr']:.1%} | {v['fpr']:.1%} | {v['precision']:.1%} | {v['f1']:.2f} "
            f"| {v['benchmark_score']:+.1%} |"
        )
    lines.append("")
    lines.append("`*` = no OpenSAST rule fired in this category (out of rule coverage).")
    lines.append("")

    for label, key in [
        ("All 11 categories", "overall_all_categories"),
        ("Covered categories only", "overall_covered_categories"),
    ]:
        v = result[key]
        if not v:
            continue
        lines += [
            f"## Overall — {label}",
            "",
            f"- TP {v['tp']} / FN {v['fn']} / FP {v['fp']} / TN {v['tn']}",
            f"- Recall (TPR): **{v['tpr']:.1%}**",
            f"- FPR: **{v['fpr']:.1%}**",
            f"- Precision: **{v['precision']:.1%}**",
            f"- F1: **{v['f1']:.2f}**",
            f"- OWASP Benchmark score (TPR-FPR): **{v['benchmark_score']:+.1%}**",
            "",
        ]
    lines.append(
        "Reference points (official OWASP Benchmark scorecards, full toolset): "
        "free SAST tools typically score between 0% and ~35%; "
        "commercial tool average is ~26%; SpotBugs+FindSecBugs ~39%."
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-dir", default=DEFAULT_BENCHMARK_DIR)
    parser.add_argument("--rules", default=DEFAULT_RULES)
    parser.add_argument("--output", help="Write markdown report to this path")
    parser.add_argument("--json-output", help="Write raw scoring JSON to this path")
    args = parser.parse_args()

    testcode = os.path.join(
        args.benchmark_dir, "src", "main", "java", "org", "owasp", "benchmark", "testcode"
    )
    if not os.path.isdir(testcode):
        print(f"Benchmark test cases not found at {testcode}.\nSee setup in the module docstring.")
        return 1

    expected = load_expected(args.benchmark_dir)
    print(f"Loaded ground truth: {len(expected)} test cases")

    t0 = time.time()
    findings = run_semgrep_scan(args.rules, testcode)
    elapsed = time.time() - t0
    print(f"Semgrep finished in {elapsed:.0f}s with {len(findings)} raw findings")

    detections = collect_detections(findings)
    result = score(expected, detections)

    report = format_report(result, elapsed, len(findings), args.rules)
    print()
    print(report)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        print(f"\nReport written to {args.output}")
    if args.json_output:
        os.makedirs(os.path.dirname(args.json_output) or ".", exist_ok=True)
        with open(args.json_output, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"JSON written to {args.json_output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
