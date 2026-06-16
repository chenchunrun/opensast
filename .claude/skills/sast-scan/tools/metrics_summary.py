"""Emit a Markdown metrics block for docs and promotion materials."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

TOOLS_DIR = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(TOOLS_DIR, "..", "..", "..", ".."))
RULES_DIR = os.path.join(TOOLS_DIR, "..", "rules", "semgrep")
BENCHMARK_JSON = os.path.join(REPO_ROOT, "benchmark", "results", "owasp-benchmark.json")


def _pytest_count() -> str:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            return "unknown"
        combined = result.stdout + result.stderr
        match = re.search(r"(\d+)\s+tests?\s+collected", combined)
        if match:
            return match.group(1)
    except Exception:
        pass
    return "unknown"


def _rule_coverage() -> dict:
    sys.path.insert(0, TOOLS_DIR)
    from test_rules import audit_rule_coverage

    return audit_rule_coverage(RULES_DIR).get("summary", {})


def _benchmark_score() -> dict | None:
    if not os.path.isfile(BENCHMARK_JSON):
        return None
    try:
        with open(BENCHMARK_JSON, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def build_metrics() -> dict:
    coverage = _rule_coverage()
    benchmark = _benchmark_score()
    languages = sorted(
        name for name in os.listdir(RULES_DIR)
        if os.path.isdir(os.path.join(RULES_DIR, name)) and not name.startswith(".")
    )
    metrics = {
        "tests_collected": _pytest_count(),
        "rule_files": coverage.get("rule_files", 0),
        "total_rules": coverage.get("total_rules", 0),
        "covered_rules": coverage.get("covered_rules", 0),
        "coverage_pct": coverage.get("coverage_pct", 0),
        "languages_with_rules": len(languages),
        "languages": languages,
        "supplemental_tools": [
            "bandit", "gosec", "eslint", "brakeman", "cppcheck", "cargo-audit", "swiftlint", "phpstan",
        ],
    }
    if benchmark:
        overall = benchmark.get("overall_covered_categories") or benchmark.get("overall_all_categories") or {}
        score = overall.get("benchmark_score")
        metrics["owasp_benchmark"] = {
            "score_pct": round(score * 100, 1) if isinstance(score, (int, float)) else None,
            "tpr": round(overall.get("tpr", 0) * 100, 1) if overall.get("tpr") is not None else None,
            "fpr": round(overall.get("fpr", 0) * 100, 1) if overall.get("fpr") is not None else None,
        }
    return metrics


STATUS_DOC = os.path.join(TOOLS_DIR, "..", "docs", "status-and-usage.md")
METRICS_START = "<!-- metrics:auto:start -->"
METRICS_END = "<!-- metrics:auto:end -->"


def format_status_bullets(metrics: dict) -> str:
    owasp = metrics.get("owasp_benchmark") or {}
    score = owasp.get("score_pct")
    tpr = owasp.get("tpr")
    fpr = owasp.get("fpr")
    benchmark_line = (
        f"- OWASP Benchmark v1.2 (Java rules): **+{score}%** score "
        f"(TPR {tpr}%, FPR {fpr}%)"
        if score is not None
        else "- OWASP Benchmark v1.2: run `benchmark/run_owasp_benchmark.py` to refresh"
    )
    return "\n".join(
        [
            f"- Rule coverage audit: `{metrics['covered_rules']} / {metrics['total_rules']} = {metrics['coverage_pct']}%`",
            f"- Full local test suite: `{metrics['tests_collected']} passed` (pytest collected count)",
            "- Metrics snapshot: `python3 .claude/skills/sast-scan/tools/metrics_summary.py`",
            benchmark_line,
        ]
    )


def format_markdown(metrics: dict) -> str:
    lines = [
        "## OpenSAST Metrics",
        "",
        f"- **Tests collected:** {metrics['tests_collected']}",
        f"- **Semgrep rules:** {metrics['covered_rules']}/{metrics['total_rules']} covered ({metrics['coverage_pct']}%)",
        f"- **Rule languages:** {metrics['languages_with_rules']} ({', '.join(metrics['languages'])})",
        f"- **Supplemental tools:** {len(metrics['supplemental_tools'])} wired",
    ]
    owasp = metrics.get("owasp_benchmark")
    if owasp:
        lines.append(
            f"- **OWASP Benchmark v1.2:** {owasp.get('score_pct')}% "
            f"(TPR {owasp.get('tpr')}%, FPR {owasp.get('fpr')}%)"
        )
    lines.append("")
    return "\n".join(lines)


def sync_status_doc(path: str | None = None) -> bool:
    doc_path = os.path.abspath(path or STATUS_DOC)
    if not os.path.isfile(doc_path):
        return False
    metrics = build_metrics()
    block = "\n".join([METRICS_START, format_status_bullets(metrics), METRICS_END])
    with open(doc_path, encoding="utf-8") as fh:
        content = fh.read()
    if METRICS_START not in content or METRICS_END not in content:
        return False
    start = content.index(METRICS_START)
    end = content.index(METRICS_END) + len(METRICS_END)
    updated = content[:start] + block + content[end:]
    with open(doc_path, "w", encoding="utf-8") as fh:
        fh.write(updated)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print OpenSAST metrics as Markdown or JSON")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument(
        "--sync-status-doc",
        action="store_true",
        help="Update metrics bullets in status-and-usage.md between auto markers",
    )
    args = parser.parse_args(argv)

    metrics = build_metrics()
    if args.sync_status_doc:
        if not sync_status_doc():
            print("Failed to sync status doc (missing file or markers)", file=sys.stderr)
            return 1
        print(f"Updated metrics in {STATUS_DOC}")
        return 0
    if args.format == "json":
        print(json.dumps(metrics, indent=2))
    else:
        print(format_markdown(metrics))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
