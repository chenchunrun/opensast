"""Generate a precision/recall summary table for tests/samples/corpus."""

from __future__ import annotations

import argparse
import json
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
TESTS_DIR = os.path.join(REPO_ROOT, "tests")
sys.path.insert(0, TESTS_DIR)

from test_corpus import CORPUS_DIR, _validate_corpus_file  # noqa: E402


def build_corpus_report(corpus_dir: str = CORPUS_DIR) -> dict:
    rows: list[dict] = []
    totals = {"ruleid": 0, "ok": 0, "missed": 0, "false_positives": 0}

    for name in sorted(os.listdir(corpus_dir)):
        path = os.path.join(corpus_dir, name)
        if not os.path.isfile(path) or name.startswith("_"):
            continue
        result = _validate_corpus_file(path)
        rows.append({
            "file": result["file"],
            "ruleid": result["total_ruleid"],
            "ok": result["total_ok"],
            "missed": len(result["missed"]),
            "false_positives": len(result["false_positives"]),
            "recall": round(result["recall"], 3),
            "precision": round(result["precision"], 3),
        })
        totals["ruleid"] += result["total_ruleid"]
        totals["ok"] += result["total_ok"]
        totals["missed"] += len(result["missed"])
        totals["false_positives"] += len(result["false_positives"])

    overall_recall = 1.0 - (totals["missed"] / max(totals["ruleid"], 1))
    overall_precision = 1.0 - (totals["false_positives"] / max(totals["ruleid"] + totals["false_positives"], 1))

    return {
        "corpus_dir": corpus_dir,
        "files": rows,
        "overall": {
            "ruleid_annotations": totals["ruleid"],
            "ok_annotations": totals["ok"],
            "missed": totals["missed"],
            "false_positives": totals["false_positives"],
            "recall": round(overall_recall, 3),
            "precision": round(overall_precision, 3),
        },
    }


def format_markdown(report: dict) -> str:
    lines = [
        "# Corpus Validation Report",
        "",
        f"**Corpus:** `{report['corpus_dir']}`",
        "",
        "| File | ruleid | ok | Missed | FP | Recall | Precision |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in report["files"]:
        lines.append(
            f"| {row['file']} | {row['ruleid']} | {row['ok']} | {row['missed']} | "
            f"{row['false_positives']} | {row['recall']:.0%} | {row['precision']:.0%} |"
        )
    overall = report["overall"]
    lines.extend([
        "",
        "## Overall",
        "",
        f"- **Recall:** {overall['recall']:.1%} ({overall['missed']} missed / {overall['ruleid_annotations']} ruleid)",
        f"- **Precision:** {overall['precision']:.1%} ({overall['false_positives']} FP on ok lines)",
        "",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize corpus precision/recall")
    parser.add_argument("--corpus-dir", default=CORPUS_DIR)
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", help="Optional output file path")
    args = parser.parse_args(argv)

    report = build_corpus_report(args.corpus_dir)
    content = json.dumps(report, indent=2) if args.format == "json" else format_markdown(report)

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"Wrote {args.output}")
    else:
        print(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
