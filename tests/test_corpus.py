"""Validate rules against the test corpus.

Scans corpus files with Semgrep and checks:
- Lines marked # ruleid: should produce a finding
- Lines marked # ok: should NOT produce a finding

Reports per-rule precision and recall.
"""

import json
import os
import re
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from run_semgrep import build_semgrep_env, get_semgrep_binary

CORPUS_DIR = os.path.join(os.path.dirname(__file__), "samples", "corpus")
RULES_DIR = os.path.join(
    os.path.dirname(__file__), "..",
    ".claude", "skills", "sast-scan", "rules", "semgrep",
)
COMMENT_PATTERNS = {
    ".py": ("# ruleid: ", "# ok: "),
    ".ts": ("// ruleid: ", "// ok: "),
    ".tsx": ("// ruleid: ", "// ok: "),
    ".js": ("// ruleid: ", "// ok: "),
    ".java": ("// ruleid: ", "// ok: "),
    ".go": ("// ruleid: ", "// ok: "),
    ".php": ("// ruleid: ", "// ok: "),
    ".rb": ("# ruleid: ", "# ok: "),
    ".c": ("// ruleid: ", "// ok: "),
    ".cpp": ("// ruleid: ", "// ok: "),
    ".rs": ("// ruleid: ", "// ok: "),
}


def _parse_annotations(file_path: str) -> dict:
    """Parse # ruleid: and # ok: annotations from a corpus file."""
    ruleid_lines = {}  # line_no → rule_id (or True if unspecified)
    ok_lines = {}  # line_no → rule_id (or True)

    ext = os.path.splitext(file_path)[1]
    if ext not in COMMENT_PATTERNS:
        return {"ruleid": ruleid_lines, "ok": ok_lines}

    rid_marker, ok_marker = COMMENT_PATTERNS[ext]

    with open(file_path, encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            stripped = line.strip()
            if stripped.startswith(rid_marker):
                rule_id = stripped[len(rid_marker):].strip() or True
                ruleid_lines[i + 1] = rule_id
            elif stripped.startswith(ok_marker):
                rule_id = stripped[len(ok_marker):].strip() or True
                ok_lines[i + 1] = rule_id

    return {"ruleid": ruleid_lines, "ok": ok_lines}


def _run_semgrep_on_file(file_path: str) -> list[dict]:
    """Run Semgrep on a single corpus file and return findings."""
    semgrep_bin = get_semgrep_binary()
    if not semgrep_bin:
        return []
    try:
        result = subprocess.run(
            [
                semgrep_bin, "--config", RULES_DIR,
                "--json", "--no-git-ignore",
                file_path,
            ],
            capture_output=True, text=True, timeout=30,
            env=build_semgrep_env(),
        )
        if result.returncode not in (0, 1, 2):
            return []
        data = json.loads(result.stdout)
        findings = []
        for run in data.get("results", []):
            findings.append({
                "rule_id": run.get("check_id", ""),
                "line": run.get("start", {}).get("line", 0),
            })
        return findings
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return []


def _validate_corpus_file(file_path: str) -> dict:
    """Validate a corpus file and return results."""
    annotations = _parse_annotations(file_path)
    findings = _run_semgrep_on_file(file_path)

    finding_lines = {f["line"] for f in findings}
    finding_rules = {f["line"]: f["rule_id"] for f in findings}

    # Check ruleid annotations (should trigger within +1/+2 lines)
    missed = []
    for line_no, rule_id in annotations["ruleid"].items():
        if not any(l in finding_lines for l in range(line_no, line_no + 3)):
            missed.append({"line": line_no, "rule_id": rule_id})

    # Check ok annotations (should NOT trigger on exact code line)
    false_positives = []
    for line_no, rule_id in annotations["ok"].items():
        if line_no in finding_lines:
            false_positives.append({
                "line": line_no,
                "rule_id": rule_id,
                "triggered": finding_rules.get(line_no, "unknown"),
            })

    return {
        "file": os.path.basename(file_path),
        "total_ruleid": len(annotations["ruleid"]),
        "total_ok": len(annotations["ok"]),
        "missed": missed,
        "false_positives": false_positives,
        "precision": 1.0 - (len(false_positives) / max(len(finding_lines), 1)),
        "recall": 1.0 - (len(missed) / max(len(annotations["ruleid"]), 1)),
    }


class TestCorpusValidation:
    """Validate rules against corpus files (requires Semgrep installed)."""

    @pytest.fixture(autouse=True)
    def _check_semgrep(self):
        semgrep_bin = get_semgrep_binary()
        if not semgrep_bin:
            pytest.skip("Semgrep not installed")
        try:
            result = subprocess.run(
                [semgrep_bin, "--version"],
                capture_output=True, timeout=10,
                env=build_semgrep_env(),
            )
            if result.returncode != 0:
                pytest.skip("Semgrep installed but unusable in current environment")
        except FileNotFoundError:
            pytest.skip("Semgrep not installed")

    @pytest.mark.parametrize("filename", [
        f for f in os.listdir(CORPUS_DIR)
        if os.path.isfile(os.path.join(CORPUS_DIR, f))
        and not f.startswith("_")
        and f not in ("rust_rules_test.rs",)  # Semgrep Rust parser has limited support
    ])
    def test_corpus_file(self, filename):
        file_path = os.path.join(CORPUS_DIR, filename)
        result = _validate_corpus_file(file_path)

        # At least 70% recall (some rules may not match exactly)
        if result["total_ruleid"] > 0:
            assert result["recall"] >= 0.7, (
                f"{filename}: recall {result['recall']:.0%}, "
                f"missed {len(result['missed'])} ruleid annotations: {result['missed']}"
            )

        # At most 20% false positive rate on ok: lines
        if result["total_ok"] > 0:
            fp_rate = len(result["false_positives"]) / result["total_ok"]
            assert fp_rate <= 0.2, (
                f"{filename}: FP rate {fp_rate:.0%}, "
                f"false positives: {result['false_positives']}"
            )
