"""Unit tests for the OWASP Benchmark scorer (no semgrep / network needed)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "benchmark"))

from run_owasp_benchmark import (
    CATEGORY_CWES,
    collect_detections,
    extract_rule_cwes,
    score,
)


def _finding(path: str, cwes: list[str]) -> dict:
    return {"path": path, "extra": {"metadata": {"cwe": cwes}}}


def test_extract_rule_cwes_parses_cwe_strings():
    f = _finding("x.java", ["CWE-89", "CWE-78"])
    assert extract_rule_cwes(f) == {89, 78}


def test_extract_rule_cwes_handles_string_and_missing():
    assert extract_rule_cwes({"path": "x", "extra": {"metadata": {"cwe": "CWE-22"}}}) == {22}
    assert extract_rule_cwes({"path": "x", "extra": {}}) == set()


def test_collect_detections_maps_testcase_names():
    findings = [
        _finding("a/b/BenchmarkTest00001.java", ["CWE-89"]),
        _finding("a/b/BenchmarkTest00001.java", ["CWE-78"]),
        _finding("a/b/BenchmarkTest00002.java", ["CWE-328"]),
        _finding("a/b/NotATestCase.java", ["CWE-89"]),
    ]
    det = collect_detections(findings)
    assert det == {
        "BenchmarkTest00001": {89, 78},
        "BenchmarkTest00002": {328},
    }


def test_score_counts_tp_fn_fp_tn():
    expected = {
        "BenchmarkTest00001": {"category": "sqli", "real": True, "cwe": 89},
        "BenchmarkTest00002": {"category": "sqli", "real": True, "cwe": 89},
        "BenchmarkTest00003": {"category": "sqli", "real": False, "cwe": 89},
        "BenchmarkTest00004": {"category": "sqli", "real": False, "cwe": 89},
    }
    detections = {
        "BenchmarkTest00001": {89},   # TP
        "BenchmarkTest00003": {89},   # FP
        # 00002 -> FN, 00004 -> TN
    }
    result = score(expected, detections)
    sqli = result["per_category"]["sqli"]
    assert (sqli["tp"], sqli["fn"], sqli["fp"], sqli["tn"]) == (1, 1, 1, 1)
    assert sqli["tpr"] == 0.5
    assert sqli["fpr"] == 0.5
    assert sqli["benchmark_score"] == 0.0
    assert result["covered_categories"] == ["sqli"]


def test_score_ignores_unrelated_cwe_detections():
    expected = {
        "BenchmarkTest00001": {"category": "sqli", "real": True, "cwe": 89},
    }
    # CWE-362 (thread safety) is not an accepted CWE for sqli
    detections = {"BenchmarkTest00001": {362}}
    result = score(expected, detections)
    sqli = result["per_category"]["sqli"]
    assert sqli["tp"] == 0
    assert sqli["fn"] == 1


def test_score_accepts_child_cwe_equivalents():
    # weakrand accepts CWE-338 (child of CWE-330)
    assert 338 in CATEGORY_CWES["weakrand"]
    expected = {
        "BenchmarkTest00001": {"category": "weakrand", "real": True, "cwe": 330},
    }
    result = score(expected, {"BenchmarkTest00001": {338}})
    assert result["per_category"]["weakrand"]["tp"] == 1
