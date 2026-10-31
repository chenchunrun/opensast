"""Tests for SARIF merge functionality."""

import json
import os
import tempfile

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from sarif_merge import (
    filter_sarif_excluded_paths,
    load_sarif,
    merge_sarif_files,
    normalize_paths_in_sarif,
    remap_sarif_prefixes,
)


def _make_sarif(tool_name: str = "test-tool", rules: list | None = None, results: list | None = None) -> dict:
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool_name, "version": "1.0", "rules": rules or []}},
            "results": results or [],
        }],
    }


def test_load_sarif_valid():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
        json.dump(_make_sarif(), f)
        path = f.name
    try:
        result = load_sarif(path)
        assert result is not None
        assert result["version"] == "2.1.0"
        assert len(result["runs"]) == 1
    finally:
        os.unlink(path)


def test_load_sarif_invalid_version():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
        json.dump({"version": "1.0.0", "runs": []}, f)
        path = f.name
    try:
        result = load_sarif(path)
        assert result is None
    finally:
        os.unlink(path)


def test_load_sarif_missing_file():
    result = load_sarif("/nonexistent/path.sarif")
    assert result is None


def test_load_sarif_invalid_json():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
        f.write("not json")
        path = f.name
    try:
        result = load_sarif(path)
        assert result is None
    finally:
        os.unlink(path)


def test_merge_sarif_files():
    sarif1 = _make_sarif("tool1", results=[{"ruleId": "R1", "level": "error"}])
    sarif2 = _make_sarif("tool2", results=[{"ruleId": "R2", "level": "warning"}])

    with tempfile.TemporaryDirectory() as tmpdir:
        path1 = os.path.join(tmpdir, "a.sarif")
        path2 = os.path.join(tmpdir, "b.sarif")
        output = os.path.join(tmpdir, "merged.sarif")

        with open(path1, "w") as f:
            json.dump(sarif1, f)
        with open(path2, "w") as f:
            json.dump(sarif2, f)

        merged = merge_sarif_files([path1, path2], output)

        assert merged["version"] == "2.1.0"
        assert len(merged["runs"]) == 2
        assert os.path.isfile(output)

        with open(output) as f:
            saved = json.load(f)
        assert len(saved["runs"]) == 2


def test_merge_skips_invalid():
    sarif1 = _make_sarif("tool1")
    with tempfile.TemporaryDirectory() as tmpdir:
        path1 = os.path.join(tmpdir, "a.sarif")
        output = os.path.join(tmpdir, "merged.sarif")

        with open(path1, "w") as f:
            json.dump(sarif1, f)

        merged = merge_sarif_files([path1, "/nonexistent.sarif"], output)
        assert len(merged["runs"]) == 1


def test_normalize_paths():
    sarif = _make_sarif(results=[{
        "ruleId": "R1",
        "level": "error",
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": "/home/user/project/src/app.py"},
                "region": {"startLine": 10},
            }
        }],
    }])

    result = normalize_paths_in_sarif(sarif, "/home/user/project")
    loc_uri = result["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert loc_uri == "src/app.py"


def test_remap_sarif_prefixes_rewrites_staged_paths():
    staged = os.path.join(tempfile.gettempdir(), "opensast-scan-abc")
    repo = "/home/user/project"
    sarif = _make_sarif(results=[{
        "ruleId": "R1",
        "level": "error",
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": os.path.join(staged, "pkg", "app.py")},
                "region": {"startLine": 3},
            }
        }],
    }])

    result = remap_sarif_prefixes(sarif, staged, repo)
    uri = result["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == os.path.join(repo, "pkg", "app.py")
    # original dict untouched
    original_uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert original_uri.startswith(staged)


def test_remap_sarif_prefixes_without_staged_root_is_noop():
    sarif = _make_sarif(results=[{"ruleId": "R1"}])
    assert remap_sarif_prefixes(sarif, None, "/repo") is sarif


def test_remap_sarif_prefixes_leaves_outside_paths_alone():
    sarif = _make_sarif(results=[{
        "ruleId": "R1",
        "locations": [{
            "physicalLocation": {"artifactLocation": {"uri": "/elsewhere/app.py"}}
        }],
    }])
    result = remap_sarif_prefixes(sarif, "/tmp/opensast-scan-abc", "/repo")
    uri = result["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "/elsewhere/app.py"


def test_filter_sarif_excluded_paths_drops_excluded_results():
    def result_with_uri(rule_id: str, uri: str) -> dict:
        return {
            "ruleId": rule_id,
            "level": "error",
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 1}}
            }],
        }

    sarif = _make_sarif(results=[
        result_with_uri("R1", "pkg/app.py"),
        result_with_uri("R2", "examples/pkg/app.py"),
        result_with_uri("R3", "examples_app.py"),  # prefix collision guard
    ])
    filtered = filter_sarif_excluded_paths(sarif, ["examples"])
    uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in filtered["runs"][0]["results"]]
    assert sorted(uris) == ["examples_app.py", "pkg/app.py"]
    # original untouched
    assert len(sarif["runs"][0]["results"]) == 3
