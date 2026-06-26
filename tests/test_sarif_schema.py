"""Test SARIF 2.1.0 schema compliance of merged SAST output."""

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from sarif_merge import merge_sarif_files


SARIF_SCHEMA_REQUIRED_TOP = {
    "$schema",
    "version",
    "runs",
}

SARIF_RUN_REQUIRED = {
    "tool",
    "results",
}

SARIF_TOOL_REQUIRED = {
    "driver",
}

SARIF_DRIVER_REQUIRED = {
    "name",
}

SARIF_RESULT_REQUIRED = {
    "message",
    "ruleId",
}

SARIF_RESULT_OPTIONAL = {
    "level",
    "locations",
    "properties",
    "fingerprints",
    "partialFingerprints",
    "kind",
    "rank",
    "fixes",
    "webRequest",
    "webResponse",
    "codeFlows",
    "relatedLocations",
    "suppressions",
    "baselineState",
    "taxa",
    "attachments",
    "hostedViewerUri",
    "provenance",
    "stacks",
    "graphTraversals",
    "threadFlowLocations",
    "workItemUris",
}


def _validate_sarif_baseline(sarif_data: dict) -> list[str]:
    """Validate SARIF 2.1.0 structural compliance."""
    errors: list[str] = []

    if not isinstance(sarif_data, dict):
        return ["SARIF root is not a dict"]

    # Top-level
    missing_top = SARIF_SCHEMA_REQUIRED_TOP - set(sarif_data.keys())
    if missing_top:
        errors.append(f"Missing top-level keys: {missing_top}")
    if sarif_data.get("version") != "2.1.0":
        errors.append(f"Invalid version: {sarif_data.get('version')}")

    for run_idx, run in enumerate(sarif_data.get("runs", [])):
        prefix = f"runs[{run_idx}]"
        missing_run = SARIF_RUN_REQUIRED - set(run.keys())
        if missing_run:
            errors.append(f"{prefix}: missing required keys {missing_run}")

        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        if not isinstance(driver, dict) or "name" not in driver:
            errors.append(f"{prefix}.tool.driver: missing 'name'")

        for res_idx, result in enumerate(run.get("results", [])):
            rp = f"{prefix}.results[{res_idx}]"
            missing_res = SARIF_RESULT_REQUIRED - set(result.keys())
            if missing_res:
                errors.append(f"{rp}: missing required keys {missing_res}")
            if not isinstance(result.get("message"), dict) or "text" not in result.get("message", {}):
                errors.append(f"{rp}: message must be an object with 'text'")

    return errors


def test_merged_sarif_schema_compliance():
    """Verify merged.sarif output conforms to SARIF 2.1.0 structure."""
    sarif_path = os.path.join(
        os.path.dirname(__file__), "..", ".claude", "sast", "results", "merged.sarif"
    )
    if not os.path.isfile(sarif_path):
        pytest.skip("No merged.sarif found — run a scan first")

    with open(sarif_path, encoding="utf-8") as f:
        data = json.load(f)

    errors = _validate_sarif_baseline(data)
    assert not errors, f"SARIF schema errors:\n" + "\n".join(f"  - {e}" for e in errors)


def test_sarif_from_empty_scan_is_valid():
    """Empty scan results must still produce valid SARIF."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = os.path.join(tmpdir, "empty.sarif")
        merge_sarif_files([], out)
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        errors = _validate_sarif_baseline(data)
        assert not errors, f"Empty SARIF validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
        if data.get("runs"):
            assert data["runs"][0]["results"] == []


# Allow running standalone
if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
