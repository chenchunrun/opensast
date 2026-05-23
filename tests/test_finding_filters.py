"""Tests for finding filters (false positive reduction)."""

import importlib.util
import os
import tempfile

_spec = importlib.util.spec_from_file_location(
    "finding_filters",
    os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools", "finding_filters.py"),
)
_ff = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ff)

is_test_code = _ff.is_test_code
is_generated_code = _ff.is_generated_code
compute_reachability = _ff.compute_reachability
apply_finding_filters = _ff.apply_finding_filters
_reduce_severity = _ff._reduce_severity


# --- Test code detection ---


def test_test_code_paths():
    assert is_test_code("tests/test_app.py")
    assert is_test_code("src/test/utils.py")
    assert is_test_code("app_test.go")
    assert is_test_code("spec/handler_spec.js")
    assert is_test_code("__tests__/component.test.tsx")
    assert is_test_code("my.test.js")


def test_not_test_code():
    assert not is_test_code("src/app.py")
    assert not is_test_code("lib/handler.go")
    assert not is_test_code("controllers/user.py")
    assert not is_test_code("testing_framework/README.md")  # path component but as directory


def test_generated_code_paths():
    assert is_generated_code("vendor/lib/a.py")
    assert is_generated_code("node_modules/react/index.js")
    assert is_generated_code("dist/bundle.js")
    assert is_generated_code("app.generated.ts")
    assert is_generated_code("api.pb.go")
    assert is_generated_code("styles.min.css")


def test_not_generated_code():
    assert not is_generated_code("src/app.py")
    assert not is_generated_code("lib/handler.go")
    assert not is_generated_code("components/Button.tsx")


def test_severity_reduction():
    assert _reduce_severity("critical") == "high"
    assert _reduce_severity("high") == "medium"
    assert _reduce_severity("medium") == "low"
    assert _reduce_severity("low") == "info"
    assert _reduce_severity("info") == "info"


# --- Apply filters ---


def test_apply_filters_reduces_test_code_severity():
    findings = [
        {"file": "tests/test_app.py", "severity": "high", "language": "python",
         "start_line": 10, "tool": "semgrep", "rule_id": "R1"},
    ]
    result = apply_finding_filters(findings, "/tmp/project")
    assert len(result) == 1
    assert result[0]["severity"] == "medium"
    assert result[0]["context"] == "test_code"
    assert result[0]["original_severity"] == "high"


def test_apply_filters_skips_generated_code():
    findings = [
        {"file": "vendor/lib/a.py", "severity": "critical", "language": "python",
         "start_line": 5, "tool": "semgrep", "rule_id": "R1"},
    ]
    result = apply_finding_filters(findings, "/tmp/project")
    assert len(result) == 1
    assert result[0]["is_suppressed"] is True


def test_apply_filters_skip_action_removes_finding():
    findings = [
        {"file": "tests/test_app.py", "severity": "high", "language": "python",
         "start_line": 10, "tool": "semgrep", "rule_id": "R1"},
    ]
    config = {"finding_filters": {"test_code": {"enabled": True, "severity_reduction": "skip"}}}
    result = apply_finding_filters(findings, "/tmp/project", config)
    assert len(result) == 0


def test_apply_filters_leaves_normal_code():
    findings = [
        {"file": "src/app.py", "severity": "high", "language": "python",
         "start_line": 10, "tool": "semgrep", "rule_id": "R1"},
    ]
    result = apply_finding_filters(findings, "/tmp/project")
    assert len(result) == 1
    assert result[0]["severity"] == "high"
    assert "context" not in result[0]


def test_apply_filters_disabled():
    findings = [
        {"file": "tests/test_app.py", "severity": "high", "language": "python",
         "start_line": 10, "tool": "semgrep", "rule_id": "R1"},
    ]
    config = {"finding_filters": {"test_code": {"enabled": False}}}
    result = apply_finding_filters(findings, "/tmp/project", config)
    assert len(result) == 1
    assert result[0]["severity"] == "high"


# --- Reachability ---


def test_reachability_inside_entry_point():
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = os.path.join(tmpdir, "app.py")
        with open(filepath, "w") as f:
            f.write("from flask import Flask\napp = Flask(__name__)\n\n")
            f.write("@app.get('/user')\ndef get_user():\n")
            f.write("    user_id = request.args.get('id')\n")
            f.write("    cursor.execute(f'SELECT * FROM users WHERE id={user_id}')\n")

        finding = {"file": "app.py", "language": "python", "start_line": 6}
        result = compute_reachability(finding, tmpdir)
        assert result["is_reachable"] is True
        assert result["confidence"] == "high"


def test_reachability_not_near_entry_point():
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = os.path.join(tmpdir, "utils.py")
        with open(filepath, "w") as f:
            f.write("def internal_helper():\n")
            f.write("    eval(user_input)\n")

        finding = {"file": "utils.py", "language": "python", "start_line": 2}
        result = compute_reachability(finding, tmpdir)
        assert result["is_reachable"] is True
        assert result["confidence"] == "low"
        assert result["reason"] == "no_entry_points_detected"
