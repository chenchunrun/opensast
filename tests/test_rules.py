"""Tests for rule testing framework."""

import importlib.util
import json
import os
import sys

_spec = importlib.util.spec_from_file_location(
    "rule_tester",
    os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools", "test_rules.py"),
)
_rule_tester = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rule_tester)

discover_rule_tests = _rule_tester.discover_rule_tests
validate_rules = _rule_tester.validate_rules
test_rules = _rule_tester.test_rules


RULES_DIR = os.path.join(
    os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "rules", "semgrep"
)


def test_discover_rule_tests():
    entries = discover_rule_tests(RULES_DIR)
    assert len(entries) >= 4
    languages = {e["language"] for e in entries}
    assert "python" in languages
    assert "javascript" in languages
    assert "java" in languages
    assert "go" in languages
    for entry in entries:
        assert os.path.isfile(entry["rule_path"])
        assert entry["language"]


def test_discover_rule_tests_has_test_dirs():
    entries = discover_rule_tests(RULES_DIR)
    with_tests = [e for e in entries if e["test_dir"] is not None]
    assert len(with_tests) >= 4
    for entry in with_tests:
        assert os.path.isdir(entry["test_dir"])


def test_discover_rule_tests_nonexistent():
    entries = discover_rule_tests("/nonexistent/path")
    assert entries == []


def test_all_rules_files_valid_yaml():
    import yaml
    entries = discover_rule_tests(RULES_DIR)
    for entry in entries:
        with open(entry["rule_path"], encoding="utf-8") as f:
            data = yaml.safe_load(f)
        assert "rules" in data
        assert isinstance(data["rules"], list)
        for rule in data["rules"]:
            assert "id" in rule
            assert "languages" in rule
            assert "severity" in rule
            assert "patterns" in rule or "pattern" in rule or "pattern-either" in rule
            assert rule.get("metadata", {}).get("cwe")
            assert rule.get("metadata", {}).get("owasp")


def test_rules_have_positive_and_negative_cases():
    entries = discover_rule_tests(RULES_DIR)
    for entry in entries:
        test_dir = entry.get("test_dir")
        if not test_dir or not os.path.isdir(test_dir):
            continue
        for test_file in os.listdir(test_dir):
            if test_file.startswith("."):
                continue
            path = os.path.join(test_dir, test_file)
            with open(path, encoding="utf-8") as f:
                content = f.read()
            has_ruleid = "ruleid:" in content.lower()
            has_ok = "ok:" in content.lower()
            assert has_ruleid, f"{path}: no positive test cases (ruleid:)"
            assert has_ok, f"{path}: no negative test cases (ok:)"


def test_validate_rules_skip_if_no_semgrep():
    import shutil
    if not shutil.which("semgrep"):
        result = validate_rules(RULES_DIR)
        assert not result["valid"]
        assert "semgrep is not installed" in result["errors"][0]


def test_test_rules_skip_if_no_semgrep():
    import shutil
    if not shutil.which("semgrep"):
        result = test_rules(RULES_DIR)
        assert not result["passed"]
        assert result["failed_tests"] >= 1
