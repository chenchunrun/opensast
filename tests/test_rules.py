"""Tests for rule testing framework."""

import importlib.util
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

_spec = importlib.util.spec_from_file_location(
    "rule_tester",
    os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools", "test_rules.py"),
)
_rule_tester = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rule_tester)

discover_rule_tests = _rule_tester.discover_rule_tests
validate_rules = _rule_tester.validate_rules
run_rule_tests = _rule_tester.test_rules
audit_rule_coverage = _rule_tester.audit_rule_coverage
format_rule_coverage_markdown = _rule_tester.format_rule_coverage_markdown


RULES_DIR = os.path.join(
    os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "rules", "semgrep"
)
CORPUS_DIR = os.path.join(os.path.dirname(__file__), "samples", "corpus")


def test_discover_rule_tests():
    entries = discover_rule_tests(RULES_DIR)
    assert len(entries) >= 10
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


def test_discover_rule_tests_includes_javascript_auxiliary_rule_files():
    entries = discover_rule_tests(RULES_DIR)
    js_entries = [entry for entry in entries if entry["language"] == "javascript"]
    js_rule_files = sorted(os.path.basename(entry["rule_path"]) for entry in js_entries)
    assert "rules.yml" in js_rule_files
    assert "xss-template-rules.yml" in js_rule_files
    assert "framework-rules.yml" in js_rule_files
    js_with_tests = {
        os.path.basename(entry["rule_path"])
        for entry in js_entries
        if entry["test_dir"] is not None
    }
    assert "xss-template-rules.yml" in js_with_tests
    assert "framework-rules.yml" in js_with_tests
    assert "config-rules.yml" in js_with_tests
    assert "nextjs-auth-rules.yml" in js_with_tests
    assert "nextjs-rules.yml" in js_with_tests
    assert "security-enhanced-rules.yml" in js_with_tests


def test_discover_rule_tests_nonexistent():
    entries = discover_rule_tests("/nonexistent/path")
    assert entries == []


def _collect_rule_ids() -> set[str]:
    rule_ids: set[str] = set()
    for path in Path(RULES_DIR).rglob("*.yml"):
        with open(path, encoding="utf-8") as f:
            import yaml
            data = yaml.safe_load(f)
        for rule in data.get("rules", []):
            rule_id = rule.get("id")
            if rule_id:
                rule_ids.add(rule_id)
    return rule_ids


def _collect_corpus_rule_ids() -> set[str]:
    corpus_ids: set[str] = set()
    for path in Path(CORPUS_DIR).iterdir():
        if not path.is_file() or path.name.startswith("_"):
            continue
        with open(path, encoding="utf-8") as f:
            for line in f:
                marker = "ruleid:"
                if marker in line.lower():
                    candidate = line.split(marker, 1)[1].strip()
                    if "." in candidate and " " not in candidate:
                        corpus_ids.add(candidate)
    return corpus_ids


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
            if rule.get("mode") == "taint":
                assert "pattern-sources" in rule and "pattern-sinks" in rule
            else:
                assert "patterns" in rule or "pattern" in rule or "pattern-either" in rule
            assert rule.get("metadata", {}).get("cwe")
            assert rule.get("metadata", {}).get("owasp")


def test_rule_coverage_audit_includes_expected_languages():
    coverage = audit_rule_coverage(RULES_DIR)
    languages = {row["language"] for row in coverage["languages"]}
    assert {"javascript", "python", "go", "java", "php", "ruby", "cpp", "rust", "csharp"} <= languages
    summary = coverage["summary"]
    assert summary["total_rules"] >= 200
    assert summary["covered_rules"] >= 200


def test_rule_coverage_markdown_contains_summary_table():
    coverage = audit_rule_coverage(RULES_DIR)
    markdown = format_rule_coverage_markdown(coverage)
    assert "| Language | Rule Files | Test Files | Covered / Total | Coverage | Uncovered |" in markdown
    assert "Overall coverage:" in markdown


def test_primary_languages_keep_expected_coverage_floor():
    coverage = audit_rule_coverage(RULES_DIR)
    by_language = {row["language"]: row for row in coverage["languages"]}
    assert by_language["javascript"]["covered_rules"] == by_language["javascript"]["total_rules"]
    assert by_language["python"]["covered_rules"] == by_language["python"]["total_rules"]
    assert by_language["go"]["covered_rules"] == by_language["go"]["total_rules"]
    assert by_language["java"]["covered_rules"] == by_language["java"]["total_rules"]
    assert by_language["php"]["covered_rules"] == by_language["php"]["total_rules"]
    assert by_language["ruby"]["covered_rules"] == by_language["ruby"]["total_rules"]
    assert by_language["cpp"]["covered_rules"] == by_language["cpp"]["total_rules"]
    assert by_language["rust"]["covered_rules"] == by_language["rust"]["total_rules"]


def test_dependency_rules_are_backed_by_tests():
    entries = discover_rule_tests(RULES_DIR)
    dependency_entries = [entry for entry in entries if entry["language"] == "dependency"]
    assert dependency_entries, "Dependency rules were not discovered"
    assert any(entry["test_dir"] is not None for entry in dependency_entries), "Dependency rules have no matched test files"


def test_dependency_rules_keep_full_coverage():
    coverage = audit_rule_coverage(RULES_DIR)
    by_language = {row["language"]: row for row in coverage["languages"]}
    assert by_language["dependency"]["covered_rules"] == by_language["dependency"]["total_rules"]


def test_compliance_rules_are_backed_by_tests():
    entries = discover_rule_tests(RULES_DIR)
    compliance_entries = [entry for entry in entries if entry["language"] == "compliance"]
    assert compliance_entries, "Compliance rules were not discovered"
    assert any(entry["test_dir"] is not None for entry in compliance_entries), "Compliance rules have no matched test files"


def test_compliance_rules_keep_full_coverage():
    coverage = audit_rule_coverage(RULES_DIR)
    by_language = {row["language"]: row for row in coverage["languages"]}
    assert by_language["compliance"]["covered_rules"] == by_language["compliance"]["total_rules"]


def test_swift_kotlin_rules_are_backed_by_tests():
    entries = discover_rule_tests(RULES_DIR)
    swift_kotlin_entries = [entry for entry in entries if entry["language"] == "swift-kotlin"]
    assert swift_kotlin_entries, "Swift/Kotlin rules were not discovered"
    assert any(entry["test_dir"] is not None for entry in swift_kotlin_entries), "Swift/Kotlin rules have no matched test files"


def test_swift_kotlin_rules_keep_full_coverage():
    coverage = audit_rule_coverage(RULES_DIR)
    by_language = {row["language"]: row for row in coverage["languages"]}
    assert by_language["swift-kotlin"]["covered_rules"] == by_language["swift-kotlin"]["total_rules"]


def test_corpus_ruleids_exist_in_ruleset():
    rule_ids = _collect_rule_ids()
    corpus_ids = _collect_corpus_rule_ids()
    missing = sorted(corpus_ids - rule_ids)
    assert not missing, f"Corpus references undefined rule IDs: {missing}"


def test_corpus_languages_have_rules_files():
    expected_languages = {"python", "javascript", "java", "go", "php", "ruby", "cpp", "rust"}
    discovered = {entry["language"] for entry in discover_rule_tests(RULES_DIR)}
    missing = sorted(expected_languages - discovered)
    assert not missing, f"Missing rules.yml for corpus-covered languages: {missing}"


def test_php_rules_are_backed_by_tests():
    entries = discover_rule_tests(RULES_DIR)
    php_entries = [entry for entry in entries if entry["language"] == "php"]
    assert php_entries, "PHP rules were not discovered"
    assert any(entry["test_dir"] is not None for entry in php_entries), "PHP rules have no matched test files"


def test_ruby_rules_are_backed_by_tests():
    entries = discover_rule_tests(RULES_DIR)
    ruby_entries = [entry for entry in entries if entry["language"] == "ruby"]
    assert ruby_entries, "Ruby rules were not discovered"
    assert any(entry["test_dir"] is not None for entry in ruby_entries), "Ruby rules have no matched test files"


def test_go_rules_have_multiple_test_files():
    entries = discover_rule_tests(RULES_DIR)
    go_entries = [entry for entry in entries if entry["language"] == "go"]
    assert go_entries, "Go rules were not discovered"
    matched = [entry for entry in go_entries if entry["test_dir"] is not None]
    assert matched, "Go rules have no matched test files"
    test_files = matched[0].get("test_files", [])
    assert len(test_files) >= 3, f"Expected broader Go rule coverage, got only {len(test_files)} matched test files"


def test_java_rules_have_multiple_test_files():
    entries = discover_rule_tests(RULES_DIR)
    java_entries = [entry for entry in entries if entry["language"] == "java"]
    assert java_entries, "Java rules were not discovered"
    matched = [entry for entry in java_entries if entry["test_dir"] is not None]
    assert matched, "Java rules have no matched test files"
    test_files = matched[0].get("test_files", [])
    assert len(test_files) >= 4, f"Expected broader Java rule coverage, got only {len(test_files)} matched test files"


def test_python_rules_have_broader_security_coverage():
    entries = discover_rule_tests(RULES_DIR)
    python_entries = [entry for entry in entries if entry["language"] == "python"]
    assert python_entries, "Python rules were not discovered"
    matched = [entry for entry in python_entries if entry["test_dir"] is not None]
    assert matched, "Python rules have no matched test files"
    test_files = matched[0].get("test_files", [])
    assert len(test_files) >= 8, f"Expected broader Python rule coverage, got only {len(test_files)} matched test files"


def test_cpp_rules_are_backed_by_tests():
    entries = discover_rule_tests(RULES_DIR)
    cpp_entries = [entry for entry in entries if entry["language"] == "cpp"]
    assert cpp_entries, "C/C++ rules were not discovered"
    assert any(entry["test_dir"] is not None for entry in cpp_entries), "C/C++ rules have no matched test files"


def test_rust_rules_are_backed_by_tests():
    entries = discover_rule_tests(RULES_DIR)
    rust_entries = [entry for entry in entries if entry["language"] == "rust"]
    assert rust_entries, "Rust rules were not discovered"
    assert any(entry["test_dir"] is not None for entry in rust_entries), "Rust rules have no matched test files"


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


def test_stage_semgrep_test_merges_fixtures_by_extension():
    import tempfile

    with tempfile.TemporaryDirectory() as staged_dir:
        rule_path = os.path.join(RULES_DIR, "java", "rules.yml")
        test_files = [
            os.path.join(RULES_DIR, "java", "tests", "TestSqlInjection.java"),
            os.path.join(RULES_DIR, "java", "tests", "TestMiscSecurity.java"),
        ]
        _rule_tester._stage_semgrep_test(rule_path, test_files, staged_dir)
        merged = os.path.join(staged_dir, "rules.java")
        assert os.path.isfile(os.path.join(staged_dir, "rules.yml"))
        assert os.path.isfile(merged)
        content = Path(merged).read_text(encoding="utf-8")
        assert "ruleid:" in content.lower()
        assert "TestSqlInjection" in content or "sql-injection" in content


def test_validate_rules_skip_if_no_semgrep():
    from run_semgrep import get_semgrep_binary

    if not get_semgrep_binary():
        result = validate_rules(RULES_DIR)
        assert not result["valid"]
        assert "semgrep is not installed" in result["errors"][0]


def test_validate_rules_timeout_degrades_to_warning():
    """A validation timeout (e.g. network-restricted env) must not hard-fail."""
    import subprocess

    from run_semgrep import get_semgrep_binary

    if not get_semgrep_binary():
        return

    real_run = subprocess.run

    def fake_run(cmd, *args, **kwargs):
        if "--validate" in cmd:
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 60))
        return real_run(cmd, *args, **kwargs)

    original = _rule_tester.subprocess.run
    _rule_tester.subprocess.run = fake_run
    try:
        result = validate_rules(RULES_DIR, timeout=1)
    finally:
        _rule_tester.subprocess.run = original

    assert result["valid"] is True
    assert result["errors"] == []
    assert len(result["warnings"]) == result["rules_checked"]
    assert result["rules_checked"] > 0
    assert "timed out" in result["warnings"][0]


def test_test_rules_skip_if_no_semgrep():
    from run_semgrep import get_semgrep_binary

    if not get_semgrep_binary():
        result = run_rule_tests(RULES_DIR)
        assert not result["passed"]
        assert result["failed_tests"] >= 1
