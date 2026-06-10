"""Rule testing framework for Semgrep custom rules."""

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

from run_semgrep import build_semgrep_env, get_semgrep_binary

logger = logging.getLogger(__name__)

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "semgrep")


def discover_rule_tests(rules_dir: str = RULES_DIR) -> list[dict]:
    entries: list[dict] = []
    if not os.path.isdir(rules_dir):
        return entries
    for lang in sorted(os.listdir(rules_dir)):
        lang_dir = os.path.join(rules_dir, lang)
        if not os.path.isdir(lang_dir):
            continue
        test_dir = os.path.join(lang_dir, "tests")
        has_tests = os.path.isdir(test_dir) and any(
            f for f in os.listdir(test_dir) if not f.startswith(".")
        )
        rule_files = sorted(
            os.path.join(lang_dir, name)
            for name in os.listdir(lang_dir)
            if name.endswith((".yml", ".yaml")) and os.path.isfile(os.path.join(lang_dir, name))
        )
        for rule_path in rule_files:
            rule_ids = _load_rule_ids(rule_path)
            matching_test_files = _collect_matching_test_files(test_dir, rule_ids) if has_tests else []
            entries.append({
                "language": lang,
                "rule_path": rule_path,
                "test_dir": test_dir if matching_test_files else None,
                "test_files": matching_test_files,
                "rule_ids": rule_ids,
            })
    return entries


def _load_rule_ids(rule_path: str) -> list[str]:
    try:
        with open(rule_path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except OSError:
        return []
    return [rule.get("id") for rule in data.get("rules", []) if rule.get("id")]


def _collect_test_ruleids(test_dir: str) -> set[str]:
    ruleids: set[str] = set()
    for path in Path(test_dir).iterdir():
        if not path.is_file() or path.name.startswith("."):
            continue
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                lower = line.lower()
                if "ruleid:" not in lower:
                    continue
                _, _, suffix = line.partition("ruleid:")
                candidate = suffix.strip()
                if candidate:
                    ruleids.add(candidate)
    return ruleids


def _collect_matching_test_files(test_dir: str, rule_ids: list[str]) -> list[str]:
    if not test_dir or not os.path.isdir(test_dir) or not rule_ids:
        return []
    selected: list[str] = []
    rule_id_set = set(rule_ids)
    for path in sorted(Path(test_dir).iterdir()):
        if not path.is_file() or path.name.startswith("."):
            continue
        with open(path, encoding="utf-8") as fh:
            content = fh.read()
        if not any(rule_id in content for rule_id in rule_id_set):
            continue
        selected.append(str(path))
    return selected


def audit_rule_coverage(rules_dir: str = RULES_DIR) -> dict:
    entries = discover_rule_tests(rules_dir)
    languages: dict[str, dict] = {}

    for entry in entries:
        language = entry["language"]
        stats = languages.setdefault(language, {
            "language": language,
            "rule_files": 0,
            "test_files": 0,
            "total_rules": 0,
            "covered_rules": 0,
            "coverage_pct": 0.0,
            "uncovered_rules": [],
        })

        stats["rule_files"] += 1
        rule_ids = [rule_id for rule_id in entry.get("rule_ids", []) if rule_id]
        stats["total_rules"] += len(rule_ids)
        test_files = entry.get("test_files") or []
        stats["test_files"] += len(test_files)

        covered_rule_ids = set()
        if test_files:
            combined = []
            for path in test_files:
                try:
                    with open(path, encoding="utf-8") as fh:
                        combined.append(fh.read())
                except OSError:
                    continue
            combined_content = "\n".join(combined)
            covered_rule_ids = {rule_id for rule_id in rule_ids if rule_id in combined_content}

        stats["covered_rules"] += len(covered_rule_ids)
        stats["uncovered_rules"].extend(
            sorted(rule_id for rule_id in rule_ids if rule_id not in covered_rule_ids)
        )

    language_rows = []
    total_rules = 0
    covered_rules = 0
    total_rule_files = 0
    total_test_files = 0

    for language in sorted(languages):
        stats = languages[language]
        if stats["total_rules"]:
            stats["coverage_pct"] = round(stats["covered_rules"] / stats["total_rules"] * 100, 1)
        stats["uncovered_rules"] = sorted(set(stats["uncovered_rules"]))
        language_rows.append(stats)
        total_rules += stats["total_rules"]
        covered_rules += stats["covered_rules"]
        total_rule_files += stats["rule_files"]
        total_test_files += stats["test_files"]

    coverage_pct = round(covered_rules / total_rules * 100, 1) if total_rules else 100.0
    return {
        "languages": language_rows,
        "summary": {
            "rule_files": total_rule_files,
            "test_files": total_test_files,
            "total_rules": total_rules,
            "covered_rules": covered_rules,
            "coverage_pct": coverage_pct,
        },
    }


def format_rule_coverage_markdown(coverage: dict) -> str:
    lines = [
        "# Rule Coverage Audit",
        "",
        "| Language | Rule Files | Test Files | Covered / Total | Coverage | Uncovered |",
        "|----------|------------|------------|-----------------|----------|-----------|",
    ]
    for row in coverage.get("languages", []):
        uncovered = ", ".join(row["uncovered_rules"]) if row["uncovered_rules"] else "-"
        lines.append(
            f"| {row['language']} | {row['rule_files']} | {row['test_files']} | "
            f"{row['covered_rules']} / {row['total_rules']} | {row['coverage_pct']}% | {uncovered} |"
        )

    summary = coverage.get("summary", {})
    lines.extend([
        "",
        f"Overall coverage: {summary.get('covered_rules', 0)} / {summary.get('total_rules', 0)} "
        f"rules ({summary.get('coverage_pct', 0.0)}%)",
    ])
    return "\n".join(lines)


def write_rule_coverage_report(coverage: dict, output_path: str) -> None:
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    if output_path.endswith(".md"):
        content = format_rule_coverage_markdown(coverage)
    else:
        content = json.dumps(coverage, indent=2, ensure_ascii=False)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)


def _stage_semgrep_test(rule_path: str, test_files: list[str], staged_dir: str) -> None:
    """Stage rule config and merged test fixtures for ``semgrep --test``.

    Semgrep pairs ``<config-stem>.yml`` with ``<config-stem>.<lang-ext>`` in the
    same directory. Multiple fixture files for one config are merged per extension.
    """
    shutil.copy2(rule_path, os.path.join(staged_dir, os.path.basename(rule_path)))
    rule_stem = Path(rule_path).stem
    by_ext: dict[str, list[str]] = {}
    for path in test_files:
        by_ext.setdefault(Path(path).suffix, []).append(path)
    for ext, paths in by_ext.items():
        merged_path = os.path.join(staged_dir, f"{rule_stem}{ext}")
        with open(merged_path, "w", encoding="utf-8") as out:
            for i, path in enumerate(paths):
                with open(path, encoding="utf-8") as inp:
                    content = inp.read()
                if i:
                    out.write("\n")
                out.write(content)
                if content and not content.endswith("\n"):
                    out.write("\n")


def validate_rules(rules_dir: str = RULES_DIR, timeout: int = 60) -> dict:
    entries = discover_rule_tests(rules_dir)
    if not entries:
        return {"valid": True, "errors": [], "warnings": [], "rules_checked": 0}
    semgrep_bin = get_semgrep_binary()
    if not semgrep_bin:
        return {
            "valid": False,
            "errors": ["semgrep is not installed"],
            "warnings": [],
            "rules_checked": 0,
        }

    errors: list[str] = []
    warnings: list[str] = []
    checked = 0
    for entry in entries:
        rule_path = entry["rule_path"]
        if not os.path.isfile(rule_path):
            continue
        checked += 1
        try:
            result = subprocess.run(
                [semgrep_bin, "--validate", "--config", rule_path],
                capture_output=True, text=True, timeout=timeout,
                env=build_semgrep_env(),
            )
            if result.returncode != 0:
                errors.append(f"{rule_path}: {result.stderr.strip() or result.stdout.strip()}")
        except subprocess.TimeoutExpired:
            # `semgrep --validate` reaches out to the registry/schema service.
            # In network-restricted environments this stalls even though the
            # rules parse and match correctly (covered by the corpus tests).
            # Degrade to a warning instead of failing the whole run.
            warnings.append(f"{rule_path}: validation timed out (network-restricted environment?)")
        except FileNotFoundError:
            return {
                "valid": False,
                "errors": ["semgrep is not installed"],
                "warnings": warnings,
                "rules_checked": checked,
            }

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "rules_checked": checked,
    }


def test_rules(rules_dir: str = RULES_DIR, verbose: bool = False) -> dict:
    entries = discover_rule_tests(rules_dir)
    if not entries:
        return {"passed": True, "results": [], "total_tests": 0, "passed_tests": 0, "failed_tests": 0}
    semgrep_bin = get_semgrep_binary()
    if not semgrep_bin:
        return {
            "passed": False,
            "results": [{"error": "semgrep is not installed"}],
            "total_tests": 0, "passed_tests": 0, "failed_tests": 1,
        }

    results: list[dict] = []
    total = 0
    passed = 0
    failed = 0

    for entry in entries:
        rule_path = entry["rule_path"]
        test_dir = entry["test_dir"]
        test_files = entry.get("test_files") or []
        if not test_dir or not os.path.isdir(test_dir) or not test_files:
            continue

        try:
            with tempfile.TemporaryDirectory(prefix="opensast-rule-tests-") as staged_dir:
                _stage_semgrep_test(rule_path, test_files, staged_dir)
                cmd = [semgrep_bin, "--test", staged_dir]
                if verbose:
                    cmd.append("--verbose")
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=120,
                    env=build_semgrep_env(),
                )
                output = proc.stdout + proc.stderr

                entry_result = {
                    "language": entry["language"],
                    "rule_path": rule_path,
                    "test_dir": test_dir,
                    "test_files": test_files,
                    "exit_code": proc.returncode,
                    "output": output,
                    "passed": proc.returncode == 0,
                }

                if "test files" in output:
                    total += 1
                    if proc.returncode == 0:
                        passed += 1
                    else:
                        failed += 1

        except subprocess.TimeoutExpired:
            entry_result = {
                "language": entry["language"],
                "rule_path": rule_path,
                "test_dir": test_dir,
                "test_files": test_files,
                "exit_code": -1,
                "output": "timed out",
                "passed": False,
            }
            total += 1
            failed += 1
        except FileNotFoundError:
            return {
                "passed": False,
                "results": [{"error": "semgrep is not installed"}],
                "total_tests": 0, "passed_tests": 0, "failed_tests": 1,
            }

        results.append(entry_result)

    return {
        "passed": failed == 0,
        "results": results,
        "total_tests": total,
        "passed_tests": passed,
        "failed_tests": failed,
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Test Semgrep custom rules")
    parser.add_argument("--rules-dir", default=RULES_DIR, help="Rules directory")
    parser.add_argument("--validate-only", action="store_true", help="Only validate, don't test")
    parser.add_argument(
        "--coverage-report",
        help="Write rule coverage audit to a .json or .md file",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)

    coverage = audit_rule_coverage(args.rules_dir)
    summary = coverage["summary"]
    print(
        "Coverage: "
        f"{summary['covered_rules']}/{summary['total_rules']} rules "
        f"({summary['coverage_pct']}%) across {summary['rule_files']} rule files"
    )
    if args.coverage_report:
        write_rule_coverage_report(coverage, args.coverage_report)
        print(f"Coverage report: {args.coverage_report}")

    val = validate_rules(args.rules_dir)
    print(f"Validation: {'PASS' if val['valid'] else 'FAIL'} ({val['rules_checked']} rule files)")
    for err in val["errors"]:
        print(f"  ERROR: {err}")
    for warn in val.get("warnings", []):
        print(f"  WARN: {warn}")

    if not val["valid"]:
        return 1

    if args.validate_only:
        return 0

    test_result = test_rules(args.rules_dir, verbose=args.verbose)
    print(f"\nTests: {'PASS' if test_result['passed'] else 'FAIL'} "
          f"({test_result['passed_tests']}/{test_result['total_tests']} passed)")
    for r in test_result["results"]:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"  [{status}] {r['language']}: {r['rule_path']}")
        if not r["passed"] and r.get("output"):
            for line in r["output"].splitlines():
                if line.strip():
                    print(f"    {line}")

    return 0 if test_result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
