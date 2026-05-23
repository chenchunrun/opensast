"""Rule testing framework for Semgrep custom rules."""

import json
import logging
import os
import subprocess
import sys

logger = logging.getLogger(__name__)

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "semgrep")


def discover_rule_tests(rules_dir: str = RULES_DIR) -> list[dict]:
    entries: list[dict] = []
    if not os.path.isdir(rules_dir):
        return entries
    for lang in sorted(os.listdir(rules_dir)):
        lang_dir = os.path.join(rules_dir, lang)
        rules_file = os.path.join(lang_dir, "rules.yml")
        if not os.path.isfile(rules_file):
            continue
        test_dir = os.path.join(lang_dir, "tests")
        has_tests = os.path.isdir(test_dir) and any(
            f for f in os.listdir(test_dir) if not f.startswith(".")
        )
        entries.append({
            "language": lang,
            "rule_path": rules_file,
            "test_dir": test_dir if has_tests else None,
        })
    return entries


def validate_rules(rules_dir: str = RULES_DIR) -> dict:
    entries = discover_rule_tests(rules_dir)
    if not entries:
        return {"valid": True, "errors": [], "rules_checked": 0}

    errors: list[str] = []
    checked = 0
    for entry in entries:
        rule_path = entry["rule_path"]
        if not os.path.isfile(rule_path):
            continue
        checked += 1
        try:
            result = subprocess.run(
                ["semgrep", "--validate", "--config", rule_path],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode != 0:
                errors.append(f"{rule_path}: {result.stderr.strip() or result.stdout.strip()}")
        except subprocess.TimeoutExpired:
            errors.append(f"{rule_path}: validation timed out")
        except FileNotFoundError:
            return {"valid": False, "errors": ["semgrep is not installed"], "rules_checked": checked}

    return {"valid": len(errors) == 0, "errors": errors, "rules_checked": checked}


def test_rules(rules_dir: str = RULES_DIR, verbose: bool = False) -> dict:
    entries = discover_rule_tests(rules_dir)
    if not entries:
        return {"passed": True, "results": [], "total_tests": 0, "passed_tests": 0, "failed_tests": 0}

    results: list[dict] = []
    total = 0
    passed = 0
    failed = 0

    for entry in entries:
        rule_path = entry["rule_path"]
        test_dir = entry["test_dir"]
        if not test_dir or not os.path.isdir(test_dir):
            continue

        try:
            cmd = ["semgrep", "--test", "--config", rule_path, test_dir]
            if verbose:
                cmd.append("--verbose")
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
            )
            output = proc.stdout + proc.stderr

            entry_result = {
                "language": entry["language"],
                "rule_path": rule_path,
                "test_dir": test_dir,
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
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)

    val = validate_rules(args.rules_dir)
    print(f"Validation: {'PASS' if val['valid'] else 'FAIL'} ({val['rules_checked']} rule files)")
    for err in val["errors"]:
        print(f"  ERROR: {err}")

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
