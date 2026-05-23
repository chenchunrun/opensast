"""SAST Runner - Main orchestrator for multi-language security scanning."""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

import yaml

sys.path.insert(0, os.path.dirname(__file__))

from baseline import filter_new_findings, load_baseline, save_baseline
from ci_gate import evaluate_gate, get_exit_code
from detect_project import detect_project
from normalize_findings import (
    deduplicate_findings,
    normalize_checkov,
    normalize_gitleaks,
    normalize_semgrep,
)
from redact import redact_findings, redact_markdown, redact_sarif
from report_writer import generate_claude_summary, generate_json_summary, generate_markdown_report
from run_bandit import run_bandit
from run_checkov import run_checkov
from run_codeql import run_codeql
from run_gitleaks import run_gitleaks
from run_gosec import run_gosec
from run_semgrep import run_semgrep
from sarif_merge import merge_sarif_files, normalize_paths_in_sarif

logger = logging.getLogger("sast_runner")

EXIT_OK = 0
EXIT_BLOCKING = 1
EXIT_ARG_ERROR = 2
EXIT_TOOL_MISSING = 3
EXIT_SCAN_FAILURE = 4
EXIT_REPORT_FAILURE = 5
EXIT_CONFIG_ERROR = 6

SKILL_DIR = os.path.dirname(os.path.dirname(__file__))
DEFAULT_CONFIG_PATH = os.path.join(SKILL_DIR, "config", "default.yml")


def load_config(config_path: str | None) -> dict:
    paths = []
    if config_path:
        paths.append(config_path)
    user_config = os.path.join(".claude", "sast", "config.yml")
    if os.path.isfile(user_config):
        paths.append(user_config)
    paths.append(DEFAULT_CONFIG_PATH)

    merged: dict = {}
    for path in paths:
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        merged.update(data)
    return merged


def get_changed_files(target: str) -> list[str]:
    import subprocess
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMR", "HEAD"],
            cwd=target, capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            return [f.strip() for f in result.stdout.strip().splitlines() if f.strip()]
    except Exception:
        pass
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMR"],
            cwd=target, capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            return [f.strip() for f in result.stdout.strip().splitlines() if f.strip()]
    except Exception:
        pass
    return []


def _collect_sarif_paths(results: list[dict]) -> list[str]:
    paths = []
    for r in results:
        p = r.get("sarif_path")
        if p and os.path.isfile(p):
            paths.append(p)
    return paths


def _count_severity(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["info"] += 1
    return counts


def run(args: argparse.Namespace) -> int:
    start_time = time.time()
    target = os.path.abspath(args.target or ".")
    profile_name = args.profile or "standard"
    output_dir = os.path.abspath(args.output_dir or ".claude/sast/results")

    config = load_config(args.config)
    profile = config.get("profiles", {}).get(profile_name, {})
    fail_on = args.fail_on or profile.get("fail_on", "high")
    formats = args.format.split(",") if args.format else config.get("report", {}).get("formats", ["markdown"])

    os.makedirs(os.path.join(output_dir, "logs"), exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[
            logging.FileHandler(os.path.join(output_dir, "logs", "runner.log"), mode="w"),
            logging.StreamHandler(),
        ],
    )

    logger.info("SAST scan starting — target=%s profile=%s", target, profile_name)

    project = detect_project(target)
    logger.info("Languages: %s", ", ".join(project.get("languages", {}).keys()))
    logger.info("Frameworks: %s", ", ".join(project.get("frameworks", [])))

    scan_target = target
    changed_files: list[str] = []
    if args.changed_only or profile.get("changed_only"):
        changed_files = get_changed_files(target)
        if not changed_files:
            logger.info("No changed files detected. Nothing to scan.")
            changed_files = []
        else:
            logger.info("Changed files: %d", len(changed_files))

    tools_config = profile.get("tools", {})
    tool_timeout = args.tool_timeout or config.get("tools", {}).get("semgrep", {}).get("timeout", 300)
    tool_errors: list[dict] = []
    scan_results: list[dict] = []

    if tools_config.get("semgrep", True) or (not tools_config and profile_name != "quick"):
        logger.info("Running Semgrep...")
        extra_configs = config.get("rules", {}).get("semgrep", [])
        config_paths = [c for c in extra_configs if c != "auto"] if extra_configs else None
        result = run_semgrep(scan_target, output_dir, config_paths=config_paths, timeout=tool_timeout)
        scan_results.append(result)
        if not result["success"]:
            tool_errors.append({"tool": "semgrep", "error": result.get("error_message", "unknown")})
            logger.warning("Semgrep: %s", result.get("error_message", "failed"))

    if tools_config.get("gitleaks", True):
        logger.info("Running Gitleaks...")
        result = run_gitleaks(scan_target, output_dir, timeout=tool_timeout)
        scan_results.append(result)
        if not result["success"]:
            tool_errors.append({"tool": "gitleaks", "error": result.get("error_message", "unknown")})
            logger.warning("Gitleaks: %s", result.get("error_message", "failed"))

    if tools_config.get("checkov", False) and project.get("iac_files"):
        logger.info("Running Checkov...")
        result = run_checkov(scan_target, output_dir, timeout=tool_timeout)
        scan_results.append(result)
        if not result["success"]:
            tool_errors.append({"tool": "checkov", "error": result.get("error_message", "unknown")})
            logger.warning("Checkov: %s", result.get("error_message", "failed"))

    detected_languages = set(project.get("languages", {}).keys())

    if tools_config.get("codeql", False):
        logger.info("Running CodeQL...")
        codeql_timeout = config.get("tools", {}).get("codeql", {}).get("timeout", 600)
        result = run_codeql(scan_target, output_dir, languages=list(detected_languages), timeout=codeql_timeout)
        scan_results.append(result)
        if not result["success"]:
            tool_errors.append({"tool": "codeql", "error": result.get("error_message", "unknown")})
            logger.warning("CodeQL: %s", result.get("error_message", "failed"))

    if "python" in detected_languages:
        logger.info("Running Bandit...")
        result = run_bandit(scan_target, output_dir, timeout=tool_timeout)
        scan_results.append(result)
        if not result["success"]:
            tool_errors.append({"tool": "bandit", "error": result.get("error_message", "unknown")})
            logger.warning("Bandit: %s", result.get("error_message", "failed"))

    if "go" in detected_languages:
        logger.info("Running gosec...")
        result = run_gosec(scan_target, output_dir, timeout=tool_timeout)
        scan_results.append(result)
        if not result["success"]:
            tool_errors.append({"tool": "gosec", "error": result.get("error_message", "unknown")})
            logger.warning("gosec: %s", result.get("error_message", "failed"))

    logger.info("Collecting and normalizing findings...")
    all_findings: list[dict] = []

    for r in scan_results:
        sarif_path = r.get("sarif_path")
        if not sarif_path or not os.path.isfile(sarif_path):
            continue
        try:
            with open(sarif_path, encoding="utf-8") as fh:
                sarif_data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            continue

        tool = r.get("tool", "")
        if tool == "gitleaks":
            all_findings.extend(normalize_gitleaks(sarif_data))
        elif tool == "checkov":
            all_findings.extend(normalize_checkov(sarif_data))
        else:
            all_findings.extend(normalize_semgrep(sarif_data))

    all_findings = deduplicate_findings(all_findings)

    repo_root = project.get("repo_root", target)
    for f in all_findings:
        file_path = f.get("file", "")
        if file_path and os.path.isabs(file_path):
            try:
                f["file"] = os.path.relpath(file_path, repo_root)
            except ValueError:
                pass

    baseline_path = args.baseline or config.get("baseline", {}).get("file", ".claude/sast/baseline.json")
    baseline_enabled = config.get("baseline", {}).get("enabled", True)
    baseline_data = {}
    if baseline_enabled:
        baseline_data = load_baseline(baseline_path)
        all_findings = filter_new_findings(all_findings, baseline_data)

    all_findings = redact_findings(all_findings)

    logger.info("Merging SARIF files...")
    sarif_paths = _collect_sarif_paths(scan_results)
    merged_sarif_path = os.path.join(output_dir, "merged.sarif")
    if sarif_paths:
        merged = merge_sarif_files(sarif_paths, merged_sarif_path)
        merged = normalize_paths_in_sarif(merged, project.get("repo_root", target))
        merged = redact_sarif(merged)
        with open(merged_sarif_path, "w", encoding="utf-8") as fh:
            json.dump(merged, fh, indent=2)

    severity_counts = _count_severity(all_findings)
    new_count = sum(1 for f in all_findings if f.get("is_new"))

    gate_result = evaluate_gate(all_findings, fail_on=fail_on, baseline_enabled=baseline_enabled)
    blocking_count = gate_result.get("blocking_count", 0)

    tools_executed = [r["tool"] for r in scan_results if r.get("success")]
    elapsed = round(time.time() - start_time, 1)

    summary = {
        "target": target,
        "profile": profile_name,
        "scan_time": f"{elapsed}s",
        "languages": list(project.get("languages", {}).keys()),
        "tools_executed": tools_executed,
        "total_findings": len(all_findings),
        "new_findings": new_count,
        "blocking_findings": blocking_count,
        "severity_counts": severity_counts,
        "gate_result": gate_result,
        "tool_errors": tool_errors,
    }

    logger.info("Generating reports...")
    try:
        if "markdown" in formats or "all" in formats:
            md_path = os.path.join(output_dir, "report.md")
            generate_markdown_report(summary, all_findings, md_path)
            logger.info("Markdown report: %s", md_path)

        if "json" in formats or "all" in formats:
            json_path = os.path.join(output_dir, "findings.json")
            generate_json_summary(summary, all_findings, json_path)
            summary_path = os.path.join(output_dir, "summary.json")
            with open(summary_path, "w", encoding="utf-8") as fh:
                json.dump(summary, fh, indent=2, default=str)
            logger.info("JSON report: %s", json_path)

        if "sarif" in formats or "all" in formats:
            if not sarif_paths:
                sarif_path = os.path.join(output_dir, "merged.sarif")
                with open(sarif_path, "w", encoding="utf-8") as fh:
                    json.dump({"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json", "version": "2.1.0", "runs": []}, fh, indent=2)
            logger.info("SARIF report: %s", merged_sarif_path)

    except Exception as e:
        logger.error("Report generation failed: %s", e)
        return EXIT_REPORT_FAILURE

    claude_output = generate_claude_summary(summary, all_findings)
    print("\n" + claude_output)

    _write_tool_versions(output_dir, scan_results)

    logger.info("Scan complete in %ss — %d total, %d new, %d blocking", elapsed, len(all_findings), new_count, blocking_count)

    exit_code = get_exit_code(gate_result)
    if exit_code != 0:
        logger.warning("CI gate FAILED: %d findings at or above '%s'", blocking_count, fail_on)
    return exit_code


def _write_tool_versions(output_dir: str, results: list[dict]) -> None:
    versions = {}
    for r in results:
        if r.get("tool") and r.get("version"):
            versions[r["tool"]] = r["version"]
    log_dir = os.path.join(output_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    with open(os.path.join(log_dir, "tool-versions.txt"), "w", encoding="utf-8") as fh:
        for tool, ver in sorted(versions.items()):
            fh.write(f"{tool}={ver}\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SAST Runner - Multi-language security scanning orchestrator",
    )
    parser.add_argument("target", nargs="?", default=".", help="Target path to scan (default: .)")
    parser.add_argument("--profile", choices=["quick", "standard", "deep"], help="Scan profile")
    parser.add_argument("--changed-only", action="store_true", help="Scan only changed files")
    parser.add_argument("--lang", default="auto", help="Language filter (default: auto)")
    parser.add_argument("--format", dest="format", help="Report format: markdown,json,sarif,all")
    parser.add_argument("--output-dir", help="Output directory (default: .claude/sast/results)")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="Fail gate on severity")
    parser.add_argument("--baseline", help="Baseline file path")
    parser.add_argument("--config", help="Config file path")
    parser.add_argument("--tool-timeout", type=int, help="Per-tool timeout in seconds")
    return parser.parse_args(argv)


def main() -> int:
    args = parse_args()
    try:
        return run(args)
    except Exception as e:
        logging.critical("Fatal error: %s", e, exc_info=True)
        return EXIT_SCAN_FAILURE


if __name__ == "__main__":
    sys.exit(main())
