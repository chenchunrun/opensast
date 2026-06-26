"""SAST Runner - Main orchestrator for multi-language security scanning."""

import argparse
import json
import logging
import os
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone

import yaml

sys.path.insert(0, os.path.dirname(__file__))

from baseline import filter_new_findings, load_baseline, save_baseline
from ci_gate import check_trend_gate, evaluate_gate, get_exit_code
from detect_project import detect_project
from github_integration import post_pr_comment
from history import compare_scans, get_previous_scan, load_scan_history, save_scan_result
from normalize_findings import (
    JSON_NORMALIZERS,
    NORMALIZERS,
    deduplicate_findings,
    normalize_llm_findings,
    normalize_semgrep,
    validate_llm_findings,
)
from redact import redact_findings, redact_markdown, redact_sarif
from report_writer import (
    build_report_next_steps,
    generate_claude_summary,
    generate_html_report,
    generate_json_summary,
    generate_markdown_report,
    summarize_analysis_enrichment,
)
from tool_diagnostics import collect_tool_outcomes
from run_bandit import run_bandit
from run_brakeman import run_brakeman
from run_cargo_audit import run_cargo_audit
from run_checkov import run_checkov
from run_codeql import run_codeql
from run_cppcheck import run_cppcheck
from run_eslint_security import run_eslint_security
from run_gitleaks import run_gitleaks
from run_gosec import run_gosec
from run_phpstan import run_phpstan
from run_semgrep import run_semgrep
from run_swiftlint import run_swiftlint
from sarif_merge import merge_sarif_files, normalize_paths_in_sarif
from llm_orchestrator import apply_fast_filters, generate_analysis_plan, save_analysis_plan

logger = logging.getLogger("sast_runner")

EXIT_OK = 0
EXIT_BLOCKING = 1
EXIT_ARG_ERROR = 2
EXIT_TOOL_MISSING = 3
EXIT_SCAN_FAILURE = 4
EXIT_REPORT_FAILURE = 5
EXIT_CONFIG_ERROR = 6

# Environment variables that indicate the process is running inside a CI
# system. Used to make gate enforcement scenario-aware.
_CI_ENV_VARS = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_HOME", "BUILDKITE", "CIRCLECI", "TF_BUILD")


def is_ci_environment() -> bool:
    """Return True when running inside a detected CI system."""
    return any(os.environ.get(var) for var in _CI_ENV_VARS)

SKILL_DIR = os.path.dirname(os.path.dirname(__file__))
DEFAULT_CONFIG_PATH = os.path.join(SKILL_DIR, "config", "default.yml")
LANGUAGE_FILTERS = {
    "js": {"javascript"},
    "javascript": {"javascript"},
    "ts": {"typescript"},
    "typescript": {"typescript"},
    "python": {"python"},
    "py": {"python"},
    "java": {"java"},
    "kotlin": {"kotlin"},
    "go": {"go"},
    "csharp": {"csharp"},
    "cs": {"csharp"},
    "cpp": {"cpp", "c"},
    "c": {"c"},
    "php": {"php"},
    "ruby": {"ruby"},
    "rust": {"rust"},
    "swift": {"swift"},
    "terraform": {"terraform"},
    "iac": {"terraform"},
}
LANGUAGE_EXTENSIONS = {
    "python": {".py"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx"},
    "java": {".java"},
    "kotlin": {".kt", ".kts"},
    "go": {".go"},
    "csharp": {".cs"},
    "cpp": {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"},
    "c": {".c", ".h"},
    "php": {".php"},
    "ruby": {".rb"},
    "rust": {".rs"},
    "swift": {".swift"},
    "terraform": {".tf", ".tfvars", ".hcl"},
}


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(config_path: str | None) -> dict:
    paths = [DEFAULT_CONFIG_PATH]
    user_config = os.path.join(".claude", "sast", "config.yml")
    if os.path.isfile(user_config):
        paths.append(user_config)
    if config_path:
        paths.append(config_path)

    merged: dict = {}
    for path in paths:
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        merged = _deep_merge(merged, data)
    return merged


def _resolve_language_filter(lang_arg: str, detected_languages: set[str]) -> set[str]:
    if not lang_arg or lang_arg == "auto":
        return set(detected_languages)
    selected = LANGUAGE_FILTERS.get(lang_arg.lower().strip(), set())
    return selected & detected_languages if detected_languages else selected


def _filter_files_by_languages(files: list[str], languages: set[str]) -> list[str]:
    if not languages:
        return files
    allowed_exts = set()
    for language in languages:
        allowed_exts.update(LANGUAGE_EXTENSIONS.get(language, set()))
    if not allowed_exts:
        return files
    return [f for f in files if os.path.splitext(f)[1].lower() in allowed_exts]


def _stage_scan_subset(target: str, files: list[str]) -> tempfile.TemporaryDirectory | None:
    if not files:
        return None
    staged = tempfile.TemporaryDirectory(prefix="opensast-scan-")
    for rel_path in files:
        source = os.path.join(target, rel_path)
        if not os.path.isfile(source):
            continue
        dest = os.path.join(staged.name, rel_path)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(source, dest)
    return staged


def _load_llm_findings(import_path: str | None, repo_root: str) -> list[dict]:
    if not import_path:
        return []
    path = os.path.abspath(import_path)
    if not os.path.isfile(path):
        logger.warning("LLM findings file not found: %s", path)
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to load LLM findings from %s: %s", path, exc)
        return []

    is_valid, errors = validate_llm_findings(data)
    if not is_valid:
        logger.warning("LLM findings validation failed for %s: %s", path, "; ".join(errors[:5]))
        return []

    findings = normalize_llm_findings(data)
    for finding in findings:
        file_path = finding.get("file", "")
        if file_path and os.path.isabs(file_path):
            try:
                finding["file"] = os.path.relpath(file_path, repo_root)
            except ValueError:
                pass
    logger.info("Imported %d LLM findings from %s", len(findings), path)
    return findings


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

    # Gate enforcement is scenario-aware: a non-zero exit on blocking findings
    # only makes sense in CI (or when the user explicitly opts in). In a local,
    # interactive scan the runner must not "fail" just because it found issues.
    in_ci = is_ci_environment() or bool(getattr(args, "ci", False))
    fail_on_explicit = args.fail_on is not None or bool(getattr(args, "ci", False))
    enforce_gate = in_ci or fail_on_explicit

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

    detected_languages = set(project.get("languages", {}).keys())
    selected_languages = _resolve_language_filter(args.lang, detected_languages)
    if args.lang != "auto":
        logger.info("Language filter: %s -> %s", args.lang, ", ".join(sorted(selected_languages)) or "none")
    if selected_languages:
        project["languages"] = {
            lang: pct for lang, pct in project.get("languages", {}).items() if lang in selected_languages
        }
        detected_languages = set(project["languages"].keys())

    selected_files = changed_files[:] if changed_files else []
    if selected_files and selected_languages:
        selected_files = _filter_files_by_languages(selected_files, selected_languages)

    staged_target: tempfile.TemporaryDirectory | None = None
    if selected_files:
        staged_target = _stage_scan_subset(target, selected_files)
        if staged_target:
            scan_target = staged_target.name
            logger.info("Scanning staged subset: %d files", len(selected_files))

    tools_config = profile.get("tools", {})
    tool_timeout = args.tool_timeout or config.get("tools", {}).get("semgrep", {}).get("timeout", 300)
    scan_results: list[dict] = []

    if tools_config.get("semgrep", True) or (not tools_config and profile_name != "quick"):
        logger.info("Running Semgrep...")
        extra_configs = config.get("rules", {}).get("semgrep", [])
        config_paths = [c for c in extra_configs if c != "auto"] if extra_configs else None
        exclude_dirs = config.get("targets", {}).get("exclude", [])
        result = run_semgrep(
            scan_target, output_dir,
            config_paths=config_paths,
            timeout=tool_timeout,
            exclude_dirs=exclude_dirs,
        )
        scan_results.append(result)
        if not result["success"]:
            logger.warning("Semgrep: %s", result.get("error_message", "failed"))

    if tools_config.get("gitleaks", True):
        logger.info("Running Gitleaks...")
        result = run_gitleaks(scan_target, output_dir, timeout=tool_timeout)
        scan_results.append(result)
        if not result["success"]:
            logger.warning("Gitleaks: %s", result.get("error_message", "failed"))

    if tools_config.get("checkov", False) and project.get("iac_files"):
        logger.info("Running Checkov...")
        result = run_checkov(scan_target, output_dir, timeout=tool_timeout)
        scan_results.append(result)
        if not result["success"]:
            logger.warning("Checkov: %s", result.get("error_message", "failed"))

    if tools_config.get("codeql", False):
        logger.info("Running CodeQL...")
        codeql_config = config.get("tools", {}).get("codeql", {})
        codeql_timeout = codeql_config.get("timeout", 600)
        result = run_codeql(
            scan_target, output_dir,
            languages=list(detected_languages),
            query_suite=codeql_config.get("query_suite", "security-extended"),
            timeout=codeql_timeout,
            profile=profile_name,
            enable_cache=codeql_config.get("enable_cache", True),
            allow_package_manager_builds=codeql_config.get("allow_package_manager_builds", True),
            allow_repo_build_commands=codeql_config.get("allow_repo_build_commands", False),
        )
        scan_results.append(result)
        if not result["success"]:
            logger.warning("CodeQL: %s", result.get("error_message", "failed"))

    if "python" in detected_languages:
        logger.info("Running Bandit...")
        result = run_bandit(scan_target, output_dir, timeout=tool_timeout)
        scan_results.append(result)
        if not result["success"]:
            logger.warning("Bandit: %s", result.get("error_message", "failed"))

    if "go" in detected_languages:
        logger.info("Running gosec...")
        if staged_target:
            logger.info("Skipping gosec on staged subset; requires module/package context")
            result = {
                "tool": "gosec",
                "version": None,
                "exit_code": None,
                "sarif_path": None,
                "json_path": None,
                "error_message": "gosec skipped for changed-only scan because staged files do not preserve Go module context",
                "success": False,
            }
        else:
            result = run_gosec(scan_target, output_dir, timeout=tool_timeout)
        scan_results.append(result)
        if not result["success"]:
            logger.warning("gosec: %s", result.get("error_message", "failed"))

    if detected_languages & {"javascript", "typescript"}:
        logger.info("Running ESLint...")
        result = run_eslint_security(scan_target, output_dir, timeout=tool_timeout)
        scan_results.append(result)
        if not result["success"]:
            logger.warning("ESLint: %s", result.get("error_message", "skipped or failed"))

    if "ruby" in detected_languages:
        logger.info("Running Brakeman...")
        result = run_brakeman(scan_target, output_dir, timeout=tool_timeout)
        scan_results.append(result)
        if not result["success"]:
            logger.warning("Brakeman: %s", result.get("error_message", "skipped or failed"))

    if detected_languages & {"c", "cpp"}:
        logger.info("Running cppcheck...")
        result = run_cppcheck(scan_target, output_dir, timeout=tool_timeout)
        scan_results.append(result)
        if not result["success"]:
            logger.warning("cppcheck: %s", result.get("error_message", "skipped or failed"))

    if "rust" in detected_languages:
        logger.info("Running cargo-audit...")
        result = run_cargo_audit(scan_target, output_dir, timeout=tool_timeout)
        scan_results.append(result)
        if not result["success"]:
            logger.warning("cargo-audit: %s", result.get("error_message", "skipped or failed"))

    if "swift" in detected_languages:
        logger.info("Running SwiftLint...")
        result = run_swiftlint(scan_target, output_dir, timeout=tool_timeout)
        scan_results.append(result)
        if not result["success"]:
            logger.warning("SwiftLint: %s", result.get("error_message", "skipped or failed"))

    if "php" in detected_languages:
        logger.info("Running PHPStan...")
        result = run_phpstan(scan_target, output_dir, timeout=tool_timeout)
        scan_results.append(result)
        if not result["success"]:
            logger.warning("PHPStan: %s", result.get("error_message", "skipped or failed"))

    logger.info("Collecting and normalizing findings...")
    all_findings: list[dict] = []

    for r in scan_results:
        tool = r.get("tool", "")
        sarif_path = r.get("sarif_path")
        json_path = r.get("json_path")

        if sarif_path and os.path.isfile(sarif_path):
            try:
                with open(sarif_path, encoding="utf-8") as fh:
                    sarif_data = json.load(fh)
            except (json.JSONDecodeError, OSError):
                continue
            normalizer = NORMALIZERS.get(tool, normalize_semgrep)
            all_findings.extend(normalizer(sarif_data))
            continue

        if json_path and os.path.isfile(json_path):
            json_normalizer = JSON_NORMALIZERS.get(tool)
            if not json_normalizer:
                continue
            try:
                with open(json_path, encoding="utf-8") as fh:
                    json_data = json.load(fh)
            except (json.JSONDecodeError, OSError):
                continue
            all_findings.extend(json_normalizer(json_data))

    llm_findings_path = args.llm_findings or config.get("llm_findings", {}).get("import_file")
    if llm_findings_path:
        all_findings.extend(_load_llm_findings(llm_findings_path, project.get("repo_root", target)))

    all_findings = deduplicate_findings(all_findings)

    repo_root = project.get("repo_root", target)
    for f in all_findings:
        file_path = f.get("file", "")
        if file_path and os.path.isabs(file_path):
            try:
                f["file"] = os.path.relpath(file_path, repo_root)
            except ValueError:
                pass

    # Fast deterministic filters (generated code, test code)
    logger.info("Applying fast filters...")
    all_findings = apply_fast_filters(all_findings)

    baseline_path = args.baseline or config.get("baseline", {}).get("file", ".claude/sast/baseline.json")
    baseline_enabled = config.get("baseline", {}).get("enabled", True)

    baseline_data = {}
    if baseline_enabled:
        baseline_data = load_baseline(baseline_path)
        all_findings = filter_new_findings(all_findings, baseline_data)

    all_findings = redact_findings(all_findings)

    severity_counts = _count_severity(all_findings)
    new_count = sum(1 for f in all_findings if f.get("is_new"))

    logger.info("Merging SARIF files...")
    sarif_paths = _collect_sarif_paths(scan_results)
    merged_sarif_path = os.path.join(output_dir, "merged.sarif")
    if sarif_paths:
        merged = merge_sarif_files(sarif_paths, merged_sarif_path)
        merged = normalize_paths_in_sarif(merged, project.get("repo_root", target))
        merged = redact_sarif(merged)
        with open(merged_sarif_path, "w", encoding="utf-8") as fh:
            json.dump(merged, fh, indent=2)

    gate_result = evaluate_gate(
        all_findings,
        fail_on=fail_on,
        baseline_enabled=baseline_enabled,
        review_findings_blocking=config.get("gate", {}).get("review_findings_blocking", False),
    )
    blocking_count = gate_result.get("blocking_count", 0)

    tools_executed = [r["tool"] for r in scan_results if r.get("success")]
    tool_outcomes = collect_tool_outcomes(scan_results)
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
        "tool_outcomes": tool_outcomes,
        "tool_errors": tool_outcomes,
        "analysis_enrichment": summarize_analysis_enrichment(all_findings),
    }
    triage_counts = summary["analysis_enrichment"].get("by_triage", {})
    summary["review_findings"] = triage_counts.get("needs-review", 0)
    summary["suppressed_findings"] = triage_counts.get("suppressed", 0)

    if profile_name in ("standard", "deep"):
        logger.info("Generating LLM analysis plan...")
        try:
            llm_plan = generate_analysis_plan(
                findings=all_findings,
                project=project,
                project_root=target,
                config=config,
            )
            plan_path = save_analysis_plan(llm_plan, output_dir)
            logger.info(
                "LLM analysis plan: %s (%d validation targets, %d discovery targets, archetype=%s)",
                plan_path,
                len(llm_plan.get("analysis_targets", [])),
                len(llm_plan.get("discover_targets", [])),
                llm_plan.get("project_archetype", "unknown"),
            )
            summary["llm_analysis_targets"] = len(llm_plan.get("analysis_targets", []))
            summary["llm_discovery_targets"] = len(llm_plan.get("discover_targets", []))
            summary["project_archetype"] = llm_plan.get("project_archetype", "unknown")
        except Exception as e:
            logger.warning("LLM analysis plan generation failed: %s", e)

    # Compliance mapping (GB/T 35273, PCI DSS, ISO 27001)
    if profile_name in ("standard", "deep"):
        try:
            from compliance import compute_all_compliance, generate_compliance_report
            all_compliance = compute_all_compliance(all_findings)
            summary["compliance"] = all_compliance
            compliance_md = os.path.join(output_dir, "compliance.md")
            with open(compliance_md, "w", encoding="utf-8") as fh:
                fh.write(generate_compliance_report(all_compliance, all_findings))
            logger.info("Compliance report: %s", compliance_md)
        except Exception as e:
            logger.debug("Compliance mapping failed: %s", e)

    # Trend analysis
    if profile_name in ("standard", "deep") and config.get("history", {}).get("enabled", True):
        history_dir = os.path.join(os.path.dirname(output_dir), "history")
        scan_history = load_scan_history(history_dir, limit=30)
        if len(scan_history) >= 2:
            from trend_analysis import compute_trend_metrics
            summary["trend_analysis"] = compute_trend_metrics(scan_history)

    summary["next_steps"] = build_report_next_steps(summary, all_findings)

    logger.info("Generating reports...")
    try:
        if "html" in formats or "all" in formats:
            html_path = os.path.join(output_dir, "report.html")
            generate_html_report(summary, all_findings, html_path)
            logger.info("HTML report: %s", html_path)

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

    # Save scan history
    try:
        scan_id = save_scan_result(summary, all_findings, output_dir)
        logger.info("Scan history saved: %s", scan_id)
    except Exception as e:
        logger.debug("Failed to save scan history: %s", e)

    # Trend gate
    trend_config = config.get("gate", {}).get("trend", {})
    if trend_config.get("enabled", False):
        history_dir = os.path.join(os.path.dirname(output_dir), "history")
        trend_result = check_trend_gate(summary, all_findings, history_dir, config)
        summary["trend_gate"] = trend_result
        if trend_result.get("is_blocking"):
            logger.warning("Trend gate BLOCKING: %s", "; ".join(trend_result.get("blocking_reasons", [])))
            gate_result["passed"] = False

    # PR comment
    if args.pr_comment:
        try:
            post_pr_comment(summary, all_findings)
        except Exception as e:
            logger.debug("PR comment failed: %s", e)

    logger.info("Scan complete in %ss — %d total, %d new, %d blocking", elapsed, len(all_findings), new_count, blocking_count)

    exit_code = get_exit_code(gate_result)
    if not gate_result.get("passed", True):
        if enforce_gate:
            logger.warning(
                "Gate FAILED: %d findings at or above '%s' severity",
                blocking_count,
                fail_on,
            )
        else:
            # Local, interactive run: findings exist but we do not fail the
            # process. Surface the gate status as guidance only.
            exit_code = EXIT_OK
            logger.info(
                "Gate status: %d findings at or above '%s' would fail CI. "
                "Re-run with --ci (or set --fail-on) to enforce locally.",
                blocking_count,
                fail_on,
            )
    if staged_target:
        staged_target.cleanup()
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
    parser.add_argument("--target", dest="target_opt", default=None, help="Target path to scan (alias for the positional argument)")
    parser.add_argument("--profile", choices=["quick", "standard", "deep"], help="Scan profile")
    parser.add_argument("--changed-only", action="store_true", help="Scan only changed files")
    parser.add_argument("--lang", default="auto", help="Language filter (default: auto)")
    parser.add_argument("--format", dest="format", help="Report format: markdown,json,sarif,all")
    parser.add_argument("--output-dir", help="Output directory (default: .claude/sast/results)")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="Fail gate on severity")
    parser.add_argument(
        "--ci",
        action="store_true",
        help="Enforce the gate (non-zero exit on blocking findings) even when not auto-detected as CI",
    )
    parser.add_argument("--baseline", help="Baseline file path")
    parser.add_argument("--config", help="Config file path")
    parser.add_argument("--tool-timeout", type=int, help="Per-tool timeout in seconds")
    parser.add_argument("--llm-findings", help="Import LLM findings JSON and merge into final results")
    parser.add_argument("--pr-comment", action="store_true", help="Post results as GitHub PR comment")
    args = parser.parse_args(argv)
    # ``--target`` is the documented/CI interface (README, roadmap, workflows);
    # the positional form is kept for backward compatibility with tests.
    if args.target_opt is not None:
        args.target = args.target_opt
    return args


def main() -> int:
    args = parse_args()
    try:
        return run(args)
    except Exception as e:
        logging.critical("Fatal error: %s", e, exc_info=True)
        return EXIT_SCAN_FAILURE


if __name__ == "__main__":
    sys.exit(main())
