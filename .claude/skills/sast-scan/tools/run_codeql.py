"""Run CodeQL SAST scan with multi-language support and build detection."""

import argparse
import json
import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)

LANG_MAP: dict[str, str] = {
    "python": "python", "javascript": "javascript", "typescript": "javascript",
    "java": "java", "go": "go", "csharp": "csharp", "cpp": "cpp",
    "ruby": "ruby", "swift": "swift", "kotlin": "java",
}
SUPPORTED_LANGUAGES = list(LANG_MAP.keys())

QUERY_SUITES = {
    "quick": "security-extended",
    "standard": "security-extended",
    "deep": "security-and-quality",
}


def _result(version: str | None, exit_code: int | None = None,
            sarif_path: str | None = None, error_message: str | None = None,
            success: bool = False) -> dict:
    return {
        "tool": "codeql", "version": version, "exit_code": exit_code,
        "sarif_path": sarif_path, "json_path": None,
        "error_message": error_message, "success": success,
    }


def _get_version() -> str:
    try:
        r = subprocess.run(["codeql", "version"], capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return r.stdout.strip().split("\n")[0]
    except Exception:
        pass
    return "unknown"


def _resolve_languages(languages: list[str]) -> list[str]:
    seen: set[str] = set()
    resolved: list[str] = []
    for lang in languages:
        normalized = lang.lower().strip()
        codeql_lang = LANG_MAP.get(normalized)
        if codeql_lang and codeql_lang not in seen:
            seen.add(codeql_lang)
            resolved.append(codeql_lang)
    return resolved


# --- Build command detection ---


def _detect_java_build(target: str) -> list[str] | None:
    if os.path.isfile(os.path.join(target, "mvnw")):
        return ["./mvnw", "compile", "-DskipTests", "-q"]
    if shutil.which("mvn"):
        return ["mvn", "compile", "-DskipTests", "-q"]
    if os.path.isfile(os.path.join(target, "gradlew")):
        return ["./gradlew", "compileJava", "-x", "test", "-q"]
    if os.path.isfile(os.path.join(target, "build.gradle")) and shutil.which("gradle"):
        return ["gradle", "compileJava", "-x", "test", "-q"]
    return None


def _detect_go_build(target: str) -> list[str] | None:
    if os.path.isfile(os.path.join(target, "go.mod")):
        return ["go", "build", "./..."]
    return None


def _detect_csharp_build(target: str) -> list[str] | None:
    if shutil.which("dotnet"):
        for root, _dirs, files in os.walk(target):
            for f in files:
                if f.endswith(".csproj") or f.endswith(".sln"):
                    return ["dotnet", "build", "--no-restore", "-v", "q"]
            break
    return None


def _detect_cpp_build(target: str) -> list[str] | None:
    compile_db = os.path.join(target, "compile_commands.json")
    if os.path.isfile(compile_db):
        return None  # CodeQL uses compile_commands.json directly
    if os.path.isfile(os.path.join(target, "CMakeLists.txt")):
        return ["cmake", "--build", ".", "--clean-first"]
    if os.path.isfile(os.path.join(target, "Makefile")):
        return ["make"]
    return None


BUILD_DETECTORS: dict[str, callable] = {
    "java": _detect_java_build,
    "go": _detect_go_build,
    "csharp": _detect_csharp_build,
    "cpp": _detect_cpp_build,
}

INTERPRETED_LANGUAGES = {"python", "javascript", "ruby"}


def detect_build_command(target: str, language: str) -> list[str] | None:
    if language in INTERPRETED_LANGUAGES:
        return None
    detector = BUILD_DETECTORS.get(language)
    if detector:
        return detector(target)
    return None


# --- Database caching ---


def _get_cache_key(target: str, language: str) -> str:
    try:
        r = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=target, capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            return f"{language}:{r.stdout.strip()}"
    except Exception:
        pass
    return f"{language}:{os.path.getmtime(target)}"


def _cache_meta_path(cache_dir: str, language: str) -> str:
    return os.path.join(cache_dir, f"{language}.meta")


def _is_cache_valid(cache_dir: str, language: str, target: str) -> bool:
    meta_path = _cache_meta_path(cache_dir, language)
    if not os.path.isfile(meta_path):
        return False
    try:
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)
        return meta.get("cache_key") == _get_cache_key(target, language)
    except (json.JSONDecodeError, OSError):
        return False


def _save_cache_meta(cache_dir: str, language: str, target: str) -> None:
    os.makedirs(cache_dir, exist_ok=True)
    meta_path = _cache_meta_path(cache_dir, language)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump({"cache_key": _get_cache_key(target, language)}, f)


# --- Database creation and analysis ---


def _create_database(target: str, db_path: str, language: str,
                     build_cmd: list[str] | None, timeout: int) -> bool:
    cmd = ["codeql", "database", "create", db_path,
           f"--language={language}", f"--source-root={target}", "--overwrite"]
    if build_cmd:
        cmd.extend([f"--command={shlex_join(build_cmd)}"])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            logger.warning("CodeQL database creation failed (lang=%s): %s",
                           language, (r.stderr or "unknown error")[:500])
            return False
        if r.stderr:
            logger.debug("codeql database create stderr: %s", r.stderr[:500])
        return True
    except subprocess.TimeoutExpired:
        logger.warning("CodeQL database creation timed out after %ds", timeout)
        return False
    except Exception as e:
        logger.warning("CodeQL database creation error: %s", e)
        return False


def _analyze_database(db_path: str, sarif_path: str, query_suite: str,
                      timeout: int, version: str) -> dict:
    cmd = ["codeql", "database", "analyze", db_path, query_suite,
           "--format=sarif-latest", f"--output={sarif_path}"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.stderr:
            logger.debug("codeql analyze stderr: %s", r.stderr[:500])
        sarif_exists = os.path.isfile(sarif_path) and os.path.getsize(sarif_path) > 0
        return _result(
            version, r.returncode,
            sarif_path=sarif_path if sarif_exists else None,
            error_message=r.stderr.strip() if r.stderr and r.returncode not in (0, 1) else None,
            success=sarif_exists and r.returncode in (0, 1),
        )
    except subprocess.TimeoutExpired:
        return _result(version, error_message=f"CodeQL analysis timed out after {timeout}s")
    except Exception as e:
        return _result(version, error_message=str(e))


def shlex_join(args: list[str]) -> str:
    try:
        import shlex
        return shlex.join(args)
    except AttributeError:
        return " ".join(args)


# --- Main entry point ---


def run_codeql(
    target: str,
    output_dir: str,
    languages: list[str] | None = None,
    query_suite: str = "security-extended",
    timeout: int = 600,
    profile: str = "standard",
    enable_cache: bool = True,
) -> dict:
    if not shutil.which("codeql"):
        return _result(None, error_message="codeql CLI is not installed. Install: https://github.com/github/codeql-cli-binaries")

    os.makedirs(output_dir, exist_ok=True)
    version = _get_version()

    if languages is None:
        languages = ["python"]

    resolved = _resolve_languages(languages)
    if not resolved:
        return _result(version, error_message=f"No supported language found in: {languages}. Supported: {SUPPORTED_LANGUAGES}")

    effective_suite = QUERY_SUITES.get(profile, query_suite)

    cache_dir = os.path.join(output_dir, "codeql-cache")
    db_timeout = timeout // 2 if timeout > 120 else timeout
    analysis_timeout = timeout - db_timeout if timeout > 120 else timeout

    merged_sarif_path = os.path.join(output_dir, "codeql.sarif")
    all_sarif_runs: list[dict] = []
    errors: list[str] = []

    for lang in resolved:
        db_path = os.path.join(output_dir, f"codeql-db-{lang}")
        lang_sarif = os.path.join(output_dir, f"codeql-{lang}.sarif")

        build_cmd = detect_build_command(target, lang)
        needs_create = True

        if enable_cache and _is_cache_valid(cache_dir, lang, target):
            cached_db = os.path.join(cache_dir, lang)
            if os.path.isdir(cached_db):
                logger.info("Using cached CodeQL database for %s", lang)
                try:
                    if os.path.isdir(db_path):
                        shutil.rmtree(db_path)
                    shutil.copytree(cached_db, db_path)
                    needs_create = False
                except OSError:
                    needs_create = True

        if needs_create:
            logger.info("Creating CodeQL database for %s (build=%s)", lang, build_cmd or "none")
            if not _create_database(target, db_path, lang, build_cmd, db_timeout):
                errors.append(f"Database creation failed for {lang}")
                continue
            if enable_cache:
                cache_dest = os.path.join(cache_dir, lang)
                try:
                    if os.path.isdir(cache_dest):
                        shutil.rmtree(cache_dest)
                    shutil.copytree(db_path, cache_dest)
                    _save_cache_meta(cache_dir, lang, target)
                except OSError as e:
                    logger.debug("Cache save failed for %s: %s", lang, e)

        logger.info("Analyzing CodeQL database for %s (suite=%s)", lang, effective_suite)
        result = _analyze_database(db_path, lang_sarif, effective_suite, analysis_timeout, version)
        if result["success"] and result["sarif_path"]:
            try:
                with open(result["sarif_path"], encoding="utf-8") as f:
                    sarif = json.load(f)
                all_sarif_runs.extend(sarif.get("runs", []))
            except (json.JSONDecodeError, OSError):
                errors.append(f"Failed to read SARIF for {lang}")
        else:
            errors.append(result.get("error_message") or f"Analysis failed for {lang}")

    if all_sarif_runs:
        merged = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": all_sarif_runs,
        }
        with open(merged_sarif_path, "w", encoding="utf-8") as f:
            json.dump(merged, f, indent=2)
        return _result(version, 0, sarif_path=merged_sarif_path, success=True)

    if errors:
        return _result(version, error_message="; ".join(errors))
    return _result(version, error_message="No results produced")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run CodeQL SAST scan")
    parser.add_argument("target", help="Target directory to scan")
    parser.add_argument("-o", "--output-dir", default="./results")
    parser.add_argument("-l", "--language", action="append",
                        help="Language to scan (repeatable). Supported: " + ", ".join(SUPPORTED_LANGUAGES))
    parser.add_argument("-q", "--query-suite", default="security-extended",
                        help="Query suite (default: security-extended)")
    parser.add_argument("-t", "--timeout", type=int, default=600)
    parser.add_argument("-p", "--profile", default="standard",
                        choices=["quick", "standard", "deep"])
    parser.add_argument("--no-cache", action="store_true", help="Disable database caching")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    result = run_codeql(
        args.target, args.output_dir, args.language, args.query_suite,
        args.timeout, args.profile, enable_cache=not args.no_cache,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
