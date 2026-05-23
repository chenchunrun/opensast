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
    "ruby": "ruby", "swift": "swift",
}
SUPPORTED_LANGUAGES = list(LANG_MAP.keys())


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


def _resolve_language(languages: list[str]) -> str | None:
    for lang in languages:
        normalized = lang.lower().strip()
        if normalized in LANG_MAP:
            return LANG_MAP[normalized]
    return None


def _create_database(target: str, db_path: str, language: str, timeout: int) -> bool:
    cmd = ["codeql", "database", "create", db_path,
           f"--language={language}", f"--source-root={target}", "--overwrite"]
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


def run_codeql(
    target: str,
    output_dir: str,
    languages: list[str] | None = None,
    query_suite: str = "security-extended",
    timeout: int = 600,
) -> dict:
    if not shutil.which("codeql"):
        return _result(None, error_message="codeql CLI is not installed. Install: https://github.com/github/codeql-cli-binaries")

    os.makedirs(output_dir, exist_ok=True)
    version = _get_version()

    if languages is None:
        languages = ["python"]

    codeql_lang = _resolve_language(languages)
    if codeql_lang is None:
        return _result(version, error_message=f"No supported language found in: {languages}. Supported: {SUPPORTED_LANGUAGES}")

    db_path = os.path.join(output_dir, "codeql-db")
    sarif_path = os.path.join(output_dir, "codeql.sarif")

    if not _create_database(target, db_path, codeql_lang, timeout):
        return _result(version, error_message=f"Database creation failed for language '{codeql_lang}'. Compiled languages may require a build step.")

    return _analyze_database(db_path, sarif_path, query_suite, timeout, version)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run CodeQL SAST scan")
    parser.add_argument("target", help="Target directory to scan")
    parser.add_argument("-o", "--output-dir", default="./results")
    parser.add_argument("-l", "--language", action="append",
                        help="Language to scan (repeatable). Supported: " + ", ".join(SUPPORTED_LANGUAGES))
    parser.add_argument("-q", "--query-suite", default="security-extended",
                        help="Query suite (default: security-extended)")
    parser.add_argument("-t", "--timeout", type=int, default=600,
                        help="Timeout per step in seconds (default: 600)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    result = run_codeql(args.target, args.output_dir, args.language, args.query_suite, args.timeout)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
