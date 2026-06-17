import argparse
import json
import logging
import os
import shutil
import subprocess
import tempfile

logger = logging.getLogger(__name__)

SCAN_EXTENSIONS = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".java", ".kt", ".kts", ".go", ".rs", ".rb", ".php", ".cs",
    ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp",
    ".scala", ".swift", ".tf", ".tfvars",
}

DEFAULT_EXCLUDE_DIRS = frozenset({
    "node_modules", ".git", "venv", ".venv", "__pycache__",
    "dist", "build", ".gradle", "target", "vendor",
    ".next", ".nuxt", ".turbo", "coverage", ".cache",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".parcel-cache", ".sass-cache", ".vscode", ".idea",
    ".opensast-semgrep-home",
})

SEMGREP_ENV = {
    "SEMGREP_SEND_METRICS": "off",
    "SEMGREP_ENABLE_VERSION_CHECK": "0",
}


def get_semgrep_binary() -> str | None:
    return shutil.which("pysemgrep") or shutil.which("semgrep")


def build_semgrep_env(_base_dir: str | None = None) -> dict[str, str]:
    """Build a Semgrep-friendly environment with an isolated writable HOME.

    HOME is always placed under the system temp directory. Do not nest it under
    rule trees or scan targets — Semgrep may treat ``.semgrep/settings.yml``
    inside those paths as rule configs and fail with exit code 7.
    """
    env = {**os.environ, **SEMGREP_ENV}

    home_dir = os.path.join(tempfile.gettempdir(), "opensast-semgrep-home")
    os.makedirs(home_dir, exist_ok=True)
    os.makedirs(os.path.join(home_dir, ".semgrep"), exist_ok=True)
    env["HOME"] = home_dir

    cert_path = None
    try:
        import certifi  # type: ignore
        cert_path = certifi.where()
    except Exception:
        if os.path.isfile("/etc/ssl/cert.pem"):
            cert_path = "/etc/ssl/cert.pem"

    if cert_path:
        env.setdefault("SSL_CERT_FILE", cert_path)
        env.setdefault("REQUESTS_CA_BUNDLE", cert_path)

    return env


def _collect_scan_targets(
    target: str,
    exclude_dirs: set[str] | None = None,
) -> list[str]:
    if os.path.isfile(target):
        return [os.path.abspath(target)]
    skipped = DEFAULT_EXCLUDE_DIRS | (exclude_dirs or set())
    abs_target = os.path.abspath(target)
    targets = []
    for root, dirs, files in os.walk(abs_target):
        dirs[:] = [d for d in dirs if d not in skipped]
        for f in files:
            _, ext = os.path.splitext(f)
            if ext.lower() in SCAN_EXTENSIONS:
                targets.append(os.path.join(root, f))
    return targets


def run_semgrep(
    target: str,
    output_dir: str,
    config_paths: list[str] | None = None,
    timeout: int = 300,
    max_size_mb: int = 50,
    exclude_dirs: list[str] | None = None,
) -> dict:
    semgrep_bin = get_semgrep_binary()
    if not semgrep_bin:
        return {
            "tool": "semgrep", "version": None, "exit_code": None,
            "sarif_path": None, "json_path": None,
            "error_message": "semgrep is not installed. Install: pip install semgrep",
            "success": False,
        }

    os.makedirs(output_dir, exist_ok=True)

    version = _get_version()

    sarif_path = os.path.join(output_dir, "semgrep.sarif")
    json_path = os.path.join(output_dir, "semgrep.json")

    extra_excludes = set(exclude_dirs) if exclude_dirs else set()
    scan_targets = _collect_scan_targets(target, extra_excludes)
    if not scan_targets:
        logger.info("No scannable files found in target: %s", target)
        return {
            "tool": "semgrep", "version": version, "exit_code": 0,
            "sarif_path": None, "json_path": None,
            "error_message": None, "success": True,
        }

    cmd = [
        semgrep_bin,
        "--sarif-output", sarif_path,
        "--json-output", json_path,
        "--timeout", str(timeout),
    ]

    if config_paths:
        for cfg in config_paths:
            cmd.extend(["--config", cfg])
    else:
        # Fall back to semgrep registry rules when no custom config is provided.
        # Use explicit rule packs (no auto-config) so metrics-off is respected.
        cmd.extend(["--config", "p/default"])

    cmd.extend(scan_targets)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 60,
            env=build_semgrep_env(),
        )
        exit_code = result.returncode

        if result.stderr:
            logger.debug("semgrep stderr: %s", result.stderr[:500])

        has_sarif = os.path.isfile(sarif_path) and os.path.getsize(sarif_path) > 0
        has_json = os.path.isfile(json_path) and os.path.getsize(json_path) > 0

        return {
            "tool": "semgrep", "version": version, "exit_code": exit_code,
            "sarif_path": sarif_path if has_sarif else None,
            "json_path": json_path if has_json else None,
            "error_message": result.stderr.strip() if result.stderr and exit_code not in (0, 1) else None,
            "success": exit_code in (0, 1),
        }

    except subprocess.TimeoutExpired:
        return {
            "tool": "semgrep", "version": version, "exit_code": None,
            "sarif_path": None, "json_path": None,
            "error_message": f"semgrep timed out after {timeout + 60}s",
            "success": False,
        }
    except Exception as e:
        return {
            "tool": "semgrep", "version": version, "exit_code": None,
            "sarif_path": None, "json_path": None,
            "error_message": str(e), "success": False,
        }


def _get_version() -> str:
    semgrep_bin = get_semgrep_binary()
    if not semgrep_bin:
        return "unknown"
    try:
        result = subprocess.run(
            [semgrep_bin, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            env=build_semgrep_env(),
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Semgrep SAST scan")
    parser.add_argument("target", help="Target directory or file to scan")
    parser.add_argument("-o", "--output-dir", default="./results")
    parser.add_argument("-t", "--timeout", type=int, default=300)
    parser.add_argument("-m", "--max-size-mb", type=int, default=50)
    parser.add_argument("-c", "--config", action="append")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    result = run_semgrep(args.target, args.output_dir, args.config, args.timeout, args.max_size_mb)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
