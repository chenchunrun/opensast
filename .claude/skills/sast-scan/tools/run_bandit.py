import argparse
import json
import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)


def run_bandit(target: str, output_dir: str, timeout: int = 300, exclude_dirs: list[str] | None = None, config_file: str | None = None) -> dict:
    if not shutil.which("bandit"):
        return {
            "tool": "bandit", "version": None, "exit_code": None,
            "sarif_path": None, "json_path": None,
            "error_message": "bandit is not installed. Install: pip install bandit",
            "success": False,
        }

    os.makedirs(output_dir, exist_ok=True)
    version = _get_version()
    sarif_path = os.path.join(output_dir, "bandit.sarif")
    json_path = os.path.join(output_dir, "bandit.json")

    excludes = exclude_dirs if exclude_dirs else ["./tests", "./.git", "./node_modules"]
    exclude_str = ",".join(excludes)

    sarif_cmd = ["bandit", "-r", target, "-f", "sarif", "-o", sarif_path, "--exit-zero", "--exclude", exclude_str]
    json_cmd = ["bandit", "-r", target, "-f", "json", "-o", json_path, "--exit-zero", "--exclude", exclude_str]

    if config_file:
        sarif_cmd.extend(["--ini", config_file])
        json_cmd.extend(["--ini", config_file])

    exit_code = None
    error_message = None

    try:
        result = subprocess.run(sarif_cmd, capture_output=True, text=True, timeout=timeout)
        exit_code = result.returncode
        if result.stderr:
            logger.debug("bandit sarif stderr: %s", result.stderr[:500])

        subprocess.run(json_cmd, capture_output=True, text=True, timeout=timeout)

    except subprocess.TimeoutExpired:
        return {
            "tool": "bandit", "version": version, "exit_code": None,
            "sarif_path": None, "json_path": None,
            "error_message": f"bandit timed out after {timeout}s",
            "success": False,
        }
    except Exception as e:
        return {
            "tool": "bandit", "version": version, "exit_code": None,
            "sarif_path": None, "json_path": None,
            "error_message": str(e), "success": False,
        }

    has_sarif = os.path.isfile(sarif_path) and os.path.getsize(sarif_path) > 0
    has_json = os.path.isfile(json_path) and os.path.getsize(json_path) > 0

    return {
        "tool": "bandit", "version": version, "exit_code": exit_code,
        "sarif_path": sarif_path if has_sarif else None,
        "json_path": json_path if has_json else None,
        "error_message": error_message, "success": exit_code == 0,
    }


def _get_version() -> str:
    try:
        result = subprocess.run(["bandit", "--version"], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return result.stdout.strip().split("\n")[0]
    except Exception:
        pass
    return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Bandit Python security scan")
    parser.add_argument("target", help="Target directory to scan")
    parser.add_argument("-o", "--output-dir", default="./results")
    parser.add_argument("-t", "--timeout", type=int, default=300)
    parser.add_argument("-e", "--exclude", action="append", help="Dirs to exclude (repeatable)")
    parser.add_argument("-c", "--config", help="Path to bandit config file (.ini)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    result = run_bandit(args.target, args.output_dir, args.timeout, args.exclude, args.config)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
