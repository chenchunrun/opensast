"""Run cppcheck static analysis for C/C++ projects."""

import json
import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)


def run_cppcheck(target: str, output_dir: str, timeout: int = 600) -> dict:
    if not shutil.which("cppcheck"):
        return _skip("cppcheck is not installed. Install via package manager: apt/brew install cppcheck")

    os.makedirs(output_dir, exist_ok=True)
    sarif_path = os.path.join(output_dir, "cppcheck.sarif")
    json_path = os.path.join(output_dir, "cppcheck.json")

    sarif_cmd = [
        "cppcheck", "--enable=warning,style,performance,portability",
        "--sarif", sarif_path, "--quiet", "--suppress=missingIncludeSystem", target,
    ]
    json_cmd = [
        "cppcheck", "--enable=warning,style,performance,portability",
        "--error-exitcode=0", "--output-file", json_path, "--quiet", target,
    ]

    try:
        result = subprocess.run(sarif_cmd, capture_output=True, text=True, timeout=timeout)
        subprocess.run(json_cmd, capture_output=True, text=True, timeout=timeout)
        has_sarif = os.path.isfile(sarif_path) and os.path.getsize(sarif_path) > 0
        has_json = os.path.isfile(json_path) and os.path.getsize(json_path) > 0
        return {
            "tool": "cppcheck",
            "version": _get_version(),
            "exit_code": result.returncode,
            "sarif_path": sarif_path if has_sarif else None,
            "json_path": json_path if has_json else None,
            "error_message": None if (has_sarif or has_json) else (result.stderr.strip() or "cppcheck produced no output"),
            "success": has_sarif or has_json,
        }
    except subprocess.TimeoutExpired:
        return _fail(f"cppcheck timed out after {timeout}s")
    except Exception as e:
        return _fail(str(e))


def _get_version() -> str:
    try:
        result = subprocess.run(["cppcheck", "--version"], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return result.stdout.strip().split("\n")[0]
    except Exception:
        pass
    return "unknown"


def _skip(message: str) -> dict:
    return {
        "tool": "cppcheck", "version": None, "exit_code": None,
        "sarif_path": None, "json_path": None,
        "error_message": message, "success": False,
    }


def _fail(message: str) -> dict:
    return {
        "tool": "cppcheck", "version": None, "exit_code": None,
        "sarif_path": None, "json_path": None,
        "error_message": message, "success": False,
    }


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run cppcheck C/C++ scan")
    parser.add_argument("target")
    parser.add_argument("-o", "--output-dir", default="./results")
    parser.add_argument("-t", "--timeout", type=int, default=600)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(run_cppcheck(args.target, args.output_dir, args.timeout), indent=2))


if __name__ == "__main__":
    main()
