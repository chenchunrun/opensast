"""Run SwiftLint for Swift projects."""

import json
import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)


def run_swiftlint(target: str, output_dir: str, timeout: int = 300) -> dict:
    if not shutil.which("swiftlint"):
        return _skip("swiftlint is not installed. Install: brew install swiftlint")

    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "swiftlint.json")
    cmd = ["swiftlint", "lint", "--reporter", "json", "--path", target, "--quiet"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.stdout.strip():
            with open(json_path, "w", encoding="utf-8") as fh:
                fh.write(result.stdout)
        has_json = os.path.isfile(json_path) and os.path.getsize(json_path) > 0
        return {
            "tool": "swiftlint",
            "version": _get_version(),
            "exit_code": result.returncode,
            "sarif_path": None,
            "json_path": json_path if has_json else None,
            "error_message": None if has_json else (result.stderr.strip() or "swiftlint produced no output"),
            "success": has_json,
        }
    except subprocess.TimeoutExpired:
        return _fail(f"swiftlint timed out after {timeout}s")
    except Exception as e:
        return _fail(str(e))


def _get_version() -> str:
    try:
        result = subprocess.run(["swiftlint", "version"], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "unknown"


def _skip(message: str) -> dict:
    return {
        "tool": "swiftlint", "version": None, "exit_code": None,
        "sarif_path": None, "json_path": None,
        "error_message": message, "success": False,
    }


def _fail(message: str) -> dict:
    return {
        "tool": "swiftlint", "version": None, "exit_code": None,
        "sarif_path": None, "json_path": None,
        "error_message": message, "success": False,
    }


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run SwiftLint scan")
    parser.add_argument("target")
    parser.add_argument("-o", "--output-dir", default="./results")
    parser.add_argument("-t", "--timeout", type=int, default=300)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(run_swiftlint(args.target, args.output_dir, args.timeout), indent=2))


if __name__ == "__main__":
    main()
