"""Run ESLint with security-focused rules when available in the target project."""

import json
import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)


def run_eslint_security(target: str, output_dir: str, timeout: int = 300) -> dict:
    eslint = shutil.which("eslint")
    npx = shutil.which("npx")
    if not eslint and not npx:
        return _skip("eslint is not installed. Install: npm install -g eslint eslint-plugin-security")

    if not os.path.isfile(os.path.join(target, "package.json")):
        return _skip("no package.json found; skipping eslint security scan")

    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "eslint.json")
    cmd = (
        [npx, "eslint", target, "--format", "json", "-o", json_path, "--no-error-on-unmatched-pattern"]
        if npx and not eslint
        else ["eslint", target, "--format", "json", "-o", json_path, "--no-error-on-unmatched-pattern"]
    )

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=target)
        has_json = os.path.isfile(json_path) and os.path.getsize(json_path) > 0
        return {
            "tool": "eslint",
            "version": _get_version(eslint, npx),
            "exit_code": result.returncode,
            "sarif_path": None,
            "json_path": json_path if has_json else None,
            "error_message": None if has_json else (result.stderr.strip() or "eslint produced no output"),
            "success": has_json,
        }
    except subprocess.TimeoutExpired:
        return _fail(f"eslint timed out after {timeout}s")
    except Exception as e:
        return _fail(str(e))


def _get_version(eslint: str | None, npx: str | None) -> str:
    try:
        cmd = [eslint or npx, "--version"] if eslint else [npx, "eslint", "--version"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return result.stdout.strip().split("\n")[0]
    except Exception:
        pass
    return "unknown"


def _skip(message: str) -> dict:
    return {
        "tool": "eslint", "version": None, "exit_code": None,
        "sarif_path": None, "json_path": None,
        "error_message": message, "success": False,
    }


def _fail(message: str) -> dict:
    return {
        "tool": "eslint", "version": None, "exit_code": None,
        "sarif_path": None, "json_path": None,
        "error_message": message, "success": False,
    }


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run ESLint security scan")
    parser.add_argument("target")
    parser.add_argument("-o", "--output-dir", default="./results")
    parser.add_argument("-t", "--timeout", type=int, default=300)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(run_eslint_security(args.target, args.output_dir, args.timeout), indent=2))


if __name__ == "__main__":
    main()
