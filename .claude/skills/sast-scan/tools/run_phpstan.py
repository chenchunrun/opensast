"""Run PHPStan when available in the target PHP project."""

import json
import logging
import os
import subprocess

logger = logging.getLogger(__name__)


def _find_phpstan(target: str) -> str | None:
    candidates = [
        os.path.join(target, "vendor", "bin", "phpstan"),
        os.path.join(target, "vendor", "bin", "phpstan.phar"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def run_phpstan(target: str, output_dir: str, timeout: int = 600) -> dict:
    phpstan = _find_phpstan(target)
    if not phpstan:
        return _skip("phpstan not found in vendor/bin; run composer require --dev phpstan/phpstan")

    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "phpstan.json")
    cmd = [phpstan, "analyse", target, "--error-format=json", f"--output={json_path}"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=target)
        has_json = os.path.isfile(json_path) and os.path.getsize(json_path) > 0
        return {
            "tool": "phpstan",
            "version": "project-local",
            "exit_code": result.returncode,
            "sarif_path": None,
            "json_path": json_path if has_json else None,
            "error_message": None if has_json else (result.stderr.strip() or "phpstan produced no output"),
            "success": has_json,
        }
    except subprocess.TimeoutExpired:
        return _fail(f"phpstan timed out after {timeout}s")
    except Exception as e:
        return _fail(str(e))


def _skip(message: str) -> dict:
    return {
        "tool": "phpstan", "version": None, "exit_code": None,
        "sarif_path": None, "json_path": None,
        "error_message": message, "success": False,
    }


def _fail(message: str) -> dict:
    return {
        "tool": "phpstan", "version": None, "exit_code": None,
        "sarif_path": None, "json_path": None,
        "error_message": message, "success": False,
    }


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run PHPStan scan")
    parser.add_argument("target")
    parser.add_argument("-o", "--output-dir", default="./results")
    parser.add_argument("-t", "--timeout", type=int, default=600)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(run_phpstan(args.target, args.output_dir, args.timeout), indent=2))


if __name__ == "__main__":
    main()
