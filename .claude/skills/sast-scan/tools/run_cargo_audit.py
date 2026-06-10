"""Run cargo-audit for Rust dependency vulnerabilities."""

import json
import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)


def _find_cargo_root(target: str) -> str | None:
    path = os.path.abspath(target)
    while True:
        if os.path.isfile(os.path.join(path, "Cargo.toml")):
            return path
        parent = os.path.dirname(path)
        if parent == path:
            return None
        path = parent


def run_cargo_audit(target: str, output_dir: str, timeout: int = 300) -> dict:
    if not shutil.which("cargo-audit"):
        return _skip("cargo-audit is not installed. Install: cargo install cargo-audit")

    cargo_root = _find_cargo_root(target)
    if not cargo_root:
        return _skip("no Cargo.toml found; skipping cargo-audit")

    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "cargo-audit.json")
    cmd = ["cargo", "audit", "--json", "-q"]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=cargo_root,
        )
        if result.stdout.strip():
            with open(json_path, "w", encoding="utf-8") as fh:
                fh.write(result.stdout)
        has_json = os.path.isfile(json_path) and os.path.getsize(json_path) > 0
        return {
            "tool": "cargo-audit",
            "version": _get_version(),
            "exit_code": result.returncode,
            "sarif_path": None,
            "json_path": json_path if has_json else None,
            "error_message": None if has_json else (result.stderr.strip() or "cargo-audit produced no output"),
            "success": has_json,
        }
    except subprocess.TimeoutExpired:
        return _fail(f"cargo-audit timed out after {timeout}s")
    except Exception as e:
        return _fail(str(e))


def _get_version() -> str:
    try:
        result = subprocess.run(["cargo-audit", "--version"], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "unknown"


def _skip(message: str) -> dict:
    return {
        "tool": "cargo-audit", "version": None, "exit_code": None,
        "sarif_path": None, "json_path": None,
        "error_message": message, "success": False,
    }


def _fail(message: str) -> dict:
    return {
        "tool": "cargo-audit", "version": None, "exit_code": None,
        "sarif_path": None, "json_path": None,
        "error_message": message, "success": False,
    }


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run cargo-audit Rust dependency scan")
    parser.add_argument("target")
    parser.add_argument("-o", "--output-dir", default="./results")
    parser.add_argument("-t", "--timeout", type=int, default=300)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(run_cargo_audit(args.target, args.output_dir, args.timeout), indent=2))


if __name__ == "__main__":
    main()
