import argparse
import json
import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)


def run_gosec(target: str, output_dir: str, timeout: int = 300, exclude_dirs: list[str] | None = None) -> dict:
    if not shutil.which("gosec"):
        return {
            "tool": "gosec", "version": None, "exit_code": None,
            "sarif_path": None, "json_path": None,
            "error_message": "gosec is not installed. Install: go install github.com/securego/gosec/v2/cmd/gosec@latest",
            "success": False,
        }

    os.makedirs(output_dir, exist_ok=True)
    version = _get_version()
    sarif_path = os.path.join(output_dir, "gosec.sarif")
    json_path = os.path.join(output_dir, "gosec.json")

    sarif_cmd = ["gosec", "-fmt=sarif", f"-out={sarif_path}", "./..."]
    json_cmd = ["gosec", "-fmt=json", f"-out={json_path}", "./..."]

    if exclude_dirs:
        dir_flag = ",".join(exclude_dirs)
        sarif_cmd.insert(2, f"-exclude-dir={dir_flag}")
        json_cmd.insert(2, f"-exclude-dir={dir_flag}")

    exit_code = None

    try:
        result = subprocess.run(sarif_cmd, capture_output=True, text=True, timeout=timeout, cwd=target)
        exit_code = result.returncode
        if result.stderr:
            logger.debug("gosec sarif stderr: %s", result.stderr[:500])

        subprocess.run(json_cmd, capture_output=True, text=True, timeout=timeout, cwd=target)

    except subprocess.TimeoutExpired:
        return {
            "tool": "gosec", "version": version, "exit_code": None,
            "sarif_path": None, "json_path": None,
            "error_message": f"gosec timed out after {timeout}s",
            "success": False,
        }
    except Exception as e:
        return {
            "tool": "gosec", "version": version, "exit_code": None,
            "sarif_path": None, "json_path": None,
            "error_message": str(e), "success": False,
        }

    has_sarif = os.path.isfile(sarif_path) and os.path.getsize(sarif_path) > 0
    has_json = os.path.isfile(json_path) and os.path.getsize(json_path) > 0

    return {
        "tool": "gosec", "version": version, "exit_code": exit_code,
        "sarif_path": sarif_path if has_sarif else None,
        "json_path": json_path if has_json else None,
        "error_message": None, "success": exit_code == 0,
    }


def _get_version() -> str:
    try:
        result = subprocess.run(["gosec", "-version"], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return result.stdout.strip().split("\n")[0]
    except Exception:
        pass
    return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run gosec Go security scan")
    parser.add_argument("target", help="Go module directory to scan")
    parser.add_argument("-o", "--output-dir", default="./results")
    parser.add_argument("-t", "--timeout", type=int, default=300)
    parser.add_argument("-e", "--exclude", action="append", help="Dirs to exclude (repeatable)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    result = run_gosec(args.target, args.output_dir, args.timeout, args.exclude)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
