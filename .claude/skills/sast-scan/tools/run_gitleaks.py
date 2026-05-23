import argparse
import json
import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)


def run_gitleaks(target: str, output_dir: str, timeout: int = 120, no_git: bool = False) -> dict:
    if not shutil.which("gitleaks"):
        return {"tool": "gitleaks", "version": None, "exit_code": None, "sarif_path": None, "json_path": None, "error_message": "gitleaks is not installed", "success": False}

    os.makedirs(output_dir, exist_ok=True)

    version = "unknown"
    try:
        ver_result = subprocess.run(["gitleaks", "version"], capture_output=True, text=True, timeout=30)
        if ver_result.returncode == 0:
            version = ver_result.stdout.strip()
    except (subprocess.TimeoutExpired, Exception) as e:
        logger.warning("Failed to get gitleaks version: %s", e)

    sarif_path = os.path.join(output_dir, "gitleaks.sarif")

    cmd = ["gitleaks", "detect", "--source", target, "--report-format", "sarif", "--report-path", sarif_path]

    is_git_repo = os.path.isdir(os.path.join(target, ".git"))
    if no_git or not is_git_repo:
        cmd.append("--no-git")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        stdout, stderr, exit_code = result.stdout, result.stderr, result.returncode

        if stdout:
            logger.info("gitleaks stdout: %s", stdout)
        if stderr:
            logger.error("gitleaks stderr: %s", stderr)

        sarif_exists = os.path.isfile(sarif_path)

        return {"tool": "gitleaks", "version": version, "exit_code": exit_code, "sarif_path": sarif_path if sarif_exists else None, "json_path": None, "error_message": stderr.strip() if stderr and exit_code not in (0, 1) else None, "success": sarif_exists and exit_code in (0, 1)}

    except subprocess.TimeoutExpired:
        return {"tool": "gitleaks", "version": version, "exit_code": None, "sarif_path": None, "json_path": None, "error_message": f"gitleaks timed out after {timeout}s", "success": False}
    except Exception as e:
        return {"tool": "gitleaks", "version": version, "exit_code": None, "sarif_path": None, "json_path": None, "error_message": str(e), "success": False}


def main():
    parser = argparse.ArgumentParser(description="Run Gitleaks secret detection scan")
    parser.add_argument("target", help="Target directory to scan")
    parser.add_argument("-o", "--output-dir", default="./results", help="Output directory (default: ./results)")
    parser.add_argument("-t", "--timeout", type=int, default=120, help="Scan timeout in seconds (default: 120)")
    parser.add_argument("--no-git", action="store_true", help="Run in no-git mode")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    result = run_gitleaks(args.target, args.output_dir, args.timeout, args.no_git)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
