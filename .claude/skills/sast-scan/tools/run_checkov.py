import argparse
import json
import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)

IAC_EXTENSIONS = {".tf", ".tfvars", ".yaml", ".yml", ".json", ".template", ".dockerfile", ".containerfile"}
IAC_FILENAMES = {"Dockerfile", "Containerfile", "docker-compose.yml", "docker-compose.yaml", "cloudformation.yaml", "cloudformation.yml"}


def _has_iac_files(target: str) -> bool:
    for root, _, files in os.walk(target):
        for fname in files:
            if fname in IAC_FILENAMES:
                return True
            _, ext = os.path.splitext(fname)
            if ext.lower() in IAC_EXTENSIONS:
                return True
    return False


def run_checkov(target: str, output_dir: str, timeout: int = 300, frameworks: list[str] | None = None) -> dict:
    if not shutil.which("checkov"):
        return {"tool": "checkov", "version": None, "exit_code": None, "sarif_path": None, "json_path": None, "error_message": "checkov is not installed", "success": False}

    if not _has_iac_files(target):
        return {"tool": "checkov", "version": None, "exit_code": None, "sarif_path": None, "json_path": None, "error_message": "No IaC files detected in target", "success": False}

    os.makedirs(output_dir, exist_ok=True)

    version = "unknown"
    try:
        ver_result = subprocess.run(["checkov", "--version"], capture_output=True, text=True, timeout=30)
        if ver_result.returncode == 0:
            version = ver_result.stdout.strip().split("\n")[0]
    except (subprocess.TimeoutExpired, Exception) as e:
        logger.warning("Failed to get checkov version: %s", e)

    cmd = ["checkov", "-d", target, "--output", "sarif", "--output", "cli", "--output-file-path", output_dir, "--compact"]

    if frameworks:
        cmd.extend(["--framework", ",".join(frameworks)])

    sarif_path = os.path.join(output_dir, "results.sarif")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        stdout, stderr, exit_code = result.stdout, result.stderr, result.returncode

        if stdout:
            logger.info("checkov output: %s", stdout[-2000:] if len(stdout) > 2000 else stdout)
        if stderr:
            logger.error("checkov stderr: %s", stderr)

        sarif_exists = os.path.isfile(sarif_path)

        return {"tool": "checkov", "version": version, "exit_code": exit_code, "sarif_path": sarif_path if sarif_exists else None, "json_path": None, "error_message": stderr.strip() if stderr and exit_code not in (0, 1) else None, "success": sarif_exists}

    except subprocess.TimeoutExpired:
        return {"tool": "checkov", "version": version, "exit_code": None, "sarif_path": None, "json_path": None, "error_message": f"checkov timed out after {timeout}s", "success": False}
    except Exception as e:
        return {"tool": "checkov", "version": version, "exit_code": None, "sarif_path": None, "json_path": None, "error_message": str(e), "success": False}


def main():
    parser = argparse.ArgumentParser(description="Run Checkov IaC scan")
    parser.add_argument("target", help="Target directory to scan")
    parser.add_argument("-o", "--output-dir", default="./results", help="Output directory (default: ./results)")
    parser.add_argument("-t", "--timeout", type=int, default=300, help="Scan timeout in seconds (default: 300)")
    parser.add_argument("-f", "--framework", action="append", help="Framework to scan (repeatable): terraform, cloudformation, kubernetes, dockerfile, all")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    result = run_checkov(args.target, args.output_dir, args.timeout, args.framework)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
