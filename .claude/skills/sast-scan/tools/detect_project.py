"""Project detection module for SAST scanning."""

import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

EXTENSION_MAP = {
    ".py": "python", ".js": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".jsx": "javascript", ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
    ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php", ".cs": "csharp",
    ".c": "c", ".cpp": "cpp", ".h": "c", ".hpp": "cpp", ".scala": "scala",
    ".swift": "swift", ".tf": "terraform", ".hcl": "terraform",
}

MANIFESTS = {
    "package.json", "pyproject.toml", "requirements.txt", "Pipfile", "setup.py",
    "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "Cargo.toml",
    "Gemfile", "composer.json", "CMakeLists.txt", "Makefile",
}

IAC_EXTENSIONS = {".tf", ".tfvars", ".hcl"}

EXCLUDE_DIRS = {
    "node_modules", ".git", "venv", ".venv", "__pycache__", ".tox",
    "dist", "build", ".gradle", ".idea", ".vscode", "target",
    "vendor", ".cargo", "bazel-bin", ".next", ".nuxt", "coverage",
}

FRAMEWORK_PATTERNS = {
    "express": {"express"}, "react": {"react"}, "next": {"next"},
    "vue": {"vue"}, "angular": {"@angular/core"},
    "django": {"django"}, "flask": {"flask"}, "fastapi": {"fastapi"},
    "celery": {"celery"},
    "spring": {"spring-core", "spring-boot", "org.springframework"},
    "rails": {"rails"}, "laravel": {"laravel"}, "symfony": {"symfony"},
    "gin": {"github.com/gin-gonic/gin"},
    "fiber": {"github.com/gofiber/fiber"},
    "actix": {"actix-web"}, "rocket": {"rocket"},
}

LANGUAGE_TOOLS = {
    "python": ["semgrep", "bandit"],
    "javascript": ["semgrep", "eslint"],
    "typescript": ["semgrep", "eslint"],
    "java": ["semgrep"],
    "kotlin": ["semgrep"],
    "go": ["semgrep", "gosec"],
    "rust": ["semgrep", "cargo-audit"],
    "ruby": ["semgrep", "brakeman"],
    "php": ["semgrep", "phpstan"],
    "csharp": ["semgrep"],
    "c": ["semgrep", "cppcheck"],
    "cpp": ["semgrep", "cppcheck"],
    "swift": ["semgrep", "swiftlint"],
}

MONOREPO_MANIFESTS = {
    "package.json", "pom.xml", "build.gradle", "build.gradle.kts",
    "Cargo.toml", "go.mod", "pyproject.toml",
}

NPM_MANIFESTS = {"package.json"}
TEXT_MANIFESTS = {
    "pyproject.toml", "requirements.txt", "Pipfile", "pom.xml",
    "build.gradle", "build.gradle.kts", "Gemfile", "Cargo.toml",
}
SPRING_KEYWORDS = {"spring-core", "spring-boot", "org.springframework", "spring"}

WEB_FRAMEWORKS = {
    "express", "next", "vue", "angular", "django", "flask", "fastapi",
    "spring", "rails", "laravel", "symfony", "gin", "fiber", "actix",
    "rocket", "svelte", "nuxt", "remix", "hono", "fastify", "koa",
}

CLI_FRAMEWORKS = {
    "cobra": "github.com/spf13/cobra",
    "urfave": "github.com/urfave/cli",
    "click": "click",
    "argparse": "argparse",
    "typer": "typer",
}


def _detect_archetype(
    target_path: str, languages: dict, frameworks: list[str], file_list: list[tuple[str, str]],
) -> str:
    """Detect project archetype: web-app, cli-tool, library, or serverless."""
    abs_path = os.path.abspath(target_path)

    # Check for serverless indicators
    for root, dirs, files in os.walk(abs_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in files:
            if f in ("serverless.yml", "serverless.yaml"):
                return "serverless"
            if f in ("handler.py", "handler.js", "handler.ts", "index.ts", "index.js"):
                rel = os.path.relpath(os.path.join(root, f), abs_path)
                if not rel.startswith("node_modules") and not rel.startswith("vendor"):
                    return "serverless"
        break  # only top-level

    # Check for web framework indicators
    fw_set = set(frameworks)
    if fw_set & WEB_FRAMEWORKS:
        return "web-app"

    # Check for route files (Next.js, etc.) — only in web-related directories
    has_web_routes = False
    for ext, filepath in file_list:
        basename = os.path.basename(filepath)
        if basename == "route.ts" or basename == "route.js":
            has_web_routes = True
            break
    if has_web_routes:
        return "web-app"

    # Check for main.go / cmd/ directory → CLI indicator
    has_main = os.path.isfile(os.path.join(abs_path, "main.go"))
    has_cmd = os.path.isdir(os.path.join(abs_path, "cmd"))

    # Check for main.go in subdirectories (e.g., crush-main/main.go)
    if not has_main:
        for entry in os.listdir(abs_path):
            subdir = os.path.join(abs_path, entry)
            if os.path.isdir(subdir) and os.path.isfile(os.path.join(subdir, "main.go")):
                has_main = True
                break

    # Check for HTTP handler patterns in Go
    if "go" in languages:
        # Check for CLI framework in go.mod
        go_mod_path = os.path.join(abs_path, "go.mod")
        has_cli_dep = False
        if os.path.isfile(go_mod_path):
            try:
                with open(go_mod_path, encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
                for _, dep in CLI_FRAMEWORKS.items():
                    if dep in content:
                        has_cli_dep = True
                        break
            except OSError:
                pass

        if has_cmd or has_main or has_cli_dep:
            return "cli-tool"

    # Check for CLI indicators in Python
    if "python" in languages:
        pyproject = os.path.join(abs_path, "pyproject.toml")
        if os.path.isfile(pyproject):
            try:
                with open(pyproject, encoding="utf-8", errors="ignore") as fh:
                    content = fh.read().lower()
                for cli_name in ("click", "typer", "argparse"):
                    if cli_name in content:
                        return "cli-tool"
            except OSError:
                pass

        setup_py = os.path.join(abs_path, "setup.py")
        if os.path.isfile(setup_py):
            try:
                with open(setup_py, encoding="utf-8", errors="ignore") as fh:
                    content = fh.read().lower()
                if "console_scripts" in content or "entry_points" in content:
                    return "cli-tool"
            except OSError:
                pass

    # Check for Java Spring Boot
    if "java" in languages:
        for ext, filepath in file_list:
            try:
                with open(filepath, encoding="utf-8", errors="ignore") as fh:
                    head = fh.read(2000)
                if "@SpringBootApplication" in head or "@RestController" in head:
                    return "web-app"
            except OSError:
                continue

    # Default: library
    return "library"


def _run_git(args: list[str], cwd: str) -> str | None:
    try:
        result = subprocess.run(
            ["git"] + args, cwd=cwd, capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return None


def _is_manifest_file(name: str) -> bool:
    if name in MANIFESTS:
        return True
    return any(name.endswith(m) for m in MANIFESTS if m.startswith("."))


def _looks_like_cloudformation_or_k8s(filepath: str) -> bool:
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            head = "".join(line for i, line in enumerate(fh) if i <= 30)
        lower = head.lower()
        if "awstemplateformatversion" in lower or ("resources" in lower and "aws::" in lower):
            return True
        if "apiversion" in lower and "kind" in lower:
            return True
    except OSError:
        pass
    return False


def _extract_frameworks_from_npm(filepath: str, frameworks: set) -> None:
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        deps = set()
        for section in ("dependencies", "devDependencies"):
            deps.update(data.get(section, {}).keys())
        for fw, patterns in FRAMEWORK_PATTERNS.items():
            if deps & patterns:
                frameworks.add(fw)
    except (json.JSONDecodeError, OSError):
        pass


def _extract_frameworks_from_text(filepath: str, basename: str, frameworks: set) -> None:
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            content = fh.read().lower()
    except OSError:
        return

    if basename in ("pyproject.toml", "requirements.txt", "Pipfile"):
        for fw in ("django", "flask", "fastapi", "celery"):
            if fw in content:
                frameworks.add(fw)
    elif basename in ("pom.xml", "build.gradle", "build.gradle.kts"):
        if any(kw in content for kw in SPRING_KEYWORDS):
            frameworks.add("spring")
    elif basename == "Gemfile":
        if "rails" in content:
            frameworks.add("rails")
    elif basename == "composer.json":
        if "laravel" in content:
            frameworks.add("laravel")
        if "symfony" in content:
            frameworks.add("symfony")
    elif basename == "go.mod":
        raw = content
        for fw, patterns in FRAMEWORK_PATTERNS.items():
            if any(p.lower() in raw for p in patterns):
                frameworks.add(fw)
    elif basename == "Cargo.toml":
        if "actix-web" in content:
            frameworks.add("actix")
        if "rocket" in content:
            frameworks.add("rocket")


def _walk_target(target_path: str):
    file_list: list[tuple[str, str]] = []
    manifest_paths: list[str] = []
    iac_paths: list[str] = []
    manifest_counts = {m: 0 for m in MONOREPO_MANIFESTS}

    for root, dirs, files in os.walk(target_path):
        rel_root = os.path.relpath(root, target_path)
        parts = Path(rel_root).parts if rel_root != "." else ()
        if any(part in EXCLUDE_DIRS for part in parts):
            continue
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for f in files:
            ext = os.path.splitext(f)[1].lower()
            rel_path = os.path.join(rel_root, f) if rel_root != "." else f

            if ext in EXTENSION_MAP:
                file_list.append((ext, os.path.join(root, f)))

            if _is_manifest_file(f):
                manifest_paths.append(rel_path)
                for m in MONOREPO_MANIFESTS:
                    if f == m or (m.startswith(".") and f.endswith(m)):
                        manifest_counts[m] += 1

            if ext in IAC_EXTENSIONS:
                iac_paths.append(rel_path)
            elif f.endswith((".yaml", ".yml")):
                if _looks_like_cloudformation_or_k8s(os.path.join(root, f)):
                    iac_paths.append(rel_path)

    return file_list, manifest_paths, iac_paths, manifest_counts


def _detect_frameworks(target_path: str, manifest_paths: list[str]) -> list[str]:
    frameworks: set[str] = set()
    for rel_path in manifest_paths:
        full_path = os.path.join(target_path, rel_path.lstrip("./"))
        if not os.path.isfile(full_path):
            continue
        basename = os.path.basename(rel_path)
        if basename in NPM_MANIFESTS:
            _extract_frameworks_from_npm(full_path, frameworks)
        elif basename in TEXT_MANIFESTS or basename == "composer.json":
            _extract_frameworks_from_text(full_path, basename, frameworks)
    return sorted(frameworks)


def _compute_languages(file_list: list[tuple[str, str]]) -> dict[str, int]:
    counter = Counter(EXTENSION_MAP.get(ext) for ext, _ in file_list)
    counter.pop(None, None)
    total = sum(counter.values())
    if total == 0:
        return {}
    return {lang: round(count / total * 100) for lang, count in counter.most_common()}


def _recommend_tools(languages: dict, has_iac: bool) -> list[str]:
    tools = ["gitleaks"]
    seen: set[str] = set()
    for lang in languages:
        for tool in LANGUAGE_TOOLS.get(lang, []):
            if tool not in seen:
                tools.append(tool)
                seen.add(tool)
    if has_iac:
        tools.append("checkov")
    return tools


def _detect_scan_targets(target_path: str) -> list[str]:
    candidates = {"src", "app", "lib", "pkg", "cmd", "internal", "api", "web"}
    found = [e for e in os.listdir(target_path)
             if os.path.isdir(os.path.join(target_path, e)) and e in candidates]
    return sorted(found) if found else ["."]


def detect_project(target_path: str) -> dict:
    target_path = os.path.abspath(target_path)
    if not os.path.isdir(target_path):
        raise ValueError(f"Target path is not a directory: {target_path}")

    git_root = _run_git(["rev-parse", "--show-toplevel"], target_path)
    file_list, manifest_paths, iac_paths, manifest_counts = _walk_target(target_path)
    languages = _compute_languages(file_list)
    frameworks = _detect_frameworks(target_path, manifest_paths)
    has_iac = len(iac_paths) > 0

    archetype = _detect_archetype(target_path, languages, frameworks, file_list)

    return {
        "repo_root": git_root or target_path,
        "is_git_repo": git_root is not None,
        "is_monorepo": any(c > 1 for c in manifest_counts.values()),
        "archetype": archetype,
        "languages": languages,
        "manifests": sorted(manifest_paths),
        "frameworks": frameworks,
        "iac_files": sorted(iac_paths),
        "recommended_tools": _recommend_tools(languages, has_iac),
        "scan_targets": _detect_scan_targets(target_path),
        "exclude_dirs": sorted(EXCLUDE_DIRS),
    }


def main() -> None:
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path>", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(detect_project(sys.argv[1]), indent=2))


if __name__ == "__main__":
    main()
