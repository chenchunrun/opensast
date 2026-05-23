"""Project detection module for SAST scanning."""

import json
import os
import subprocess
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
    "python": ["semgrep", "bandit"], "javascript": ["semgrep", "eslint"],
    "typescript": ["semgrep", "eslint"], "java": ["semgrep"],
    "kotlin": ["semgrep"], "go": ["semgrep", "gosec"],
    "rust": ["semgrep"], "ruby": ["semgrep", "brakeman"],
    "php": ["semgrep"], "csharp": ["semgrep"],
    "c": ["semgrep"], "cpp": ["semgrep"],
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

    return {
        "repo_root": git_root or target_path,
        "is_git_repo": git_root is not None,
        "is_monorepo": any(c > 1 for c in manifest_counts.values()),
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
