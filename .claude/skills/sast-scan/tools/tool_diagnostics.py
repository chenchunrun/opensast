"""Normalize scanner skip/failure outcomes with copy-paste fix hints."""

from __future__ import annotations

TOOL_INSTALL_HINTS: dict[str, str] = {
    "semgrep": "pip install semgrep",
    "gitleaks": "brew install gitleaks  # or: https://github.com/gitleaks/gitleaks#installing",
    "checkov": "pip install checkov",
    "codeql": "https://github.com/github/codeql-cli-binaries/releases",
    "bandit": "pip install bandit",
    "gosec": "go install github.com/securego/gosec/v2/cmd/gosec@latest",
    "eslint": "npm install -g eslint eslint-plugin-security",
    "brakeman": "gem install brakeman",
    "cppcheck": "brew install cppcheck  # or: apt install cppcheck",
    "cargo-audit": "cargo install cargo-audit",
    "swiftlint": "brew install swiftlint",
    "phpstan": "composer require --dev phpstan/phpstan",
}

_SKIP_MARKERS = (
    "skip",
    "not installed",
    "no package.json",
    "no cargo.toml",
    "vendor/bin/phpstan",
    "not found",
    "requires",
    "staged subset",
    "does not preserve",
)


def classify_outcome_status(reason: str) -> str:
    lower = reason.lower()
    if any(marker in lower for marker in _SKIP_MARKERS):
        return "skipped"
    return "failed"


def fix_command_for_tool(tool: str, reason: str) -> str | None:
    lower = reason.lower()
    if "staged subset" in lower or "changed-only" in lower:
        return "Run a full-repo scan without --changed-only for complete supplemental tool coverage"
    return TOOL_INSTALL_HINTS.get(tool)


def normalize_tool_outcome(result: dict) -> dict | None:
    if result.get("success"):
        return None
    tool = str(result.get("tool", "unknown"))
    reason = str(result.get("error_message") or "unknown error")
    status = classify_outcome_status(reason)
    fix_command = fix_command_for_tool(tool, reason)
    return {
        "tool": tool,
        "status": status,
        "reason": reason,
        "error": reason,
        "fix_command": fix_command,
    }


def collect_tool_outcomes(scan_results: list[dict]) -> list[dict]:
    outcomes: list[dict] = []
    for result in scan_results:
        outcome = normalize_tool_outcome(result)
        if outcome:
            outcomes.append(outcome)
    return outcomes
