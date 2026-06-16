#!/usr/bin/env bash
# Verify optional SAST toolchain dependencies for OpenSAST.
set -euo pipefail

ok=0
warn=0

check() {
  local name="$1"
  local cmd="$2"
  local install_hint="$3"
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "  OK   $name ($("$cmd" --version 2>/dev/null | head -1 || echo present))"
    ok=$((ok + 1))
  else
    echo "  SKIP $name — $install_hint"
    warn=$((warn + 1))
  fi
}

echo "OpenSAST toolchain check"
echo "========================"

check "Python" python3 "install Python 3.11+"
check "Semgrep" semgrep "pip install semgrep  (or: pip install pysemgrep)"
check "Gitleaks" gitleaks "https://github.com/gitleaks/gitleaks#installing"
check "Checkov" checkov "pip install checkov"
check "Bandit" bandit "pip install bandit"
check "gosec" gosec "go install github.com/securego/gosec/v2/cmd/gosec@latest"
check "ESLint" eslint "npm install -g eslint eslint-plugin-security"
check "Brakeman" brakeman "gem install brakeman"
check "cppcheck" cppcheck "brew install cppcheck"
check "cargo-audit" cargo-audit "cargo install cargo-audit"
check "SwiftLint" swiftlint "brew install swiftlint"
check "PHPStan" phpstan "composer require --dev phpstan/phpstan (project-local)"

echo ""
echo "Required for rule-layer CI: Semgrep (+ Gitleaks recommended)."
echo "LLM/Agent analysis runs in Claude Code Skill sessions, not via this script."
echo "Summary: $ok tools found, $warn optional tools missing."
