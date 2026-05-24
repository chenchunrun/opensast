# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-23

### Added

- Multi-language SAST scanning skill for Claude Code, orchestrating Semgrep, Gitleaks, and Checkov.
- Three scan profiles: `quick` (Semgrep + Gitleaks), `standard` (Semgrep + Gitleaks + Checkov), `deep` (all tools + CodeQL).
- Support for 11 languages: JavaScript/TypeScript, Python, Java/Kotlin, Go, C#, C/C++, PHP, Ruby, Rust, Swift, and Terraform/IaC.
- Semgrep custom rules organized by language under `.claude/skills/sast-scan/rules/`.
- SARIF 2.1.0 report output, compatible with GitHub code scanning.
- Markdown and JSON report formats.
- OWASP/CWE mapping and risk scoring in report output.
- HTML report generation.
- CI integration guides for GitHub Actions and GitLab CI.
- Rule authoring guide for writing Semgrep rules.
- Docker support via `Dockerfile.sast`.
- Apache 2.0 license.

### Changed

- Overhauled the detection engine with result normalization and deduplication.
- Improved false positive reduction across all scanners.
- Upgraded to LLM-primary architecture: Claude acts as the primary analyzer with rule scanners providing raw signals.
- Added discovery targets for LLM-augmented security analysis including taint tracking and data flow analysis.
- Rewrote README with comprehensive feature documentation.
