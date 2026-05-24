# Contributing to OpenSAST

Thank you for your interest in contributing. This guide covers the essentials for getting started.

## Reporting Bugs

Open a [GitHub Issue](https://github.com/CCR/openSAST/issues/new) and include:

- OpenSAST version (or commit hash)
- Steps to reproduce
- Expected vs. actual behavior
- Relevant log output or SARIF snippets
- Scanner tools installed (Semgrep, Gitleaks, Checkov, etc.)

## Suggesting Features

Open a GitHub Issue with the label `enhancement`. Describe the use case and expected behavior. If you plan to implement it yourself, mention that in the issue so we can coordinate before you start.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/CCR/openSAST.git
cd openSAST

# Install dependencies
pip install -r requirements.txt

# Install at least one scanner for local testing
pip install semgrep

# Run the test suite
pytest tests/
```

## Code Style

- Follow [PEP 8](https://peps.python.org/pep-0008/) for all Python code.
- Use type hints where practical.
- Keep functions under 50 lines and files under 800 lines.
- Run `pytest tests/` before submitting any change.

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/) with one of these prefixes:

| Type | Purpose |
|------|---------|
| `feat` | New feature or scanner support |
| `fix` | Bug fix |
| `refactor` | Code restructuring without behavior change |
| `docs` | Documentation changes |
| `test` | Adding or updating tests |
| `chore` | Build, CI, or tooling changes |
| `perf` | Performance improvements |
| `ci` | CI/CD configuration |

Example: `feat: add Ruby Brakeman scanner integration`

## Pull Request Process

1. Fork the repository.
2. Create a feature branch from `main`: `git checkout -b feat/my-feature`.
3. Make your changes with clear, atomic commits.
4. Add or update tests to cover your changes.
5. Ensure all tests pass: `pytest tests/`.
6. Open a pull request against `main` with a clear description of the change and motivation.

## Adding a New Language

To add scanning support for a new programming language:

1. Create a Semgrep rules directory at `.claude/skills/sast-scan/rules/<language>/`.
2. Write Semgrep rules in YAML, one vulnerability pattern per file.
3. Map the language in `.claude/skills/sast-scan/config/default.yml` under the `languages` section.
4. Add positive test cases (vulnerable code) and negative test cases (safe code) under `tests/`.

### Rule File Example

```yaml
rules:
  - id: python-sql-injection
    patterns:
      - pattern: |
          $CURSOR.execute($QUERY % ...)
    message: "Possible SQL injection via string formatting"
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-89"
      owasp: "A03:2021-Injection"
```

## Adding a New Scanner Tool

1. Create a scanner module in `.claude/skills/sast-scan/tools/` that implements the standard scanner interface (accepts target path and config, returns normalized findings).
2. Register the scanner in the toolchain configuration.
3. Add the tool to `requirements.txt` or document the manual install step.
4. Write integration tests confirming the scanner produces expected output.
5. Update the README scanner table.

## Testing Requirements

All contributions that add or modify scanning rules or scanner integrations must include:

- **Positive test cases**: Code samples that the rule should flag.
- **Negative test cases**: Code samples that the rule should not flag (validates against false positives).
- Tests go under `tests/` and run via `pytest tests/`.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
