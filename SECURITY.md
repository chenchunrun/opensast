# Security Policy

## Supported Versions

OpenSAST is in early development. The following versions receive security updates:

| Version | Supported |
|---------|-----------|
| 0.1.x | Yes |
| < 0.1.0 | No |

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

Instead, report them using one of these methods:

- **GitHub Security Advisory**: Use the [Security Advisories](https://github.com/CCR/openSAST/security/advisories/new) page to privately report a vulnerability.
- **Email**: Send a report to security@example.com with the subject line starting with `[OpenSAST Security]`.

### What to Include in a Report

Provide as much of the following as possible:

- Description of the vulnerability and its potential impact.
- Steps to reproduce, including any proof-of-concept code or commands.
- Affected OpenSAST version or commit hash.
- The scanner tools and configuration in use.
- Any relevant log output or SARIF files.
- Suggested fix, if you have one.

## Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | Within 48 hours |
| Initial triage | Within 7 days |
| Status updates | Every 7 days until resolved |
| Fix release | Depends on severity and complexity |

We will keep you informed throughout the process and credit you in the advisory unless you request otherwise.

## Safe Harbor

We support responsible disclosure. If you act in good faith to identify and report a vulnerability:

- We will not pursue legal action against you.
- We ask that you avoid accessing or modifying user data, degrading services, or causing harm.
- We ask that you give us a reasonable time to address the issue before any public disclosure.

## Scope

This policy applies to the OpenSAST codebase itself. Vulnerabilities in third-party scanner tools (Semgrep, Gitleaks, Checkov, CodeQL, etc.) should be reported to their respective maintainers.

## Out of Scope

- Vulnerabilities in dependencies that are already patched in the latest version.
- Issues that require unlikely user interaction or non-default configurations.
- Theoretical vulnerabilities without a practical attack scenario.

## Contact

For non-security questions or general discussion, use [GitHub Issues](https://github.com/CCR/openSAST/issues).
