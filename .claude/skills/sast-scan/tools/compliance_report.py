#!/usr/bin/env python3
"""Generate compliance coverage reports from SAST findings.

Maps findings to compliance framework controls via CWE tags, producing
a per-control pass/fail/attention matrix showing framework coverage.

Supports: SOC 2, PCI-DSS, HIPAA, ISO 27001:2022, NIST 800-53, GB/T 35273.

Usage:
    python3 compliance_report.py --findings .claude/sast/results/findings.json
    python3 compliance_report.py --findings findings.json --framework soc2 --output md
    python3 compliance_report.py --findings findings.json --format json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from typing import Any

# Framework → control → metadata
# Each control lists expected CWE tags that would indicate coverage
COMPLIANCE_FRAMEWORKS: dict[str, dict[str, dict[str, Any]]] = {
    "soc2": {
        "CC6.1 — Access Control": {
            "description": "Logical and physical access controls",
            "cwe": {306, 862, 863, 22},
            "rules": ["soc2.access-control-missing-auth", "soc2.admin-function-no-role-check"],
        },
        "CC6.6 — External Access": {
            "description": "Access from external parties requires authentication",
            "cwe": {306, 287},
            "rules": ["soc2.access-control-missing-auth"],
        },
        "CC7.1 — Vulnerability Detection": {
            "description": "Detect and remediate vulnerabilities in infrastructure and application",
            "cwe": {1104, 937},
            "rules": ["soc2.dependency-no-pinning", "soc2.no-vulnerability-scanning"],
        },
        "CC7.2 — Security Monitoring": {
            "description": "Monitor for anomalous activity, generate audit logs for security events",
            "cwe": {778, 532},
            "rules": ["soc2.logging-not-configured", "soc2.logging-missing-security-events"],
        },
    },
    "pci-dss": {
        "3.4 — Render PAN Unreadable": {
            "description": "Do not log full PAN or sensitive cardholder data",
            "cwe": {532},
            "rules": ["pci-dss.logging-card-data"],
        },
        "4.2.1 — Strong Cryptography in Transit": {
            "description": "Use TLS for all transmission of sensitive cardholder data",
            "cwe": {319},
            "rules": ["pci-dss.http-transmission-sensitive"],
        },
        "6.5.1 — Injection Flaws": {
            "description": "Protect against SQL injection, OS command injection, etc.",
            "cwe": {89, 78, 94, 90, 643},
            "rules": ["pci-dss.sql-string-concatenation"],
        },
        "6.5.2 — Default Credentials": {
            "description": "No hardcoded or default passwords, unique per-environment credentials",
            "cwe": {798},
            "rules": ["pci-dss.default-credentials"],
        },
    },
    "hipaa": {
        "164.312(a)(1) — Access Control": {
            "description": "Implement unique user identification and emergency access procedures",
            "cwe": {306, 862, 22},
            "rules": ["hipaa.access-no-user-audit"],
        },
        "164.312(a)(2)(iv) — Encryption at Rest": {
            "description": "Encrypt and decrypt electronic PHI with adequate encryption",
            "cwe": {326, 327},
            "rules": ["hipaa.encryption-weak-algorithm"],
        },
        "164.312(b) — Audit Controls": {
            "description": "Implement audit controls for systems containing or accessing PHI",
            "cwe": {778, 532},
            "rules": ["hipaa.audit-phi-access-no-log"],
        },
        "164.312(d) — Session Termination": {
            "description": "Implement automatic logoff after a period of inactivity",
            "cwe": {613},
            "rules": ["hipaa.session-no-timeout"],
        },
        "164.312(e)(1) — Transmission Security": {
            "description": "Implement security measures for data transmitted over networks",
            "cwe": {319},
            "rules": ["hipaa.transmission-no-tls"],
        },
    },
    "iso27001": {
        "A.8.3 — Information Access Restriction": {
            "description": "Access to information is restricted per policy",
            "cwe": {942, 862},
            "rules": ["iso27001.a8-3-open-cors"],
        },
        "A.8.8 — Vulnerability Management": {
            "description": "Detect and remediate technical vulnerabilities",
            "cwe": {1104, 937},
            "rules": ["iso27001.a8-8-vulnerable-dependency"],
        },
        "A.8.9 — Configuration Management": {
            "description": "Secure configuration baselines enforced",
            "cwe": {215},
            "rules": ["iso27001.a8-9-production-debug"],
        },
        "A.8.12 — Data Leakage Prevention": {
            "description": "Prevent data leakage through code, logs, or error messages",
            "cwe": {798, 532, 209},
            "rules": ["iso27001.a8-12-hardcoded-secrets"],
        },
        "A.8.26 — Application Security": {
            "description": "Input validation and secure coding enforced in application requirements",
            "cwe": {20, 89, 78, 79},
            "rules": ["iso27001.a8-26-missing-input-validation"],
        },
    },
    "nist800-53": {
        "AC-3 — Access Enforcement": {
            "description": "Enforce approved authorizations for logical access",
            "cwe": {862, 306},
            "rules": ["nist800-53.ac3-access-enforcement"],
        },
        "AC-7 — Unsuccessful Login Attempts": {
            "description": "Enforce limit of consecutive invalid login attempts",
            "cwe": {307},
            "rules": ["nist800-53.ac7-no-rate-limiting"],
        },
        "AU-2 — Audit Events": {
            "description": "System capable of generating audit records for defined events",
            "cwe": {778, 532},
            "rules": ["nist800-53.au2-no-audit-log"],
        },
        "CM-6 — Configuration Settings": {
            "description": "Mandatory configuration settings for products",
            "cwe": {215, 937},
            "rules": ["nist800-53.cm6-debug-config"],
        },
        "IA-5 — Authenticator Management": {
            "description": "Manage system authenticators (passwords, tokens, PKI certs)",
            "cwe": {798},
            "rules": ["nist800-53.ia5-hardcoded-authenticator"],
        },
        "SC-8 — Transmission Confidentiality": {
            "description": "Protect confidentiality and integrity of transmitted information",
            "cwe": {319},
            "rules": ["nist800-53.sc8-no-tls"],
        },
        "SC-13 — Cryptographic Protection": {
            "description": "Use FIPS-validated cryptographic modules",
            "cwe": {326, 327, 328},
            "rules": ["nist800-53.sc13-weak-crypto"],
        },
        "SI-4 — System Monitoring": {
            "description": "Monitor system events and detect attacks",
            "cwe": {778},
            "rules": ["nist800-53.si4-no-monitoring"],
        },
    },
    "gbt35273": {
        "5.4 — Storage Encryption": {
            "description": "Personal data stored in encrypted form",
            "cwe": {312},
            "rules": ["gbt35273.personal-data-plaintext-storage"],
        },
        "5.5 — Transmission Security": {
            "description": "Personal data transmitted over secure channels",
            "cwe": {319},
            "rules": ["gbt35273.personal-data-unencrypted-transit"],
        },
        "10.1 — Logging Restrictions": {
            "description": "Personal data not written to log files",
            "cwe": {532},
            "rules": ["gbt35273.logging-personal-data"],
        },
    },
}

FRAMEWORK_ORDER = ["soc2", "pci-dss", "hipaa", "iso27001", "nist800-53", "gbt35273"]
FRAMEWORK_NAMES = {
    "soc2": "SOC 2 (AICPA TSC 2017)",
    "pci-dss": "PCI-DSS 4.0",
    "hipaa": "HIPAA Security Rule",
    "iso27001": "ISO 27001:2022 Annex A",
    "nist800-53": "NIST SP 800-53 Rev 5",
    "gbt35273": "GB/T 35273-2020",
}


def _extract_cwes(findings: list[dict]) -> set[int]:
    """Extract all unique CWE IDs from findings."""
    cwes: set[int] = set()
    for f in findings:
        for raw in f.get("cwe", []) or []:
            # Handle both "CWE-89" and just 89 formats
            s = str(raw).replace("CWE-", "").replace("cwe-", "").strip()
            try:
                cwes.add(int(s))
            except (ValueError, TypeError):
                pass
    return cwes


def _count_rule_hits(findings: list[dict], rule_ids: list[str]) -> int:
    """Count the distinct findings triggered by given rule IDs."""
    seen = set()
    for f in findings:
        rid = f.get("rule_id", "")
        for r in rule_ids:
            if r in rid:
                seen.add(rid)
    return len(seen)


def build_compliance_report(findings: list[dict],
                            framework_filter: str | None = None) -> dict:
    """Build compliance coverage report across all (or one) frameworks.

    Returns:
        dict: per-framework results with control-by-control pass/fail/attention.
    """
    cwes = _extract_cwes(findings)
    frameworks = (
        {framework_filter: COMPLIANCE_FRAMEWORKS[framework_filter]}
        if framework_filter and framework_filter in COMPLIANCE_FRAMEWORKS
        else COMPLIANCE_FRAMEWORKS
    )

    results: dict[str, Any] = {
        "total_findings": len(findings),
        "cwes_detected": sorted(cwes),
        "frameworks": {},
        "overall": {},
    }

    for fw_key in FRAMEWORK_ORDER:
        if fw_key not in frameworks:
            continue
        fw = frameworks[fw_key]
        controls = {}
        fw_pass = 0
        fw_attention = 0
        fw_gap = 0

        for control_name, meta in fw.items():
            expected_cwes = meta.get("cwe", set())
            rule_ids = meta.get("rules", [])
            detected = cwes & expected_cwes
            rule_hits = _count_rule_hits(findings, rule_ids)

            if detected or rule_hits > 0:
                # Has findings that map to this control
                if rule_hits > 0:
                    status = "attention"  # Rule triggered — needs triage
                    fw_attention += 1
                else:
                    status = "pass"  # CWE tags present but no direct rule hit
                    fw_pass += 1
            else:
                status = "gap"  # No relevant findings/coverage
                fw_gap += 1

            controls[control_name] = {
                "status": status,
                "description": meta.get("description", ""),
                "expected_cwes": sorted(expected_cwes),
                "detected_cwes": sorted(detected),
                "rule_hits": rule_hits,
            }

        total = fw_pass + fw_attention + fw_gap
        results["frameworks"][fw_key] = {
            "name": FRAMEWORK_NAMES.get(fw_key, fw_key),
            "controls": controls,
            "pass": fw_pass,
            "attention": fw_attention,
            "gap": fw_gap,
            "total": total,
            "coverage_pct": round((fw_pass + fw_attention) / max(total, 1) * 100, 1),
        }

    # Overall
    all_pass = sum(f["pass"] for f in results["frameworks"].values())
    all_attention = sum(f["attention"] for f in results["frameworks"].values())
    all_gap = sum(f["gap"] for f in results["frameworks"].values())
    results["overall"] = {
        "pass": all_pass,
        "attention": all_attention,
        "gap": all_gap,
        "total": all_pass + all_attention + all_gap,
    }

    return results


STATUS_ICONS = {"pass": "✅", "attention": "⚠️", "gap": "❌"}


def format_compliance_markdown(report: dict) -> str:
    """Format compliance report as Markdown."""
    lines = [
        "# Compliance Coverage Report",
        "",
        f"Findings analyzed: **{report['total_findings']}**",
        f"CWEs detected: {', '.join(f'`CWE-{c}`' for c in report['cwes_detected'][:15])}"
        f"{'...' if len(report['cwes_detected']) > 15 else ''}",
        "",
        "## Summary",
        "",
        "| Framework | Controls | ✅ Pass | ⚠️ Attention | ❌ Gap | Coverage |",
        "|-----------|:--------:|:-------:|:------------:|:------:|:--------:|",
    ]

    for fw_key in FRAMEWORK_ORDER:
        if fw_key not in report["frameworks"]:
            continue
        fw = report["frameworks"][fw_key]
        lines.append(
            f"| {fw['name']} | {fw['total']} | {fw['pass']} | {fw['attention']} "
            f"| {fw['gap']} | {fw['coverage_pct']}% |"
        )

    total = report["overall"]
    lines.append(
        f"| **Total** | **{total['total']}** | **{total['pass']}** "
        f"| **{total['attention']}** | **{total['gap']}** | — |"
    )
    lines.append("")

    # Per-framework detail
    for fw_key in FRAMEWORK_ORDER:
        if fw_key not in report["frameworks"]:
            continue
        fw = report["frameworks"][fw_key]
        lines += [
            f"## {fw['name']}",
            "",
            f"Coverage: {fw['coverage_pct']}% ({fw['pass'] + fw['attention']}/{fw['total']} controls)",
            "",
            "| Control | Status | Description | CWEs Detected |",
            "|---------|--------|-------------|--------------|",
        ]
        for name, ctrl in fw["controls"].items():
            icon = STATUS_ICONS[ctrl["status"]]
            detected = ", ".join(f"`CWE-{c}`" for c in ctrl["detected_cwes"]) or "—"
            lines.append(
                f"| {name} | {icon} {ctrl['status']} | {ctrl['description']} | {detected} |"
            )
        lines.append("")

    lines += [
        "---",
        "",
        "**Legend:** ✅ = findings detected, no rule violations mapped to this control | "
        "⚠️ = rule violations detected, needs triage | ❌ = no coverage for this control",
        "",
        "**Remediation priority:** Address ⚠️ items first (active findings), "
        "then fill ❌ gaps (add missing rules or enable additional scanners).",
        "",
        f"*Generated by OpenSAST compliance_report.py*",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", required=True,
                        help="Path to findings.json from a SAST scan")
    parser.add_argument("--framework", choices=list(COMPLIANCE_FRAMEWORKS),
                        help="Limit report to a single framework")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown",
                        help="Output format (default: markdown)")
    parser.add_argument("--output", "-o",
                        help="Write report to file instead of stdout")
    args = parser.parse_args(argv)

    if not os.path.isfile(args.findings):
        print(f"Findings file not found: {args.findings}", file=sys.stderr)
        return 1

    with open(args.findings, encoding="utf-8") as f:
        data = json.load(f)
    findings = data.get("findings", data) if isinstance(data, dict) else data

    report = build_compliance_report(findings, args.framework)

    if args.format == "json":
        output = json.dumps(report, indent=2, ensure_ascii=False)
    else:
        output = format_compliance_markdown(report)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Compliance report written to {args.output}")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
