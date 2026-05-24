"""Compliance framework mappings and report generation.

Maps findings to compliance standards:
- GB/T 35273-2020 (个人信息安全规范)
- PCI DSS v4.0
- CWE Top 25 (2024)
- OWASP Top 10 (2021)
- ISO 27001 Annex A
"""

from collections import defaultdict

# ── GB/T 35273-2020 Personal Information Security Specification ──

GBT35273_MAPPING: dict[str, dict] = {
    "5.1 收集个人信息的最小必要": {
        "title": "Minimum necessity of personal information collection",
        "cwes": ["CWE-20", "CWE-200"],
        "description": "Only collect minimum necessary personal information",
    },
    "5.2 收集个人信息时的同意": {
        "title": "Consent for personal information collection",
        "cwes": ["CWE-284"],
        "description": "Obtain explicit consent before collecting personal data",
    },
    "5.4 个人信息存储": {
        "title": "Personal information storage",
        "cwes": ["CWE-312", "CWE-327", "CWE-798"],
        "description": "Encrypt personal data at rest and protect storage",
    },
    "5.5 个人信息安全传输": {
        "title": "Secure transmission of personal information",
        "cwes": ["CWE-295", "CWE-319", "CWE-327"],
        "description": "Encrypt personal data in transit using TLS",
    },
    "5.7 个人信息访问控制": {
        "title": "Access control for personal information",
        "cwes": ["CWE-284", "CWE-862", "CWE-639"],
        "description": "Implement access controls and authorization",
    },
    "6.1 个人信息共享转移": {
        "title": "Personal information sharing and transfer",
        "cwes": ["CWE-200", "CWE-352"],
        "description": "Protect data during sharing/transfer with third parties",
    },
    "6.3 个人信息公开披露": {
        "title": "Public disclosure of personal information",
        "cwes": ["CWE-200", "CWE-532"],
        "description": "Prevent unauthorized public disclosure",
    },
    "7.1 个人信息主体权利": {
        "title": "Data subject rights",
        "cwes": ["CWE-284"],
        "description": "Allow data subjects to access, correct, delete their data",
    },
    "8.1 安全事件应急响应": {
        "title": "Security incident response",
        "cwes": ["CWE-532", "CWE-778"],
        "description": "Implement incident response for data breaches",
    },
    "9.1 数据出境安全": {
        "title": "Cross-border data transfer security",
        "cwes": ["CWE-295", "CWE-319"],
        "description": "Ensure security for cross-border personal data transfers",
    },
    "10.1 个人信息安全审计": {
        "title": "Personal information security audit",
        "cwes": ["CWE-778", "CWE-532"],
        "description": "Maintain audit logs for personal data access",
    },
}

# ── PCI DSS v4.0 Requirements ──

PCI_DSS_MAPPING: dict[str, dict] = {
    "Requirement 1: Network Security": {
        "title": "Install and maintain network security controls",
        "cwes": ["CWE-284", "CWE-668"],
        "description": "Protect cardholder data with firewalls and network segmentation",
    },
    "Requirement 2: Secure Configurations": {
        "title": "Apply secure configurations to all system components",
        "cwes": ["CWE-16", "CWE-215", "CWE-276"],
        "description": "Never use vendor-supplied defaults; harden all systems",
    },
    "Requirement 3: Protect Stored Account Data": {
        "title": "Protect stored account data",
        "cwes": ["CWE-312", "CWE-327", "CWE-798"],
        "description": "Encrypt PAN at rest; never store CVV/CVC",
    },
    "Requirement 4: Encrypt Transmission": {
        "title": "Protect cardholder data with strong cryptography in transit",
        "cwes": ["CWE-295", "CWE-319", "CWE-327"],
        "description": "Use TLS 1.2+ for all data transmission",
    },
    "Requirement 5: Malware Protection": {
        "title": "Protect against malicious software",
        "cwes": ["CWE-94", "CWE-502"],
        "description": "Deploy antivirus; prevent execution of unauthorized code",
    },
    "Requirement 6: Secure Systems and Software": {
        "title": "Develop and maintain secure systems and software",
        "cwes": ["CWE-89", "CWE-79", "CWE-78", "CWE-434", "CWE-1104"],
        "description": "Apply secure coding practices; fix vulnerabilities",
    },
    "Requirement 7: Need-to-Know Access": {
        "title": "Restrict access to need-to-know basis",
        "cwes": ["CWE-284", "CWE-862", "CWE-639"],
        "description": "Limit access to minimum necessary for job function",
    },
    "Requirement 8: User Identity": {
        "title": "Identify users and authenticate access",
        "cwes": ["CWE-287", "CWE-798", "CWE-384", "CWE-613"],
        "description": "Implement strong authentication; MFA for admin access",
    },
    "Requirement 9: Physical Access": {
        "title": "Restrict physical access to cardholder data",
        "cwes": ["CWE-284"],
        "description": "Control physical access to systems",
    },
    "Requirement 10: Log and Monitor": {
        "title": "Log and monitor all access to system components",
        "cwes": ["CWE-778", "CWE-532", "CWE-117"],
        "description": "Implement logging; review logs regularly",
    },
    "Requirement 11: Test Security Regularly": {
        "title": "Test security of systems and networks regularly",
        "cwes": ["CWE-1104"],
        "description": "Run vulnerability scans and penetration tests",
    },
    "Requirement 12: Security Policy": {
        "title": "Support information security with organizational policies",
        "cwes": ["CWE-284"],
        "description": "Maintain security policies and training programs",
    },
}

# ── ISO 27001:2022 Annex A Controls (Security-relevant subset) ──

ISO27001_MAPPING: dict[str, dict] = {
    "A.5.14 Information Transfer": {
        "title": "Secure information transfer",
        "cwes": ["CWE-295", "CWE-319"],
    },
    "A.5.15 Access Control": {
        "title": "Access control",
        "cwes": ["CWE-284", "CWE-862"],
    },
    "A.5.33 Protection of Records": {
        "title": "Protection of records",
        "cwes": ["CWE-532", "CWE-778"],
    },
    "A.8.1 User Endpoint Devices": {
        "title": "User endpoint security",
        "cwes": ["CWE-312", "CWE-798"],
    },
    "A.8.2 Privileged Access Rights": {
        "title": "Privileged access management",
        "cwes": ["CWE-284", "CWE-798"],
    },
    "A.8.5 Secure Authentication": {
        "title": "Secure authentication",
        "cwes": ["CWE-287", "CWE-384", "CWE-613"],
    },
    "A.8.8 Management of Technical Vulnerabilities": {
        "title": "Technical vulnerability management",
        "cwes": ["CWE-89", "CWE-79", "CWE-78", "CWE-94"],
    },
    "A.8.9 Configuration Management": {
        "title": "Secure configuration management",
        "cwes": ["CWE-16", "CWE-215", "CWE-276"],
    },
    "A.8.10 Information Deletion": {
        "title": "Secure information deletion",
        "cwes": ["CWE-312"],
    },
    "A.8.11 Data Masking": {
        "title": "Data masking",
        "cwes": ["CWE-200"],
    },
    "A.8.12 Data Leakage Prevention": {
        "title": "Data leakage prevention",
        "cwes": ["CWE-200", "CWE-532"],
    },
    "A.8.16 Monitoring Activities": {
        "title": "Monitoring activities",
        "cwes": ["CWE-778", "CWE-532", "CWE-117"],
    },
    "A.8.20 Networks": {
        "title": "Network security",
        "cwes": ["CWE-295", "CWE-918"],
    },
    "A.8.24 Cryptography": {
        "title": "Use of cryptography",
        "cwes": ["CWE-327", "CWE-328", "CWE-338"],
    },
    "A.8.25 Secure Development Lifecycle": {
        "title": "Secure development lifecycle",
        "cwes": ["CWE-89", "CWE-79", "CWE-78", "CWE-20"],
    },
    "A.8.26 Application Security Requirements": {
        "title": "Application security requirements",
        "cwes": ["CWE-20", "CWE-284"],
    },
    "A.8.28 Secure Coding": {
        "title": "Secure coding",
        "cwes": ["CWE-89", "CWE-78", "CWE-79", "CWE-94", "CWE-502"],
    },
    "A.8.29 Security Testing": {
        "title": "Security testing in development",
        "cwes": ["CWE-20", "CWE-284"],
    },
    "A.8.30 Outsourced Development": {
        "title": "Outsourced development security",
        "cwes": ["CWE-1104"],
    },
}


def _extract_cwe_set(findings: list[dict]) -> set[str]:
    """Extract all CWE IDs from findings."""
    cwes = set()
    for f in findings:
        for cwe in f.get("cwe", []):
            code = cwe.split(":")[0].strip() if ":" in cwe else cwe.strip()
            cwes.add(code)
    return cwes


def compute_gbt35273_compliance(findings: list[dict]) -> dict:
    """Compute GB/T 35273 compliance mapping."""
    cwe_ids = _extract_cwe_set(findings)
    result = {}
    for section, info in GBT35273_MAPPING.items():
        matched_cwes = set(info["cwes"]) & cwe_ids
        finding_count = sum(
            1 for f in findings
            if not f.get("is_suppressed")
            and any(c in set(info["cwes"]) for c in f.get("cwe", []))
        )
        result[section] = {
            "title": info["title"],
            "description": info["description"],
            "matched_cwes": sorted(matched_cwes),
            "finding_count": finding_count,
            "status": "fail" if finding_count > 0 else "pass",
        }
    return result


def compute_pci_dss_compliance(findings: list[dict]) -> dict:
    """Compute PCI DSS v4.0 compliance mapping."""
    cwe_ids = _extract_cwe_set(findings)
    result = {}
    for req, info in PCI_DSS_MAPPING.items():
        matched_cwes = set(info["cwes"]) & cwe_ids
        finding_count = sum(
            1 for f in findings
            if not f.get("is_suppressed")
            and any(c in set(info["cwes"]) for c in f.get("cwe", []))
        )
        result[req] = {
            "title": info["title"],
            "description": info["description"],
            "matched_cwes": sorted(matched_cwes),
            "finding_count": finding_count,
            "status": "fail" if finding_count > 0 else "pass",
        }
    return result


def compute_iso27001_compliance(findings: list[dict]) -> dict:
    """Compute ISO 27001 Annex A compliance mapping."""
    cwe_ids = _extract_cwe_set(findings)
    result = {}
    for control, info in ISO27001_MAPPING.items():
        matched_cwes = set(info["cwes"]) & cwe_ids
        finding_count = sum(
            1 for f in findings
            if not f.get("is_suppressed")
            and any(c in set(info["cwes"]) for c in f.get("cwe", []))
        )
        result[control] = {
            "title": info["title"],
            "matched_cwes": sorted(matched_cwes),
            "finding_count": finding_count,
            "status": "fail" if finding_count > 0 else "pass",
        }
    return result


def compute_all_compliance(findings: list[dict]) -> dict:
    """Compute all compliance mappings."""
    return {
        "gbt_35273": compute_gbt35273_compliance(findings),
        "pci_dss": compute_pci_dss_compliance(findings),
        "iso_27001": compute_iso27001_compliance(findings),
    }


def generate_compliance_report(compliance: dict, findings: list[dict]) -> str:
    """Generate markdown compliance report."""
    lines = ["# Compliance Report", ""]

    # GB/T 35273
    lines.extend([
        "## GB/T 35273-2020 (个人信息安全规范)",
        "",
        "| Section | Title | Status | Findings | CWEs |",
        "|---|---|---|---:|---|",
    ])
    for section, info in compliance.get("gbt_35273", {}).items():
        status = "PASS" if info["status"] == "pass" else "**FAIL**"
        cwes = ", ".join(info["matched_cwes"]) or "-"
        lines.append(f"| {section} | {info['title']} | {status} | {info['finding_count']} | {cwes} |")
    lines.append("")

    # PCI DSS
    lines.extend([
        "## PCI DSS v4.0",
        "",
        "| Requirement | Title | Status | Findings | CWEs |",
        "|---|---|---|---:|---|",
    ])
    for req, info in compliance.get("pci_dss", {}).items():
        status = "PASS" if info["status"] == "pass" else "**FAIL**"
        cwes = ", ".join(info["matched_cwes"]) or "-"
        lines.append(f"| {req} | {info['title']} | {status} | {info['finding_count']} | {cwes} |")
    lines.append("")

    # ISO 27001
    lines.extend([
        "## ISO 27001:2022 Annex A",
        "",
        "| Control | Title | Status | Findings | CWEs |",
        "|---|---|---|---:|---|",
    ])
    for control, info in compliance.get("iso_27001", {}).items():
        status = "PASS" if info["status"] == "pass" else "**FAIL**"
        cwes = ", ".join(info["matched_cwes"]) or "-"
        lines.append(f"| {control} | {info['title']} | {status} | {info['finding_count']} | {cwes} |")
    lines.append("")

    return "\n".join(lines)
