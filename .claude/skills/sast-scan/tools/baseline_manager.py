"""CLI helpers for baseline lifecycle operations."""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

from baseline import (
    add_suppression,
    cleanup_expired,
    diff_baselines,
    generate_baseline,
    get_audit_trail,
    get_stats,
    import_suppressions,
    load_baseline,
    remove_suppression,
    save_baseline,
    update_baseline,
)


def load_findings_payload(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        findings = data.get("findings", [])
        if isinstance(findings, list):
            return findings
        return []
    if isinstance(data, list):
        return data
    return []


def create_baseline_file(findings_path: str, baseline_path: str) -> dict[str, Any]:
    findings = load_findings_payload(findings_path)
    baseline = generate_baseline(findings)
    save_baseline(baseline_path, baseline)
    return {
        "command": "create",
        "baseline_path": baseline_path,
        "fingerprints": len(baseline.get("fingerprints", {})),
        "suppressions": len(baseline.get("suppressions", [])),
    }


def update_baseline_file(findings_path: str, baseline_path: str) -> dict[str, Any]:
    findings = load_findings_payload(findings_path)
    baseline = load_baseline(baseline_path)
    baseline = update_baseline(baseline, findings)
    save_baseline(baseline_path, baseline)
    return {
        "command": "update",
        "baseline_path": baseline_path,
        "fingerprints": len(baseline.get("fingerprints", {})),
        "suppressions": len(baseline.get("suppressions", [])),
    }


def show_baseline_file(baseline_path: str) -> dict[str, Any]:
    baseline = load_baseline(baseline_path)
    return {
        "command": "show",
        "baseline_path": baseline_path,
        "fingerprints": len(baseline.get("fingerprints", {})),
        "suppressions": len(baseline.get("suppressions", [])),
        "created_at": baseline.get("created_at"),
        "updated_at": baseline.get("updated_at"),
    }


def suppress_fingerprint(
    baseline_path: str,
    fingerprint: str,
    reason: str,
    owner: str,
    expires_at: str | None,
) -> dict[str, Any]:
    baseline = load_baseline(baseline_path)
    baseline = add_suppression(baseline, fingerprint, reason, owner, expires_at)
    save_baseline(baseline_path, baseline)
    return {
        "command": "suppress",
        "baseline_path": baseline_path,
        "fingerprint": fingerprint,
        "suppressions": len(baseline.get("suppressions", [])),
    }


def unsuppress_fingerprint(baseline_path: str, fingerprint: str) -> dict[str, Any]:
    baseline = load_baseline(baseline_path)
    baseline = remove_suppression(baseline, fingerprint)
    save_baseline(baseline_path, baseline)
    return {
        "command": "unsuppress",
        "baseline_path": baseline_path,
        "fingerprint": fingerprint,
        "suppressions": len(baseline.get("suppressions", [])),
    }


def diff_baseline_file(baseline_path: str, findings_path: str) -> dict[str, Any]:
    """Compare current baseline against latest findings."""
    baseline_before = load_baseline(baseline_path)
    findings = load_findings_payload(findings_path)
    baseline_after = generate_baseline(findings)
    diff = diff_baselines(baseline_before, baseline_after)
    return {"command": "diff", "baseline_path": baseline_path, **diff}


def stats_baseline_file(baseline_path: str) -> dict[str, Any]:
    """Get baseline statistics."""
    baseline = load_baseline(baseline_path)
    stats = get_stats(baseline)
    return {"command": "stats", "baseline_path": baseline_path, **stats}


def cleanup_baseline_file(baseline_path: str) -> dict[str, Any]:
    """Remove expired suppressions."""
    baseline = load_baseline(baseline_path)
    result = cleanup_expired(baseline)
    save_baseline(baseline_path, baseline)
    return {"command": "cleanup", "baseline_path": baseline_path, **result}


def import_baseline_file(baseline_path: str, import_path: str, owner: str = "import") -> dict[str, Any]:
    """Bulk import suppressions from a JSON file."""
    baseline = load_baseline(baseline_path)
    with open(import_path, "r", encoding="utf-8") as f:
        suppressions = json.load(f)
    if not isinstance(suppressions, list):
        suppressions = suppressions.get("suppressions", [])
    result = import_suppressions(baseline, suppressions, owner)
    save_baseline(baseline_path, baseline)
    return {"command": "import", "baseline_path": baseline_path, **result}


def audit_baseline_file(baseline_path: str, limit: int = 50) -> dict[str, Any]:
    """Show suppression change history."""
    baseline = load_baseline(baseline_path)
    trail = get_audit_trail(baseline, limit)
    return {"command": "audit", "baseline_path": baseline_path, "audit_trail": trail, "total_entries": len(trail)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage OpenSAST baseline files")
    parser.add_argument(
        "command",
        choices=["create", "update", "show", "suppress", "unsuppress", "diff", "stats", "cleanup", "import", "audit"],
    )
    parser.add_argument(
        "--findings",
        default=".claude/sast/results/findings.json",
        help="Findings JSON path",
    )
    parser.add_argument(
        "--baseline",
        default=".claude/sast/baseline.json",
        help="Baseline JSON path",
    )
    parser.add_argument("--fingerprint", help="Finding fingerprint")
    parser.add_argument("--reason", help="Suppression reason")
    parser.add_argument("--owner", default="sast-analyst", help="Suppression owner")
    parser.add_argument("--expires-at", help="Suppression expiry timestamp")
    parser.add_argument("--import-file", help="JSON file with suppressions to import")
    parser.add_argument("--limit", type=int, default=50, help="Audit trail limit")
    parser.add_argument("--output", choices=["json", "text"], default="text")
    return parser


def format_text(result: dict[str, Any]) -> str:
    lines = [f"Command: {result['command']}", f"Baseline: {result['baseline_path']}"]
    if "fingerprints" in result:
        lines.append(f"Fingerprints: {result['fingerprints']}")
    if "suppressions" in result:
        lines.append(f"Suppressions: {result['suppressions']}")
    if "fingerprint" in result:
        lines.append(f"Fingerprint: {result['fingerprint']}")

    if result["command"] == "diff":
        lines.append(f"FPs added: {len(result.get('fingerprints_added', []))}")
        lines.append(f"FPs removed: {len(result.get('fingerprints_removed', []))}")
        lines.append(f"Suppressions added: {len(result.get('suppressions_added', []))}")
        lines.append(f"Suppressions removed: {len(result.get('suppressions_removed', []))}")

    if result["command"] == "stats":
        lines.append(f"Active suppressions: {result.get('active_suppressions', 0)}")
        lines.append(f"Expired suppressions: {result.get('expired_suppressions', 0)}")
        lines.append(f"Permanent suppressions: {result.get('permanent_suppressions', 0)}")

    if result["command"] == "cleanup":
        lines.append(f"Removed: {result.get('removed_count', 0)} expired suppressions")

    if result["command"] == "import":
        lines.append(f"Imported: {result.get('imported_count', 0)}")
        lines.append(f"Skipped: {result.get('skipped_count', 0)}")

    if result["command"] == "audit":
        lines.append(f"Audit entries: {result.get('total_entries', 0)}")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command in {"create", "update", "diff"} and not os.path.isfile(args.findings):
        parser.error(f"findings file not found: {args.findings}")
    if args.command == "suppress":
        if not args.fingerprint:
            parser.error("--fingerprint is required for suppress")
        if not args.reason:
            parser.error("--reason is required for suppress")
    if args.command == "unsuppress" and not args.fingerprint:
        parser.error("--fingerprint is required for unsuppress")
    if args.command == "import" and not args.import_file:
        parser.error("--import-file is required for import")

    if args.command == "create":
        result = create_baseline_file(args.findings, args.baseline)
    elif args.command == "update":
        result = update_baseline_file(args.findings, args.baseline)
    elif args.command == "show":
        result = show_baseline_file(args.baseline)
    elif args.command == "suppress":
        result = suppress_fingerprint(args.baseline, args.fingerprint, args.reason, args.owner, args.expires_at)
    elif args.command == "unsuppress":
        result = unsuppress_fingerprint(args.baseline, args.fingerprint)
    elif args.command == "diff":
        result = diff_baseline_file(args.baseline, args.findings)
    elif args.command == "stats":
        result = stats_baseline_file(args.baseline)
    elif args.command == "cleanup":
        result = cleanup_baseline_file(args.baseline)
    elif args.command == "import":
        result = import_baseline_file(args.baseline, args.import_file, args.owner)
    elif args.command == "audit":
        result = audit_baseline_file(args.baseline, args.limit)
    else:
        parser.error(f"Unknown command: {args.command}")

    if args.output == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(format_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
