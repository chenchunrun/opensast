"""CLI helpers for baseline lifecycle operations."""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

from baseline import (
    add_suppression,
    generate_baseline,
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage OpenSAST baseline files")
    parser.add_argument("command", choices=["create", "update", "show", "suppress", "unsuppress"])
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
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command in {"create", "update"} and not os.path.isfile(args.findings):
        parser.error(f"findings file not found: {args.findings}")
    if args.command == "suppress":
        if not args.fingerprint:
            parser.error("--fingerprint is required for suppress")
        if not args.reason:
            parser.error("--reason is required for suppress")
    if args.command == "unsuppress" and not args.fingerprint:
        parser.error("--fingerprint is required for unsuppress")

    if args.command == "create":
        result = create_baseline_file(args.findings, args.baseline)
    elif args.command == "update":
        result = update_baseline_file(args.findings, args.baseline)
    elif args.command == "show":
        result = show_baseline_file(args.baseline)
    elif args.command == "suppress":
        result = suppress_fingerprint(args.baseline, args.fingerprint, args.reason, args.owner, args.expires_at)
    else:
        result = unsuppress_fingerprint(args.baseline, args.fingerprint)

    if args.output == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(format_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
