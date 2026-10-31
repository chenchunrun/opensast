"""Scan-scope helpers: changed-file discovery, staged-path mapping, exclusions.

These functions define how an explicitly requested scan target interacts with
git state and the configured exclude dirs. Keeping them separate from the
runner makes the coordinate-system rules (paths are repo-root-relative)
testable in isolation.
"""

from __future__ import annotations

import os


def is_path_inside(path: str, root: str) -> bool:
    """True when *path* equals *root* or lies somewhere below it."""
    norm_path = os.path.normpath(path)
    norm_root = os.path.normpath(root)
    return norm_path == norm_root or norm_path.startswith(norm_root + os.sep)


def git_repo_root(path: str) -> str | None:
    """Return the absolute git toplevel containing *path*, or None."""
    import subprocess
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=path, capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return os.path.normpath(result.stdout.strip())
    except Exception:
        pass
    return None


def get_changed_files(target: str) -> list[str]:
    """Return git-changed (added/copied/modified/renamed) files under *target*.

    Paths come back **repo-root-relative** so staging, reports, baselines and
    exclusion filters all share one coordinate system. When *target* is a
    subdirectory, only changes inside it are returned — git prints paths
    relative to the repo root regardless of the invocation directory, so an
    explicit subdirectory target must not silently pull in unrelated files.
    """
    import subprocess

    repo_root = git_repo_root(target)
    if repo_root is None:
        return []

    def _diff(extra: list[str]) -> list[str]:
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", "--diff-filter=ACMR", *extra],
                cwd=repo_root, capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                return [f.strip() for f in result.stdout.strip().splitlines() if f.strip()]
        except Exception:
            pass
        return []

    changed = _diff(["HEAD"]) or _diff([])
    target_abs = os.path.normpath(os.path.abspath(target))
    if target_abs != repo_root:
        changed = [f for f in changed if is_path_inside(os.path.join(repo_root, f), target_abs)]
    return changed


def remap_staged_path(path: str, staged_root: str, repo_root: str) -> str:
    """Map a finding path from the staged scan copy back to repo coordinates.

    Accepts plain absolute paths and ``file://`` URIs, mirroring the SARIF-side
    remapper (``sarif_merge._rewrite_staged_uri``) so both share one URI rule.
    """
    if not path:
        return path
    path = path[7:] if path.startswith("file://") else path
    if not os.path.isabs(path):
        return path
    norm = os.path.normpath(path)
    staged_root = os.path.normpath(staged_root)
    if norm == staged_root or norm.startswith(staged_root + os.sep):
        return os.path.join(repo_root, os.path.relpath(norm, staged_root))
    return path


def effective_exclude_dirs(exclude_dirs: list[str], target_rel: str) -> list[str]:
    """Drop exclude dirs at or above the scan target.

    ``targets.exclude`` prunes subtrees *within* the scan scope. Explicitly
    targeting a path inside an excluded subtree (e.g. scanning
    ``examples/python-sqli`` while ``examples`` is excluded for self-scans)
    overrides the ancestor exclusion; otherwise every finding would be
    silently filtered and the scan would report a meaningless zero.
    """
    if target_rel in (".", ""):
        return [d.strip("/") for d in exclude_dirs if d.strip("/")]
    kept: list[str] = []
    for d in exclude_dirs:
        d = d.strip("/")
        if not d:
            continue
        if target_rel == d or target_rel.startswith(d + "/"):
            continue
        kept.append(d)
    return kept


def remap_findings_from_staging(
    findings: list[dict], staged_root: str | None, repo_root: str,
) -> list[dict]:
    """Map staged-scan finding paths (primary file + dataflow evidence) to repo coordinates."""
    if not staged_root:
        return findings
    remapped: list[dict] = []
    for f in findings:
        evidence = f.get("evidence") or {}
        dataflow = evidence.get("dataflow") or []
        new_dataflow = [
            {**step, "file": remap_staged_path(step.get("file", ""), staged_root, repo_root)}
            if isinstance(step, dict) else step
            for step in dataflow
        ]
        remapped.append({
            **f,
            "file": remap_staged_path(f.get("file", ""), staged_root, repo_root),
            "evidence": {**evidence, "dataflow": new_dataflow} if new_dataflow else evidence,
        })
    return remapped


def relativize_finding_paths(findings: list[dict], repo_root: str) -> list[dict]:
    """Convert absolute finding paths (primary file + dataflow evidence) to repo-relative."""

    def _to_rel(path: str) -> str:
        if not path or not os.path.isabs(path):
            return path
        try:
            return os.path.relpath(path, repo_root)
        except ValueError:
            return path

    relativized: list[dict] = []
    for f in findings:
        evidence = f.get("evidence") or {}
        dataflow = evidence.get("dataflow") or []
        if dataflow:
            evidence = {**evidence, "dataflow": [
                {**step, "file": _to_rel(step.get("file", ""))}
                if isinstance(step, dict) else step
                for step in dataflow
            ]}
        relativized.append({**f, "file": _to_rel(f.get("file", "")), "evidence": evidence})
    return relativized
