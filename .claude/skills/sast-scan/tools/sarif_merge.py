"""Merge multiple SARIF files into a single SARIF 2.1.0 file."""

import json
import os
from pathlib import PurePosixPath, PureWindowsPath


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)


def load_sarif(path: str) -> dict | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    if data.get("version") != SARIF_VERSION:
        return None

    if "runs" not in data or not isinstance(data["runs"], list):
        return None

    return data


def _to_relative_path(file_uri: str, repo_root: str) -> str:
    if file_uri.startswith("file://"):
        file_uri = file_uri[7:]

    try:
        abs_path = os.path.normpath(os.path.abspath(file_uri))
        rel = os.path.relpath(abs_path, repo_root)
    except (ValueError, OSError):
        return file_uri

    return rel.replace(os.sep, "/")


def _normalize_uri_in_location(location: dict, repo_root: str) -> dict:
    phys = location.get("physicalLocation", {})
    artifact = phys.get("artifactLocation", {})
    uri = artifact.get("uri", "")
    if uri and not uri.startswith(".."):
        artifact["uri"] = _to_relative_path(uri, repo_root)
        phys["artifactLocation"] = artifact
        location["physicalLocation"] = phys
    return location


def _rewrite_staged_uri(uri: str, staged_root: str, repo_root: str) -> str:
    """Map an absolute artifact URI under *staged_root* onto *repo_root*.

    Changed-only scans run the tools against a staged temp copy that mirrors
    the repo layout. Absolute URIs pointing into that copy would otherwise be
    unrepresentable as repo-relative paths downstream.
    """
    if not uri:
        return uri
    candidate = uri[7:] if uri.startswith("file://") else uri
    if not os.path.isabs(candidate):
        return uri
    norm = os.path.normpath(candidate)
    if norm == staged_root or norm.startswith(staged_root + os.sep):
        return os.path.join(repo_root, os.path.relpath(norm, staged_root))
    return uri


def remap_sarif_prefixes(sarif: dict, staged_root: str | None, repo_root: str) -> dict:
    """Rewrite artifact URIs from a staged scan copy back to repo coordinates."""
    if not staged_root:
        return sarif
    sarif = json.loads(json.dumps(sarif))
    staged_root = os.path.normpath(os.path.abspath(staged_root))
    repo_root = os.path.normpath(os.path.abspath(repo_root))

    def rewrite_loc(location: dict) -> None:
        phys = location.get("physicalLocation", {})
        artifact = phys.get("artifactLocation", {})
        new_uri = _rewrite_staged_uri(artifact.get("uri", ""), staged_root, repo_root)
        if new_uri != artifact.get("uri"):
            artifact["uri"] = new_uri

    for run in sarif.get("runs", []):
        for val in run.get("originalUriBaseIds", {}).values():
            uri = val.get("uri", "")
            new_uri = _rewrite_staged_uri(uri, staged_root, repo_root)
            if new_uri != uri:
                val["uri"] = new_uri

        for result in run.get("results", []):
            for loc in result.get("locations", []):
                rewrite_loc(loc)
            for flow in result.get("codeFlows", []):
                for tf in flow.get("threadFlows", []):
                    for loc in tf.get("locations", []):
                        rewrite_loc(loc.get("location", {}))
            for fix in result.get("fixes", []):
                for change in fix.get("artifactChanges", []):
                    artifact = change.get("artifactLocation", {})
                    new_uri = _rewrite_staged_uri(artifact.get("uri", ""), staged_root, repo_root)
                    if new_uri != artifact.get("uri"):
                        artifact["uri"] = new_uri

        for artifact in run.get("artifacts", []):
            location = artifact.get("location", {})
            uri = location.get("uri", "")
            new_uri = _rewrite_staged_uri(uri, staged_root, repo_root)
            if new_uri != uri:
                location["uri"] = new_uri

    return sarif


def filter_sarif_excluded_paths(sarif: dict, exclude_dirs: list[str]) -> dict:
    """Drop SARIF results whose (repo-relative) artifact path is under an exclude dir.

    Mirrors the runner's finding-level exclude filter so the SARIF deliverable
    (e.g. GitHub code scanning upload) matches the gated/report findings.
    Heuristic filters (generated/test code, baselines) stay findings-level only.
    """
    excludes = [d.strip("/") for d in exclude_dirs if d and d.strip("/")]
    if not excludes:
        return sarif

    sarif = json.loads(json.dumps(sarif))

    def _excluded(uri: str) -> bool:
        path = uri.replace("\\", "/")
        if path.startswith("./"):
            path = path[2:]
        return any(path == d or path.startswith(d + "/") for d in excludes)

    for run in sarif.get("runs", []):
        kept = []
        for result in run.get("results", []):
            uris = [
                loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                for loc in result.get("locations", [])
            ]
            if any(_excluded(uri) for uri in uris if uri):
                continue
            kept.append(result)
        run["results"] = kept
    return sarif


def normalize_paths_in_sarif(sarif: dict, repo_root: str) -> dict:
    sarif = json.loads(json.dumps(sarif))

    repo_root = os.path.normpath(os.path.abspath(repo_root))

    for run in sarif.get("runs", []):
        original_uri_base = run.get("originalUriBaseIds", {})
        for key, val in original_uri_base.items():
            uri = val.get("uri", "")
            if uri:
                val["uri"] = _to_relative_path(uri, repo_root)

        for result in run.get("results", []):
            for loc in result.get("locations", []):
                _normalize_uri_in_location(loc, repo_root)
            for flow in result.get("codeFlows", []):
                for tf in flow.get("threadFlows", []):
                    for loc in tf.get("locations", []):
                        inner = loc.get("location", {})
                        _normalize_uri_in_location(inner, repo_root)
            for fix in result.get("fixes", []):
                for change in fix.get("artifactChanges", []):
                    artifact = change.get("artifactLocation", {})
                    uri = artifact.get("uri", "")
                    if uri:
                        artifact["uri"] = _to_relative_path(uri, repo_root)

        for artifact in run.get("artifacts", []):
            uri = artifact.get("location", {}).get("uri", "")
            if uri:
                artifact["location"]["uri"] = _to_relative_path(uri, repo_root)

    return sarif


def merge_sarif_files(sarif_paths: list[str], output_path: str) -> dict:
    merged: dict = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [],
    }

    for path in sarif_paths:
        sarif = load_sarif(path)
        if sarif is None:
            continue
        merged["runs"].extend(sarif.get("runs", []))

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2, ensure_ascii=False)

    return merged
