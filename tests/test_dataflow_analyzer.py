"""Tests for cross-file data flow analyzer."""
import os
import sys

import pytest

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools",
    ),
)

from dataflow_analyzer import (
    _build_function_index,
    _find_route_handlers,
    analyze_project,
)

NEXTJS_DIR = os.path.join(os.path.dirname(__file__), "samples", "nextjs")


class TestFunctionIndex:
    def test_builds_index(self) -> None:
        if not os.path.isdir(NEXTJS_DIR):
            pytest.skip("NextJS samples not found")
        index = _build_function_index(NEXTJS_DIR)
        assert isinstance(index, dict)

    def test_finds_service_functions(self) -> None:
        if not os.path.isdir(NEXTJS_DIR):
            pytest.skip("NextJS samples not found")
        index = _build_function_index(NEXTJS_DIR)
        # getFile and getFileForUser should be indexed
        assert "getFile" in index
        assert "getFileForUser" in index

    def test_service_detection(self) -> None:
        if not os.path.isdir(NEXTJS_DIR):
            pytest.skip("NextJS samples not found")
        index = _build_function_index(NEXTJS_DIR)
        file_fn = index.get("getFile")
        assert file_fn is not None
        assert file_fn["is_service"] is True
        assert file_fn["has_db_query"] is True

    def test_ownership_check_detection(self) -> None:
        if not os.path.isdir(NEXTJS_DIR):
            pytest.skip("NextJS samples not found")
        index = _build_function_index(NEXTJS_DIR)
        # getFileForUser is in file-service.ts which contains userId
        # so the file-level ownership check is True
        safe_fn = index.get("getFileForUser")
        assert safe_fn is not None
        assert safe_fn["has_ownership_check"] is True


class TestRouteHandlers:
    def test_finds_routes(self) -> None:
        if not os.path.isdir(NEXTJS_DIR):
            pytest.skip("NextJS samples not found")
        routes = _find_route_handlers(NEXTJS_DIR)
        assert len(routes) >= 1

    def test_route_has_http_methods(self) -> None:
        if not os.path.isdir(NEXTJS_DIR):
            pytest.skip("NextJS samples not found")
        routes = _find_route_handlers(NEXTJS_DIR)
        for route in routes:
            assert "http_methods" in route
            assert isinstance(route["http_methods"], list)

    def test_route_has_function_calls(self) -> None:
        if not os.path.isdir(NEXTJS_DIR):
            pytest.skip("NextJS samples not found")
        routes = _find_route_handlers(NEXTJS_DIR)
        all_calls: list[str] = []
        for route in routes:
            all_calls.extend(route["function_calls"])
        # At least getFile or getFileForUser should be found
        assert "getFile" in all_calls or "getFileForUser" in all_calls


class TestAnalyzeProject:
    def test_detects_missing_authz(self) -> None:
        if not os.path.isdir(NEXTJS_DIR):
            pytest.skip("NextJS samples not found")
        project: dict = {"languages": {"typescript": {}}, "frameworks": ["next"]}
        findings = analyze_project(NEXTJS_DIR, project)
        # Should find at least 1 missing authorization issue
        assert len(findings) >= 1
        assert findings[0]["tool"] == "dataflow-analyzer"
        assert "CWE-862" in findings[0]["cwe"]

    def test_skips_non_ts_projects(self) -> None:
        project: dict = {"languages": {"python": {}}, "frameworks": ["django"]}
        findings = analyze_project(NEXTJS_DIR, project)
        assert findings == []

    def test_finding_format(self) -> None:
        if not os.path.isdir(NEXTJS_DIR):
            pytest.skip("NextJS samples not found")
        project: dict = {"languages": {"typescript": {}}, "frameworks": ["next"]}
        findings = analyze_project(NEXTJS_DIR, project)
        if findings:
            f = findings[0]
            assert f["severity"] in ("critical", "high", "medium", "low", "info")
            assert f["rule_id"]
            assert f["file"]
            assert f["cwe"]
            assert f["owasp"]
            assert f["evidence"]["dataflow"]
            assert len(f["evidence"]["dataflow"]) >= 2
            assert f["recommendation"]

    def test_evidence_contains_source_and_sink(self) -> None:
        if not os.path.isdir(NEXTJS_DIR):
            pytest.skip("NextJS samples not found")
        project: dict = {"languages": {"typescript": {}}, "frameworks": ["next"]}
        findings = analyze_project(NEXTJS_DIR, project)
        if findings:
            evidence = findings[0]["evidence"]
            assert evidence["source"]
            assert evidence["sink"]
