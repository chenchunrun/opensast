"""Tests for the LLM analysis plan generator."""

import importlib.util
import json
import os
import tempfile

_spec = importlib.util.spec_from_file_location(
    "llm_analyzer",
    os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools", "llm_analyzer.py"),
)
_la = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_la)

generate_llm_analysis_plan = _la.generate_llm_analysis_plan
_prioritize_targets = _la._prioritize_targets
_extract_code_context = _la._extract_code_context
_extract_handler_regions = _la._extract_handler_regions
_extract_imports = _la._extract_imports
_build_analysis_checklist = _la._build_analysis_checklist


def _make_target(file: str = "/app/api/users/route.ts", risks: list[str] | None = None, priority: str = "high") -> dict:
    return {
        "file": file,
        "risks": risks or ["idor-risk"],
        "priority": priority,
        "reason": "test target",
    }


# --- Prioritization ---


def test_prioritize_missing_auth_ranks_highest():
    targets = [
        _make_target(risks=["missing-csrf"]),
        _make_target(risks=["idor-risk"]),
        _make_target(risks=["missing-authentication"]),
    ]
    result = _prioritize_targets(targets, [], {
        "risk_priorities": {
            "missing-authentication": {"base_score": 3},
            "idor-risk": {"base_score": 2},
            "missing-csrf": {"base_score": 0},
        },
    })
    assert result[0]["risks"] == ["missing-authentication"]


def test_prioritize_limits_count():
    targets = [_make_target(risks=["idor-risk"]) for _ in range(50)]
    result = _prioritize_targets(targets, [], {"max_targets": 10})
    assert len(result) == 50  # _prioritize doesn't limit, caller does


def test_prioritize_fp_paths_reduces_score():
    targets = [
        _make_target(file="/app/api/auth/login/route.ts", risks=["missing-authentication"]),
        _make_target(file="/app/api/admin/users/route.ts", risks=["missing-authentication"]),
    ]
    result = _prioritize_targets(targets, [], {
        "risk_priorities": {
            "missing-authentication": {"base_score": 3, "fp_paths": ["/api/auth/"]},
        },
    })
    assert result[0]["file"].endswith("admin/users/route.ts")


def test_prioritize_deduplicates_with_findings():
    targets = [
        _make_target(file="/app/api/data/route.ts", risks=["idor-risk"]),
    ]
    findings = [
        {"file": "/app/api/data/route.ts", "tool": "dataflow-analyzer",
         "confidence": "high", "rule_id": "missing-auth"},
    ]
    result = _prioritize_targets(targets, findings, {
        "coverage_deduction": {"dataflow-analyzer": 2},
    })
    assert result[0]["_score"] < 2


def test_prioritize_compound_risk_bonus():
    targets = [
        _make_target(risks=["idor-risk"]),
        _make_target(risks=["idor-risk", "missing-authentication", "missing-csrf"]),
    ]
    result = _prioritize_targets(targets, [], {})
    assert result[0]["risks"] == ["idor-risk", "missing-authentication", "missing-csrf"]


# --- Code Context Extraction ---


def test_extract_handler_regions_nextjs():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".ts", delete=False) as f:
        f.write("import { NextResponse } from 'next/server';\n\n")
        f.write("export async function GET(request: Request) {\n")
        f.write("  return NextResponse.json({ hello: 'world' });\n")
        f.write("}\n\n")
        f.write("export async function POST(request: Request) {\n")
        f.write("  const body = await request.json();\n")
        f.write("  return NextResponse.json(body);\n")
        f.write("}\n")
        f.name

    try:
        with open(f.name) as fh:
            content = fh.read()
        regions = _extract_handler_regions(content)
        methods = [r["method"] for r in regions]
        assert "GET" in methods
        assert "POST" in methods
        assert all(r["start_line"] > 0 for r in regions)
    finally:
        os.unlink(f.name)


def test_extract_imports():
    code = (
        "import { NextResponse } from 'next/server';\n"
        "import { getUser } from '@/lib/auth';\n"
        "\n"
        "export async function GET() {\n"
        "  return NextResponse.json({});\n"
        "}\n"
    )
    imports = _extract_imports(code)
    assert "next/server" in imports
    assert "@/lib/auth" in imports
    assert "export" not in imports


def test_extract_code_context_file_not_found():
    ctx = _extract_code_context({"file": "/nonexistent/file.ts"}, "/tmp")
    assert ctx.get("error") == "file_not_readable"


# --- Analysis Checklist ---


def test_build_checklist_skips_covered_risks():
    target = _make_target(risks=["missing-csrf", "idor-risk"])
    findings = [
        {"tool": "semgrep", "rule_id": "csrf-missing", "confidence": "high",
         "file": "/app/api/users/route.ts", "cwe": ["CWE-352"]},
    ]
    checklist = _build_analysis_checklist(target, {}, findings)
    assert "idor-risk" in checklist["risks_to_analyze"]


def test_build_checklist_adds_business_logic():
    target = _make_target(risks=["idor-risk"])
    code_context = {
        "handler_regions": [
            {"method": "POST", "start_line": 1, "end_line": 20,
             "content": "await prisma.user.create({ data: body })"},
        ],
    }

    checklist = _build_analysis_checklist(target, code_context, [])
    assert "business-logic" in checklist["risks_to_analyze"]


def test_build_checklist_skip_when_all_covered():
    target = _make_target(risks=["missing-csrf"])
    findings = [
        {"tool": "semgrep", "rule_id": "csrf-check", "confidence": "high",
         "file": "/app/api/users/route.ts", "cwe": ["CWE-352"]},
    ]
    checklist = _build_analysis_checklist(target, {}, findings)
    assert checklist["skip"] is True


# --- Full Plan Generation ---


def test_generate_plan_output_format():
    targets = {
        "llm_analysis_targets": [
            _make_target(risks=["missing-authentication"], priority="critical"),
            _make_target(risks=["idor-risk"], priority="high"),
        ],
    }
    plan = generate_llm_analysis_plan([], targets, "/tmp/project")
    assert plan["total_targets_available"] == 2
    assert plan["targets_selected"] == 2
    assert len(plan["analysis_targets"]) == 2
    assert plan["analysis_targets"][0]["target_id"] == "T-001"
    assert "output_format" in plan


def test_generate_plan_empty_targets():
    plan = generate_llm_analysis_plan([], {"llm_analysis_targets": []}, "/tmp/project")
    assert plan["targets_selected"] == 0
    assert plan["analysis_targets"] == []


def test_generate_plan_respects_max_targets():
    targets = {
        "llm_analysis_targets": [
            _make_target(risks=["idor-risk"], priority="medium") for _ in range(30)
        ],
    }
    plan = generate_llm_analysis_plan([], targets, "/tmp/project", {"llm_analysis": {"max_targets": 5}})
    assert plan["targets_selected"] == 5


def test_generate_plan_middleware_context():
    with tempfile.TemporaryDirectory() as tmpdir:
        mw_path = os.path.join(tmpdir, "middleware.ts")
        with open(mw_path, "w") as f:
            f.write("import { getServerSession } from 'next-auth';\n")
            f.write("export function middleware(request) { }\n")
            f.write("export const config = { matcher: ['/api/:path*'] };\n")

        targets = {"llm_analysis_targets": [_make_target(risks=["idor-risk"])]}
        plan = generate_llm_analysis_plan([], targets, tmpdir)
        mw = plan["middleware_context"]
        assert mw["detected"] is True
        assert mw["has_auth_check"] is True
        assert "/api/:path*" in mw["protected_prefixes"]


def test_save_plan(tmp_path):
    path = _la.save_llm_analysis_plan({"targets_selected": 0}, str(tmp_path))
    assert os.path.isfile(path)
    with open(path) as f:
        data = json.load(f)
    assert data["targets_selected"] == 0
