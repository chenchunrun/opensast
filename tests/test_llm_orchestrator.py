"""Tests for the LLM orchestrator — archetype-aware analysis plan generation."""

import importlib.util
import json
import os
import tempfile

_spec = importlib.util.spec_from_file_location(
    "llm_orchestrator",
    os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools", "llm_orchestrator.py"),
)
_lo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_lo)

generate_analysis_plan = _lo.generate_analysis_plan
save_analysis_plan = _lo.save_analysis_plan
apply_fast_filters = _lo.apply_fast_filters
is_generated_code = _lo.is_generated_code
is_test_code = _lo.is_test_code
find_entry_points = _lo.find_entry_points
find_security_files = _lo.find_security_files
extract_finding_context = _lo.extract_finding_context
ARCHETYPE_CONTEXTS = _lo.ARCHETYPE_CONTEXTS

_dp_spec = importlib.util.spec_from_file_location(
    "detect_project",
    os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools", "detect_project.py"),
)
_dp = importlib.util.module_from_spec(_dp_spec)
_dp_spec.loader.exec_module(_dp)
detect_project = _dp.detect_project


def _make_finding(
    file: str = "api/handler.go",
    line: int = 42,
    severity: str = "high",
    rule_id: str = "go.exec-detected",
    tool: str = "semgrep",
    message: str = "exec.Command detected",
    cwe: list | None = None,
) -> dict:
    return {
        "file": file,
        "start_line": line,
        "severity": severity,
        "rule_id": rule_id,
        "tool": tool,
        "message": message,
        "cwe": cwe or ["CWE-78"],
    }


def _make_project(
    archetype: str = "library",
    languages: dict | None = None,
    frameworks: list | None = None,
) -> dict:
    return {
        "archetype": archetype,
        "languages": languages or {"go": 100},
        "frameworks": frameworks or [],
        "repo_root": "/tmp/test",
    }


# ============================================================
# Archetype detection
# ============================================================


def test_archetype_openSAST_is_web_or_library():
    result = detect_project(os.path.dirname(__file__) + "/..")
    assert result.get("archetype") in ("web-app", "library", "cli-tool")


def test_archetype_web_app_frameworks():
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = {"dependencies": {"express": "^4.0.0"}}
        with open(os.path.join(tmpdir, "package.json"), "w") as f:
            json.dump(pkg, f)
        os.makedirs(os.path.join(tmpdir, "src"))
        with open(os.path.join(tmpdir, "src", "index.js"), "w") as f:
            f.write("const app = express();\n")
        result = detect_project(tmpdir)
        assert result["archetype"] == "web-app"


def test_archetype_cli_go():
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, "cmd"))
        with open(os.path.join(tmpdir, "go.mod"), "w") as f:
            f.write("module example.com/cli\n\ngo 1.21\n")
        with open(os.path.join(tmpdir, "main.go"), "w") as f:
            f.write("package main\n\nfunc main() {}\n")
        result = detect_project(tmpdir)
        assert result["archetype"] == "cli-tool"


def test_archetype_library():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "go.mod"), "w") as f:
            f.write("module example.com/lib\n\ngo 1.21\n")
        with open(os.path.join(tmpdir, "lib.go"), "w") as f:
            f.write("package lib\n\nfunc Hello() string { return \"hello\" }\n")
        result = detect_project(tmpdir)
        assert result["archetype"] == "library"


# ============================================================
# Fast filters
# ============================================================


def test_fast_filter_generated_code():
    findings = [
        _make_finding(file="vendor/lib/utils.go"),
        _make_finding(file=".gomodcache/golang.org/x/net/dns.go"),
        _make_finding(file="src/api/handler.go"),
    ]
    result = apply_fast_filters(findings)
    assert len(result) == 1
    assert result[0]["file"] == "src/api/handler.go"


def test_fast_filter_test_code():
    findings = [
        _make_finding(file="api/handler_test.go"),
        _make_finding(file="api/handler.go"),
        _make_finding(file="tests/test_main.py"),
    ]
    result = apply_fast_filters(findings)
    assert len(result) == 1
    assert result[0]["file"] == "api/handler.go"


def test_fast_filter_empty():
    assert apply_fast_filters([]) == []


def test_is_generated_code_patterns():
    assert is_generated_code("vendor/lib/a.go")
    assert is_generated_code("node_modules/react/index.js")
    assert is_generated_code(".gomodcache/golang.org/x/net/dns.go")
    assert is_generated_code("dist/bundle.min.js")
    assert not is_generated_code("src/main.go")
    assert not is_generated_code("api/handler.py")


def test_is_test_code_patterns():
    assert is_test_code("api/handler_test.go")
    assert is_test_code("tests/test_main.py")
    assert is_test_code("__tests__/app.test.ts")
    assert is_test_code("spec/feature_spec.rb")
    assert not is_test_code("api/handler.go")
    assert not is_test_code("src/main.py")


# ============================================================
# Entry point detection
# ============================================================


def test_find_entry_points_nextjs():
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, "app", "api", "users"))
        with open(os.path.join(tmpdir, "app", "api", "users", "route.ts"), "w") as f:
            f.write("import { NextResponse } from 'next/server';\n\n")
            f.write("export async function GET(request: Request) {\n")
            f.write("  return NextResponse.json({ users: [] });\n")
            f.write("}\n\n")
            f.write("export async function POST(request: Request) {\n")
            f.write("  return NextResponse.json({ ok: true });\n")
            f.write("}\n")
        eps = find_entry_points(tmpdir)
        methods = [ep["content"] for ep in eps]
        assert any("GET" in m for m in methods)
        assert any("POST" in m for m in methods)


def test_find_entry_points_go_gin():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "main.go"), "w") as f:
            f.write('package main\n\nimport "net/http"\n\n')
            f.write("func handler(w http.ResponseWriter, r *http.Request) {}\n\n")
            f.write("func main() { http.HandleFunc(\"/\", handler) }\n")
        eps = find_entry_points(tmpdir)
        assert len(eps) >= 1
        assert any("http.ResponseWriter" in ep["content"] for ep in eps)


def test_find_entry_points_python_flask():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "app.py"), "w") as f:
            f.write("from flask import Flask\napp = Flask(__name__)\n\n")
            f.write("@app.route('/api/users')\ndef get_users(): pass\n")
        eps = find_entry_points(tmpdir)
        assert len(eps) >= 1
        assert any("route" in ep["content"] for ep in eps)


# ============================================================
# Security file detection
# ============================================================


def test_find_security_files_crypto():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "crypto_utils.go"), "w") as f:
            f.write('package main\n\nimport "crypto/aes"\n\n')
            f.write('func encrypt(key []byte) { _ = aes.NewCipher(key) }\n')
        sfiles = find_security_files(tmpdir)
        assert any("crypto" in sf for sf in sfiles)


def test_find_security_files_auth():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "auth_middleware.py"), "w") as f:
            f.write("def check_auth(token): ...\n")
        sfiles = find_security_files(tmpdir)
        assert any("auth" in sf for sf in sfiles)


# ============================================================
# Finding context extraction
# ============================================================


def test_extract_finding_context_basic():
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = os.path.join(tmpdir, "handler.go")
        with open(filepath, "w") as f:
            f.write('package main\n\nimport "os/exec"\n\n')
            f.write("func run(cmd string) {\n")
            f.write("    exec.Command(cmd)\n")
            f.write("}\n")
        finding = _make_finding(file="handler.go", line=5)
        ctx = extract_finding_context(finding, tmpdir, "cli-tool")
        assert "error" not in ctx or ctx.get("error") is None
        assert ctx.get("imports", "") != ""
        assert "exec" in ctx.get("surrounding_code", "")


def test_extract_finding_context_missing_file():
    finding = _make_finding(file="/nonexistent/file.go", line=1)
    ctx = extract_finding_context(finding, "/tmp", "library")
    assert ctx.get("error") == "file_not_readable"


def test_extract_finding_context_archetype_cli():
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = os.path.join(tmpdir, "cmd.go")
        with open(filepath, "w") as f:
            f.write('package main\n\nimport "os/exec"\n\n')
            f.write("func main() {\n    exec.Command(\"ls\")\n}\n")
        finding = _make_finding(file="cmd.go", line=5, message="exec.Command detected")
        ctx = extract_finding_context(finding, tmpdir, "cli-tool")
        assert "NORMAL" in ctx.get("archetype_context", "")


def test_extract_finding_context_archetype_web():
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = os.path.join(tmpdir, "handler.go")
        with open(filepath, "w") as f:
            f.write('package main\n\nimport "os/exec"\n\n')
            f.write("func handler(w http.ResponseWriter, r *http.Request) {\n")
            f.write("    exec.Command(r.URL.Query().Get(\"cmd\"))\n")
            f.write("}\n")
        finding = _make_finding(file="handler.go", line=5, message="exec.Command detected")
        ctx = extract_finding_context(finding, tmpdir, "web-app")
        assert "RCE" in ctx.get("archetype_context", "") or "web handler" in ctx.get("archetype_context", "")


# ============================================================
# Analysis plan generation
# ============================================================


def test_generate_plan_basic():
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = os.path.join(tmpdir, "handler.go")
        with open(filepath, "w") as f:
            f.write('package main\n\nimport "os/exec"\n\n')
            f.write("func handler(w http.ResponseWriter, r *http.Request) {\n")
            f.write("    exec.Command(r.URL.Query().Get(\"cmd\"))\n")
            f.write("}\n")

        findings = [_make_finding(file="handler.go", line=5)]
        project = _make_project(archetype="web-app")
        plan = generate_analysis_plan(findings, project, tmpdir)

        assert plan["project_archetype"] == "web-app"
        assert len(plan["analysis_targets"]) >= 1
        assert plan["analysis_targets"][0]["target_id"] == "T-001"
        assert "analysis_prompt" in plan["analysis_targets"][0]
        assert plan["rule_findings_summary"]["total"] == 1


def test_generate_plan_empty_findings():
    with tempfile.TemporaryDirectory() as tmpdir:
        plan = generate_analysis_plan([], _make_project(), tmpdir)
        assert plan["analysis_targets"] == []
        assert plan["rule_findings_summary"]["total"] == 0


def test_generate_plan_limits_targets():
    with tempfile.TemporaryDirectory() as tmpdir:
        for i in range(30):
            filepath = os.path.join(tmpdir, f"file_{i}.go")
            with open(filepath, "w") as f:
                f.write(f"package main\n\nfunc f{i}() {{}}\n")

        findings = [_make_finding(file=f"file_{i}.go", line=3, rule_id=f"rule-{i}") for i in range(30)]
        plan = generate_analysis_plan(findings, _make_project(), tmpdir, {"llm_orchestration": {"max_targets": 10}})
        assert len(plan["analysis_targets"]) <= 15  # 10 findings + up to 5 security files


def test_generate_plan_includes_output_format():
    plan = generate_analysis_plan([], _make_project(), "/tmp")
    assert "output_format" in plan
    assert "schema" in plan["output_format"]
    assert "tool" in plan["output_format"]["schema"]


def test_generate_plan_archetype_in_context():
    findings = [_make_finding()]
    plan = generate_analysis_plan(findings, _make_project(archetype="cli-tool"), "/tmp")
    assert plan["project_archetype"] == "cli-tool"
    assert plan["project_context"]["archetype"] == "cli-tool"


# ============================================================
# Analysis prompts
# ============================================================


def test_analysis_prompt_cli_exec_is_normal():
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = os.path.join(tmpdir, "main.go")
        with open(filepath, "w") as f:
            f.write('package main\n\nimport "os/exec"\n\nfunc main() {\n    exec.Command("ls")\n}\n')
        findings = [_make_finding(file="main.go", line=5, message="exec.Command detected")]
        plan = generate_analysis_plan(findings, _make_project(archetype="cli-tool"), tmpdir)
        prompt = plan["analysis_targets"][0]["analysis_prompt"]
        assert "NORMAL" in prompt or "normal" in prompt.lower()


def test_analysis_prompt_web_exec_is_rce():
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = os.path.join(tmpdir, "handler.go")
        with open(filepath, "w") as f:
            f.write('package main\n\nimport "os/exec"\n\nfunc handler() {\n    exec.Command("ls")\n}\n')
        findings = [_make_finding(file="handler.go", line=5, message="exec.Command detected")]
        plan = generate_analysis_plan(findings, _make_project(archetype="web-app"), tmpdir)
        prompt = plan["analysis_targets"][0]["analysis_prompt"]
        assert "RCE" in prompt or "user input" in prompt.lower()


def test_analysis_prompt_csrf_bearer():
    findings = [_make_finding(message="Missing CSRF protection", rule_id="csrf-missing")]
    plan = generate_analysis_plan(findings, _make_project(archetype="web-app"), "/tmp")
    prompt = plan["analysis_targets"][0]["analysis_prompt"]
    assert "CSRF" in prompt or "Bearer" in prompt or "cookie" in prompt.lower()


# ============================================================
# Save plan
# ============================================================


def test_save_plan(tmp_path):
    plan = generate_analysis_plan([], _make_project(), str(tmp_path))
    path = save_analysis_plan(plan, str(tmp_path))
    assert os.path.isfile(path)
    with open(path) as f:
        data = json.load(f)
    assert data["project_archetype"] == "library"
    assert "generated_at" in data


def test_save_plan_overwrites(tmp_path):
    plan1 = generate_analysis_plan([], _make_project(archetype="web-app"), str(tmp_path))
    save_analysis_plan(plan1, str(tmp_path))
    plan2 = generate_analysis_plan([], _make_project(archetype="cli-tool"), str(tmp_path))
    save_analysis_plan(plan2, str(tmp_path))
    with open(os.path.join(str(tmp_path), "llm-analysis-plan.json")) as f:
        data = json.load(f)
    assert data["project_archetype"] == "cli-tool"


# ============================================================
# Edge cases
# ============================================================


def test_all_findings_filtered():
    findings = [
        _make_finding(file="vendor/a.go"),
        _make_finding(file="node_modules/b.js"),
        _make_finding(file="tests/test_c.go"),
    ]
    result = apply_fast_filters(findings)
    assert result == []


def test_large_finding_set_priority():
    with tempfile.TemporaryDirectory() as tmpdir:
        for i in range(5):
            filepath = os.path.join(tmpdir, f"file_{i}.go")
            with open(filepath, "w") as f:
                f.write(f"package main\nfunc f{i}() {{}}\n")

    findings = [
        _make_finding(severity="info", rule_id="low-rule"),
        _make_finding(severity="critical", rule_id="crit-rule"),
        _make_finding(severity="medium", rule_id="med-rule"),
        _make_finding(severity="high", rule_id="high-rule"),
    ]
    plan = generate_analysis_plan(findings, _make_project(), tmpdir)
    targets = plan["analysis_targets"]
    if len(targets) >= 2:
        assert targets[0]["priority"] in ("critical", "high")


def test_duplicate_findings_deduped():
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = os.path.join(tmpdir, "handler.go")
        with open(filepath, "w") as f:
            f.write("package main\nfunc handler() {}\n")
    findings = [
        _make_finding(file="handler.go", line=3, rule_id="same-rule"),
        _make_finding(file="handler.go", line=3, rule_id="same-rule"),
    ]
    plan = generate_analysis_plan(findings, _make_project(), tmpdir)
    assert plan["rule_findings_summary"]["total"] == 1
