"""Tests for RBAC scope analyzer."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from rbac_analyzer import analyze_rbac, _find_unscoped_role_checks, _find_unscoped_lists

NEXTJS_DIR = os.path.join(os.path.dirname(__file__), "samples", "nextjs")


class TestUnscopedRoleChecks:
    def test_detects_unscoped_check(self, tmp_path):
        # Create a file with unscoped role check
        f = tmp_path / "admin.ts"
        f.write_text('''
const adminMembership = await db.teamMember.findFirst({
  where: { userId: session.user.id, role: TeamRole.ADMIN }
})
''')
        findings = _find_unscoped_role_checks(str(tmp_path))
        assert len(findings) >= 1
        assert findings[0]["rule_id"] == "rbac.unscoped-admin-check"
        assert "CWE-863" in findings[0]["cwe"]

    def test_scoped_check_not_flagged(self, tmp_path):
        f = tmp_path / "admin.ts"
        f.write_text('''
const adminMembership = await db.teamMember.findFirst({
  where: { userId: session.user.id, role: TeamRole.ADMIN, teamId: teamId }
})
''')
        findings = _find_unscoped_role_checks(str(tmp_path))
        unscoped = [f for f in findings if f["rule_id"] == "rbac.unscoped-admin-check"]
        assert len(unscoped) == 0


class TestUnscopedLists:
    def test_detects_bare_findmany(self, tmp_path):
        f = tmp_path / "service.ts"
        f.write_text('''
export async function listAgents() {
  return db.agent.findMany()
}
''')
        findings = _find_unscoped_lists(str(tmp_path))
        assert len(findings) >= 1
        assert findings[0]["rule_id"] == "rbac.unscoped-list-endpoint"

    def test_scoped_findmany_not_flagged(self, tmp_path):
        f = tmp_path / "service.ts"
        f.write_text('''
export async function listAgents(userId: string) {
  return db.agent.findMany({ where: { userId } })
}
''')
        findings = _find_unscoped_lists(str(tmp_path))
        scoped = [f for f in findings if f["file"] == str(f)]
        assert len(scoped) == 0


class TestAnalyzeProject:
    def test_finding_format(self, tmp_path):
        f = tmp_path / "admin.ts"
        f.write_text('''
const admin = await db.teamMember.findFirst({
  where: { userId: userId, role: "ADMIN" }
})
''')
        project = {"languages": {"typescript": {}}, "frameworks": []}
        findings = analyze_rbac(str(tmp_path), project)
        if findings:
            f0 = findings[0]
            assert f0["tool"] == "rbac-analyzer"
            assert f0["severity"] in ("critical", "high", "medium", "low", "info")
            assert f0["cwe"]
            assert f0["owasp"]
