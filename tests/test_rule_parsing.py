"""Compile the entire production ruleset, including rules without fixtures."""

import json
from pathlib import Path
import subprocess
import sys

import pytest

TOOLS = Path(__file__).resolve().parents[1] / ".claude/skills/sast-scan/tools"
sys.path.insert(0, str(TOOLS))
from run_semgrep import build_semgrep_env, get_semgrep_binary


@pytest.mark.skipif(not get_semgrep_binary(), reason="Semgrep is not installed")
def test_entire_ruleset_compiles_without_errors(tmp_path):
    # Each supported parser must compile patterns even if the rule has no fixture.
    for extension in ("py", "js", "ts", "java", "cs", "php", "rb", "go", "kt", "swift", "rs", "c", "tf"):
        (tmp_path / f"empty.{extension}").write_text("\n")
    proc = subprocess.run(
        [get_semgrep_binary(), "--config", str(TOOLS.parent / "rules/semgrep"),
         "--json", "--no-git-ignore", str(tmp_path)],
        capture_output=True, text=True, timeout=90, env=build_semgrep_env(),
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout).get("errors", []) == []
