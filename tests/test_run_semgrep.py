"""Tests for Semgrep wrapper environment helpers."""

import os
import shutil
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from run_semgrep import SEMGREP_ENV, build_semgrep_env, get_semgrep_binary, run_semgrep


def test_build_semgrep_env_sets_metrics_and_version_check():
    env = build_semgrep_env()
    assert env["SEMGREP_SEND_METRICS"] == SEMGREP_ENV["SEMGREP_SEND_METRICS"]
    assert env["SEMGREP_ENABLE_VERSION_CHECK"] == SEMGREP_ENV["SEMGREP_ENABLE_VERSION_CHECK"]


def test_build_semgrep_env_uses_temp_home_not_inside_base_dir():
    with tempfile.TemporaryDirectory() as base_dir:
        env = build_semgrep_env(base_dir)
        home = env["HOME"]
        assert home.endswith("opensast-semgrep-home")
        assert not home.startswith(os.path.abspath(base_dir))
        assert os.path.isdir(home)
        assert os.path.isdir(os.path.join(home, ".semgrep"))


def test_build_semgrep_env_uses_temp_home_without_base_dir():
    env = build_semgrep_env()
    assert env["HOME"].endswith("opensast-semgrep-home")
    assert os.path.isdir(env["HOME"])


def test_build_semgrep_env_sets_cert_paths_when_available(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
    monkeypatch.setitem(
        sys.modules,
        "certifi",
        SimpleNamespace(where=lambda: "/tmp/fake-ca-bundle.pem"),
    )

    env = build_semgrep_env()
    assert env["SSL_CERT_FILE"] == "/tmp/fake-ca-bundle.pem"
    assert env["REQUESTS_CA_BUNDLE"] == "/tmp/fake-ca-bundle.pem"


def test_build_semgrep_env_preserves_existing_cert_paths(monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", "/existing/cert.pem")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/existing/bundle.pem")

    env = build_semgrep_env()
    assert env["SSL_CERT_FILE"] == "/existing/cert.pem"
    assert env["REQUESTS_CA_BUNDLE"] == "/existing/bundle.pem"


def test_get_semgrep_binary_prefers_pysemgrep(monkeypatch):
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name: {
            "pysemgrep": "/usr/local/bin/pysemgrep",
            "semgrep": "/usr/local/bin/semgrep",
        }.get(name),
    )
    assert get_semgrep_binary() == "/usr/local/bin/pysemgrep"


def test_get_semgrep_binary_falls_back_to_semgrep(monkeypatch):
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name: "/usr/local/bin/semgrep" if name == "semgrep" else None,
    )
    assert get_semgrep_binary() == "/usr/local/bin/semgrep"


def test_get_semgrep_binary_returns_none_when_missing(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    assert get_semgrep_binary() is None


def test_run_semgrep_reports_missing_binary(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with tempfile.TemporaryDirectory() as tmpdir:
        result = run_semgrep("/tmp", tmpdir)
    assert result["tool"] == "semgrep"
    assert result["success"] is False
    assert "not installed" in (result["error_message"] or "")


@pytest.mark.skipif(not get_semgrep_binary(), reason="Semgrep not installed")
def test_get_semgrep_binary_returns_existing_installation():
    assert os.path.isfile(get_semgrep_binary() or "")


def test_rules_tree_has_no_stale_opensast_semgrep_home():
    rules_dir = os.path.join(
        os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "rules", "semgrep",
    )
    stale_home = os.path.join(rules_dir, ".opensast-semgrep-home")
    assert not os.path.isdir(stale_home), (
        f"Remove {stale_home} — Semgrep treats nested .semgrep/settings.yml as rule configs"
    )


@pytest.mark.skipif(not get_semgrep_binary(), reason="Semgrep not installed")
def test_build_semgrep_env_allows_version_check():
    semgrep_bin = get_semgrep_binary()
    assert semgrep_bin is not None
    import subprocess

    result = subprocess.run(
        [semgrep_bin, "--version"],
        capture_output=True,
        text=True,
        timeout=30,
        env=build_semgrep_env(),
    )
    assert result.returncode == 0
    assert result.stdout.strip()
