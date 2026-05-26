"""Tests for CodeQL integration."""

import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "codeql_runner",
    os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools", "run_codeql.py"),
)
_codeql = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_codeql)

resolve_languages = _codeql._resolve_languages
detect_build_command = _codeql.detect_build_command
run_codeql = _codeql.run_codeql
is_repo_build_command = _codeql._is_repo_build_command
is_allowed_build_command = _codeql._is_allowed_build_command


# --- Language resolution ---


def test_resolve_languages_dedup():
    assert resolve_languages(["python", "Python", "python"]) == ["python"]


def test_resolve_languages_typescript_to_javascript():
    result = resolve_languages(["typescript", "javascript"])
    assert result == ["javascript"]


def test_resolve_languages_kotlin_to_java():
    result = resolve_languages(["kotlin", "java"])
    assert result == ["java"]


def test_resolve_languages_unsupported():
    assert resolve_languages(["brainfuck"]) == []


def test_resolve_languages_mixed():
    result = resolve_languages(["python", "go", "brainfuck"])
    assert result == ["python", "go"]


def test_resolve_languages_empty():
    assert resolve_languages([]) == []


# --- Build command detection ---


def test_detect_java_build_maven():
    with tempfile.TemporaryDirectory() as tmpdir:
        mvnw = os.path.join(tmpdir, "mvnw")
        with open(mvnw, "w") as f:
            f.write("#!/bin/sh\n")
        os.chmod(mvnw, 0o755)
        result = detect_build_command(tmpdir, "java")
        assert result is not None
        assert "mvnw" in result[0]


def test_detect_java_build_gradle():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "build.gradle"), "w") as f:
            f.write("plugins { id 'java' }")
        if shutil.which("gradle"):
            result = detect_build_command(tmpdir, "java")
            assert result is not None
            assert "gradle" in result[0]


def test_detect_java_build_none():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Falls back to checking global mvn/gradle
        result = detect_build_command(tmpdir, "java")
        if shutil.which("mvn"):
            assert result is not None
            assert "mvn" in result[0]
        else:
            assert result is None


def test_detect_go_build():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "go.mod"), "w") as f:
            f.write("module example.com/test\ngo 1.21")
        result = detect_build_command(tmpdir, "go")
        assert result is not None
        assert "go" in result[0]


def test_detect_cpp_build_cmake():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "CMakeLists.txt"), "w") as f:
            f.write("cmake_minimum_required(VERSION 3.10)\nproject(test)")
        result = detect_build_command(tmpdir, "cpp")
        assert result is not None
        assert "cmake" in result[0]


def test_detect_python_no_build():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert detect_build_command(tmpdir, "python") is None


def test_detect_javascript_no_build():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert detect_build_command(tmpdir, "javascript") is None


def test_repo_build_command_detection():
    assert is_repo_build_command(["./mvnw", "compile"])
    assert is_repo_build_command(["make"])
    assert is_repo_build_command(["cmake", "--build", "."])
    assert not is_repo_build_command(["mvn", "compile"])
    assert not is_repo_build_command(["go", "build", "./..."])


def test_allow_build_command_policy():
    assert is_allowed_build_command(
        ["mvn", "compile"],
        allow_package_manager_builds=True,
        allow_repo_build_commands=False,
    )
    assert not is_allowed_build_command(
        ["./gradlew", "compileJava"],
        allow_package_manager_builds=True,
        allow_repo_build_commands=False,
    )
    assert is_allowed_build_command(
        ["./gradlew", "compileJava"],
        allow_package_manager_builds=True,
        allow_repo_build_commands=True,
    )


# --- CodeQL not installed ---


def test_run_codeql_not_installed():
    if shutil.which("codeql"):
        return
    result = run_codeql(".", "/tmp/test_output")
    assert not result["success"]
    assert "not installed" in result.get("error_message", "")


# --- Query suite mapping ---


def test_query_suites_mapping():
    assert _codeql.QUERY_SUITES["quick"] == "security-extended"
    assert _codeql.QUERY_SUITES["standard"] == "security-extended"
    assert _codeql.QUERY_SUITES["deep"] == "security-and-quality"
