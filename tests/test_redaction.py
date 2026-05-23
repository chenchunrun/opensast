"""Tests for secret redaction functionality."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "sast-scan", "tools"))

from redact import redact_findings, redact_markdown, redact_sarif, redact_secrets


def test_redact_aws_key():
    text = "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE"
    result = redact_secrets(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in result
    assert "[REDACTED" in result


def test_redact_github_token():
    text = "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    result = redact_secrets(text)
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" not in result
    assert "[REDACTED" in result


def test_redact_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    result = redact_secrets(text)
    assert "RSA PRIVATE KEY" not in result
    assert "[REDACTED" in result


def test_redact_bearer_token():
    text = 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456'
    result = redact_secrets(text)
    assert "eyJhbGciOiJIUzI1NiJ9" not in result


def test_redact_preserves_normal_text():
    text = "This is a normal line of code without secrets."
    result = redact_secrets(text)
    assert result == text


def test_redact_findings():
    findings = [{
        "title": "Secret detected",
        "message": "Found AWS key AKIAIOSFODNN7EXAMPLE in config",
        "evidence": {"source": "key=AKIAIOSFODNN7EXAMPLE", "sink": "", "dataflow": []},
    }]
    result = redact_findings(findings)
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(result)


def test_redact_markdown_report():
    content = "# Report\n\nFound secret: AKIAIOSFODNN7EXAMPLE in code"
    result = redact_markdown(content)
    assert "AKIAIOSFODNN7EXAMPLE" not in result


def test_redact_sarif():
    sarif = {
        "$schema": "https://example.com/sarif",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "test"}},
            "results": [{
                "message": {"text": "Found AKIAIOSFODNN7EXAMPLE"},
                "locations": [],
            }],
        }],
    }
    result = redact_sarif(sarif)
    dumped = json.dumps(result)
    assert "AKIAIOSFODNN7EXAMPLE" not in dumped
