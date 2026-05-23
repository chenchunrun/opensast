"""Redact secrets and sensitive data from reports and SARIF files."""

import re

_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_GITHUB_TOKEN = re.compile(r"ghp_[a-zA-Z0-9]{36}")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    r".*?"
    r"-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    re.DOTALL,
)
_BEARER_TOKEN = re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)
_CONN_STRING_PW = re.compile(
    r"(?:mongodb|mysql|postgres|postgresql|redis|mssql|sqlserver|amqp)"
    r"://[^:\s]+:([^\s@/]+)@",
    re.IGNORECASE,
)
_GENERIC_SECRET_ASSIGN = re.compile(
    r"""(?x)
    (?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|
        private[_-]?key|password|passwd|credentials?)
    \s*[=:]\s*
    ["']?
    ([A-Za-z0-9+/]{32,}={0,2})
    ["']?
    """,
    re.IGNORECASE,
)
_HEX_SECRET = re.compile(
    r"(?:key|secret|token|password|credential)\s*[=:]\s*['\"]?"
    r"([0-9a-fA-F]{32,})"
    r"['\"]?",
    re.IGNORECASE,
)


def redact_secrets(text: str) -> str:
    text = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", text)
    text = _AWS_KEY.sub("[REDACTED AWS KEY]", text)
    text = _GITHUB_TOKEN.sub("[REDACTED GITHUB TOKEN]", text)
    text = _BEARER_TOKEN.sub("Bearer [REDACTED]", text)

    def _redact_conn(m: re.Match) -> str:
        full = m.group(0)
        pw = m.group(1)
        return full.replace(pw, "[REDACTED]")

    text = _CONN_STRING_PW.sub(_redact_conn, text)

    def _redact_assign(m: re.Match) -> str:
        full = m.group(0)
        val = m.group(1)
        return full.replace(val, "[REDACTED]")

    text = _GENERIC_SECRET_ASSIGN.sub(_redact_assign, text)
    text = _HEX_SECRET.sub(_redact_assign, text)

    return text


def redact_sarif(sarif: dict) -> dict:
    sarif = _deep_copy(sarif)
    for run in sarif.get("runs", []):
        _redact_messages_in(run.get("invocations", []))
        for result in run.get("results", []):
            _redact_msg_obj(result.get("message", {}))
            for loc in result.get("locations", []):
                _redact_msg_obj(loc.get("message", {}))
                phys = loc.get("physicalLocation", {})
                _redact_msg_obj(phys.get("contextRegion", {}).get("message", {}))
                region = phys.get("region", {})
                snippet = region.get("snippet", {})
                if isinstance(snippet, dict):
                    _redact_msg_obj(snippet)
                elif isinstance(snippet, str):
                    region["snippet"] = {"text": redact_secrets(snippet)}
            for fix in result.get("fixes", []):
                _redact_msg_obj(fix.get("description", {}))
                for change in fix.get("artifactChanges", []):
                    for repl in change.get("replacements", []):
                        _redact_msg_obj(repl.get("deletedRegion", {}).get("message", {}))
        _redact_msg_obj(run.get("tool", {}).get("driver", {}).get("message", {}))
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            _redact_msg_obj(rule.get("shortDescription", {}))
            _redact_msg_obj(rule.get("fullDescription", {}))
            _redact_msg_obj(rule.get("help", {}))
    return sarif


def redact_findings(findings: list[dict]) -> list[dict]:
    redacted: list[dict] = []
    for f in findings:
        entry = _deep_copy(f)
        entry["message"] = redact_secrets(entry.get("message", ""))
        evidence = entry.get("evidence", {})
        if isinstance(evidence, dict):
            evidence["source"] = redact_secrets(evidence.get("source", ""))
            evidence["sink"] = redact_secrets(evidence.get("sink", ""))
            evidence["dataflow"] = [
                {**step, "snippet": redact_secrets(step.get("snippet", ""))}
                for step in evidence.get("dataflow", [])
            ]
        entry["recommendation"] = redact_secrets(entry.get("recommendation", ""))
        redacted.append(entry)
    return redacted


def redact_markdown(content: str) -> str:
    def _redact_code_block(m: re.Match) -> str:
        return m.group(1) + redact_secrets(m.group(2)) + m.group(3)

    content = re.sub(
        r"(`{3,}[\w]*\n)(.*?)(\n`{3,})",
        _redact_code_block,
        content,
        flags=re.DOTALL,
    )

    def _redact_inline(m: re.Match) -> str:
        return "`" + redact_secrets(m.group(1)) + "`"

    content = re.sub(r"`([^`]+)`", _redact_inline, content)
    content = redact_secrets(content)
    return content


def _redact_msg_obj(msg: dict) -> None:
    if not isinstance(msg, dict):
        return
    text = msg.get("text", "")
    if isinstance(text, str) and text:
        msg["text"] = redact_secrets(text)


def _redact_messages_in(items: list) -> None:
    for item in items:
        if isinstance(item, dict):
            _redact_msg_obj(item.get("message", {}))


def _deep_copy(obj):
    if isinstance(obj, dict):
        return {k: _deep_copy(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deep_copy(v) for v in obj]
    return obj
