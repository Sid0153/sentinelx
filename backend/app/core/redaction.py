"""Best-effort removal of secrets from log text. Standard library only.

This is a safety net, not the control: code must not log secrets in the first place. It catches
the common accidents (a token in an exception message, a password inside a database URL).
"""

import re

REDACTED = "[REDACTED]"

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # JSON Web Tokens: three base64url segments, the first starting with "eyJ"
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), "[REDACTED_JWT]"),
    # Authorization header values
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*"), "Bearer " + REDACTED),
    # Credentials inside URLs: scheme://user:password@host
    (re.compile(r"(\b[a-z][a-z0-9+.-]*://[^:/@\s]+:)[^@\s]+@"), r"\1" + REDACTED + "@"),
    # key=value / "key": "value" for well-known secret names
    (
        re.compile(
            r"(?i)(\b(?:password|passwd|secret|secret_key|token|api[_-]?key|ingest[_-]?key)\b"
            r"[\"']?\s*[=:]\s*[\"']?)([^\s,\"'}]+)"
        ),
        r"\1" + REDACTED,
    ),
]


def redact(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text
