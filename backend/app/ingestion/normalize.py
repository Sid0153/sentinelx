"""Shared mapping helpers for parsers: the rules that make different sources look alike.

Pure functions. The canonical form itself (lowercase hosts, UTC, vocabulary) is enforced by
NormalizedEvent; these helpers turn each source's conventions into that form.
"""

import ipaddress
from datetime import UTC, datetime

# Windows and several tools write "-" or an empty string for "no value".
_EMPTY = {"", "-", "--", "n/a", "null", "none"}


def clean(value: object, max_length: int | None = None) -> str | None:
    """A stripped string, or None for empty placeholders. Truncated if max_length is given."""
    if value is None:
        return None
    text = str(value).strip()
    if text.lower() in _EMPTY:
        return None
    return text[:max_length] if max_length else text


def split_user(value: object) -> tuple[str | None, str | None]:
    """'CORP\\alice' or 'alice@corp.example' -> ('alice', 'corp' / 'corp.example').

    The original stays in the raw record; only the normalized copy is split and lowercased
    (by NormalizedEvent).
    """
    text = clean(value)
    if text is None:
        return None, None
    if "\\" in text:
        domain, _, user = text.rpartition("\\")
        return clean(user), clean(domain)
    if "@" in text:
        user, _, domain = text.partition("@")
        return clean(user), clean(domain)
    return text, None


def optional_ip(value: object) -> str | None:
    """A valid IP address or None. Placeholders ('-', '::1' is kept) and junk become None."""
    text = clean(value)
    if text is None:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def optional_port(value: object) -> int | None:
    text = clean(value)
    if text is None or not text.isdigit():
        return None
    port = int(text)
    return port if 0 <= port <= 65535 else None


def basename(path: object) -> str | None:
    """Process name from a Windows or Unix path: 'C:\\Windows\\cmd.exe' -> 'cmd.exe'."""
    text = clean(path)
    if text is None:
        return None
    return text.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or None


def parse_iso_timestamp(value: object) -> datetime:
    """ISO 8601 with a zone ('Z' or an offset). Fractions beyond microseconds are cut
    (Windows writes 7 digits). Raises ValueError without the input in the message."""
    text = clean(value)
    if text is None:
        raise ValueError("missing timestamp")
    text = text.replace("Z", "+00:00").replace("z", "+00:00")
    if "." in text:
        head, _, tail = text.partition(".")
        digits = len(tail) - len(tail.lstrip("0123456789"))
        fraction, zone = tail[:digits], tail[digits:]
        text = f"{head}.{fraction[:6].ljust(6, '0')}{zone}" if fraction else head + zone
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("timestamp has no time zone")
    return parsed.astimezone(UTC)
