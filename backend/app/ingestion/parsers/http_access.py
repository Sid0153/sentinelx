"""nginx / Apache "combined" access-log lines.

    203.0.113.9 - alice [25/Sep/2026:10:31:02 +0000] "GET /admin HTTP/1.1" 401 512 "-" "curl/8"

The access log does not name the web server, so the event's host is the log source's
default_host. A request line that is not "METHOD target PROTOCOL" (scanners sending TLS
handshakes or garbage to a plain-HTTP port) still becomes an event: that noise is often the
interesting part. Its first 256 characters are kept as `request_line`.
"""

import re
from datetime import datetime

from app.events.schema import EventCategory, EventOutcome, NormalizedEvent, SourceType
from app.ingestion.normalize import clean, optional_ip
from app.ingestion.parsers.base import ParseContext, ParseFailure, decode_utf8

_LINE = re.compile(
    r"^(?P<ip>\S{1,45}) (?P<ident>\S{1,256}) (?P<user>\S{1,256}) "
    r"\[(?P<time>[^\]]{1,40})\] "
    r'"(?P<request>(?:[^"\\]|\\.){0,8192})" (?P<status>\d{3}) (?P<bytes>\d{1,15}|-)'
    r'(?: "(?P<referrer>(?:[^"\\]|\\.){0,4096})" "(?P<agent>(?:[^"\\]|\\.){0,4096})")?'
    r"(?: .*)?$"
)
_REQUEST = re.compile(
    r"^(?P<method>[A-Z]{1,16}) (?P<target>\S{1,8192}) (?P<version>HTTP/\d(?:\.\d)?)$"
)


def _outcome(status: int) -> EventOutcome:
    # 2xx/3xx: the server did what was asked. 4xx/5xx: it did not (401/403 are the
    # authentication and authorization failures that rules care about).
    return EventOutcome.SUCCESS if status < 400 else EventOutcome.FAILURE


def parse(raw: bytes, context: ParseContext) -> NormalizedEvent:
    text = decode_utf8(raw).rstrip("\r\n")
    line = _LINE.match(text)
    if line is None:
        raise ParseFailure("unrecognized_format")
    try:
        timestamp = datetime.strptime(line["time"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        raise ParseFailure("invalid_timestamp") from None

    status = int(line["status"])
    attributes: dict[str, str | int | None] = {
        "http_status": status,
        "response_bytes": None if line["bytes"] == "-" else int(line["bytes"]),
        "referrer": clean(line["referrer"], 1024),
        "user_agent": clean(line["agent"], 1024),
    }
    request = _REQUEST.match(line["request"])
    if request:
        path, _, query = request["target"].partition("?")
        attributes |= {
            "http_method": request["method"],
            "url_path": path[:1024],
            "url_query": query[:1024] or None,
            "http_version": request["version"],
        }
        message = f"{request['method']} {path[:200]} {status}"
    else:
        attributes["request_line"] = line["request"][:256] or None
        message = f"malformed request {status}"

    return NormalizedEvent(
        timestamp=timestamp,
        source_type=SourceType.HTTP_ACCESS,
        event_category=EventCategory.WEB,
        event_action="http_request",
        event_outcome=_outcome(status),
        host=context.default_host,
        source_ip=optional_ip(line["ip"]),
        username=clean(line["user"]),
        protocol="http",
        service="http",
        message=message,
        attributes={k: v for k, v in attributes.items() if v is not None},
    )
