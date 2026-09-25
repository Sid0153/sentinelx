"""Structured logging.

Every line carries the request ID of the request that produced it. In JSON mode each line is one
JSON object, so values from logs (which can be attacker-controlled, e.g. a username from an
ingested event) cannot break the line structure. Structured values go in `fields`:

    logger.info("ingest.batch_stored", extra={"fields": {"batch_id": ..., "parsed": 120}})

All text, including field values and exception traces, passes through redaction.
"""

import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any, TextIO

from app.core.redaction import redact

# Set per request by RequestContextMiddleware so every log line can be tied to one request.
request_id_var: ContextVar[str] = ContextVar("request_id", default="-")
# The caller's address for the current request (None outside a request, e.g. the CLI).
# Audit records read both, so services do not need the request object passed in.
client_ip_var: ContextVar[str | None] = ContextVar("client_ip", default=None)


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {str(k): _redact_value(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_redact_value(v) for v in value]
    if value is None or isinstance(value, bool | int | float):
        return value
    return redact(str(value))


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "request_id": getattr(record, "request_id", "-"),
            "msg": redact(record.getMessage()),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            entry["fields"] = _redact_value(fields)
        if record.exc_info:
            entry["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(entry, ensure_ascii=False, default=str)


class TextFormatter(logging.Formatter):
    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)s [%(request_id)s] %(name)s: %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        line = super().format(record)
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            line += " " + json.dumps(_redact_value(fields), default=str)
        # %r-style escaping: a newline inside a logged value must not start a fake log line.
        return redact(line).replace("\r", "\\r").replace("\n", "\\n")


class CurrentStderrHandler(logging.StreamHandler[TextIO]):
    """Writes to whatever sys.stderr is when a record is emitted.

    A plain StreamHandler keeps the stream it was created with; if stderr is replaced later
    (test capture, a process manager) it would write to a stale or closed stream.
    """

    def emit(self, record: logging.LogRecord) -> None:
        self.stream = sys.stderr
        super().emit(record)


def configure_logging(level: str, fmt: str = "json") -> None:
    handler = CurrentStderrHandler()
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    handler.addFilter(RequestIdFilter())

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)

    # uvicorn's access log is replaced by our own request log line (see middleware), which
    # has the request ID and duration. Its other loggers go through the root handler.
    for name in ("uvicorn", "uvicorn.error"):
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers = []
        uvicorn_logger.propagate = True
    logging.getLogger("uvicorn.access").disabled = True
