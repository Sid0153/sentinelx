import json
import logging
import sys

import pytest

from app.core.logging import JsonFormatter, TextFormatter, configure_logging, request_id_var
from app.core.redaction import redact

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"


def make_record(
    msg: str, *args: object, fields: dict[str, object] | None = None
) -> logging.LogRecord:
    record = logging.LogRecord("test.logger", logging.INFO, __file__, 1, msg, args, None)
    record.request_id = "req-12345678"
    if fields is not None:
        record.fields = fields
    return record


def test_json_line_has_the_expected_structure() -> None:
    line = JsonFormatter().format(make_record("ingest.batch_stored", fields={"parsed": 120}))
    entry = json.loads(line)
    assert entry["level"] == "INFO"
    assert entry["logger"] == "test.logger"
    assert entry["request_id"] == "req-12345678"
    assert entry["msg"] == "ingest.batch_stored"
    assert entry["fields"] == {"parsed": 120}
    assert entry["ts"].endswith("+00:00")


def test_attacker_controlled_newlines_stay_inside_one_json_line() -> None:
    # A username taken from a log line could contain a newline and a fake log entry.
    hostile = 'bob\n{"level": "INFO", "msg": "forged"}'
    line = JsonFormatter().format(make_record("login %s", hostile, fields={"user": hostile}))
    assert "\n" not in line
    assert json.loads(line)["fields"]["user"] == hostile


def test_text_format_escapes_newlines() -> None:
    line = TextFormatter().format(make_record("user %s", "a\nb"))
    assert "\n" not in line
    assert "a\\nb" in line


def test_secrets_in_message_fields_and_exceptions_are_redacted() -> None:
    record = make_record(
        "token=%s", "abc123", fields={"auth": f"Bearer {JWT}", "nested": {"password": "x"}}
    )
    try:
        raise RuntimeError("connect to postgresql+psycopg://sx:s3cr3t-pw@db:5432/sx failed")
    except RuntimeError:
        record.exc_info = sys.exc_info()
    line = JsonFormatter().format(record)
    for secret in ("abc123", JWT, "s3cr3t-pw"):
        assert secret not in line
    assert "[REDACTED]" in line


@pytest.mark.parametrize(
    ("text", "leaked"),
    [
        (f"header Authorization: Bearer {JWT}", JWT),
        ("postgresql+psycopg://user:pa55word@host/db", "pa55word"),
        ('{"password": "hunter2"}', "hunter2"),
        ("api_key=k-123456", "k-123456"),
        ("ingest-key: ik_abcdef", "ik_abcdef"),
    ],
)
def test_redact_removes_common_secret_shapes(text: str, leaked: str) -> None:
    assert leaked not in redact(text)


def test_redact_leaves_ordinary_text_alone() -> None:
    text = "Failed password for invalid user admin from 203.0.113.9 port 50412 ssh2"
    assert redact(text) == text


def test_configure_logging_emits_json_with_the_current_request_id(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging("INFO", "json")
    token = request_id_var.set("req-abcdefgh")
    try:
        logging.getLogger("sentinelx.test").info("hello", extra={"fields": {"n": 1}})
    finally:
        request_id_var.reset(token)
    entry = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
    assert entry["request_id"] == "req-abcdefgh"
    assert entry["fields"] == {"n": 1}
    assert logging.getLogger("uvicorn.access").disabled is True
