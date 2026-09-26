"""What every parser receives and returns.

A parser is a pure function: (raw bytes, context) -> one outcome. No database, no clock (the
receive time comes in the context), no I/O. Each parser both parses its format and maps it to
the normalized event, using the shared helpers in `ingestion/normalize.py`.

Every record ends in exactly one of three outcomes, stored on its raw record:
- Parsed: a NormalizedEvent.
- Skipped: the record was understood, but carries no security event SentinelX models
  (for example sshd's "Connection closed ... [preauth]"). Kept as evidence, not an error.
- Failed: the record could not be understood (unknown format, invalid JSON, bad timestamp).

Reason codes are short fixed strings, never text copied from the record, so a failure report
cannot leak or echo attacker-controlled content.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

from app.events.schema import NormalizedEvent


@dataclass(frozen=True)
class ParseContext:
    received_at: datetime  # UTC; used for year inference in formats without a year
    timezone: ZoneInfo  # the log source's zone, for timestamps that carry none
    default_host: str | None = None  # for formats that do not name the host


class ParseFailure(Exception):
    """The record could not be understood. `code` is a short fixed reason."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Skipped:
    """Understood, deliberately not normalized. `code` says why."""

    code: str


ParseOutcome = NormalizedEvent | Skipped
Parser = Callable[[bytes, ParseContext], ParseOutcome]


def decode_utf8(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ParseFailure("not_utf8") from None
