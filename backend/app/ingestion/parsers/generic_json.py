"""Events already written in SentinelX's own field names (NormalizedEvent), one JSON object
per record. For shippers that map their data themselves, and for process and network
telemetry (PROC-001 / NET-001 sample data).

    {"timestamp": "2026-09-25T10:31:02Z", "event_category": "network",
     "event_action": "connection", "event_outcome": "success", "host": "ws-042",
     "source_ip": "10.0.2.42", "destination_ip": "10.0.1.20", "destination_port": 445}

`source_type` is set by SentinelX, never taken from the record. Validation errors fail the
record with a fixed code; the offending values are never echoed.
"""

from pydantic import ValidationError

from app.events.schema import NormalizedEvent, SourceType
from app.ingestion.parsers.base import ParseContext, ParseFailure
from app.ingestion.parsers.json_common import load_object


def parse(raw: bytes, context: ParseContext) -> NormalizedEvent:
    record = load_object(raw)
    record.pop("source_type", None)
    record.pop("event_id", None)  # a sender's own ID stays in the raw record (and fingerprint)
    if not record.get("host") and context.default_host:
        record["host"] = context.default_host
    try:
        return NormalizedEvent(source_type=SourceType.GENERIC_JSON, **record)
    except ValidationError:
        raise ParseFailure("invalid_event") from None
    except TypeError:  # keys that are not valid argument names
        raise ParseFailure("invalid_event") from None
