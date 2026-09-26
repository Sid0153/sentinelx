"""Building detection inputs by hand or from raw log lines, without a database."""

import random
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from app.core.client_ip import parse_networks
from app.detection.evaluate import evaluate
from app.detection.events import DetectionEvent
from app.detection.explain import build
from app.detection.library import get_library
from app.detection.model import Detection, Rule
from app.events.schema import NormalizedEvent, SourceType
from app.ingestion.enrich import ip_scope
from app.ingestion.parsers import ParseContext, parse_record

T0 = datetime(2026, 9, 25, 10, 0, 0, tzinfo=UTC)
INTERNAL = parse_networks("10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7")
_counter = iter(range(1, 10_000_000))


def rule(rule_id: str) -> Rule:
    return get_library().rules[rule_id]


def ev(seconds: float = 0, **fields: Any) -> DetectionEvent:
    """An event `seconds` after T0. Defaults: an SSH logon failure on web-01."""
    values: dict[str, Any] = {
        "id": f"e{next(_counter):07d}",
        "timestamp": T0 + timedelta(seconds=seconds),
        "source_type": "linux_auth",
        "event_category": "authentication",
        "event_action": "logon",
        "event_outcome": "failure",
        "host": "web-01",
        "username": "root",
        "source_ip": "203.0.113.45",
        "source_ip_scope": "external",
        "service": "sshd",
    }
    values.update(fields)
    return DetectionEvent(**values)


def failures(
    count: int, every: float = 10, start: float = 0, **fields: Any
) -> list[DetectionEvent]:
    return [ev(start + i * every, **fields) for i in range(count)]


def detect(rule_id: str, events: list[DetectionEvent], **kwargs: Any) -> list[Detection]:
    definition = rule(rule_id)
    return [build(definition, 1, m) for m in evaluate(definition, events, **kwargs)]


def from_normalized(normalized: NormalizedEvent, index: int) -> DetectionEvent:
    data = normalized.model_dump()
    return DetectionEvent(
        id=f"n{index:06d}",
        source_ip_scope=ip_scope(normalized.source_ip, INTERNAL),
        **{k: v for k, v in data.items() if k in DetectionEvent.__dataclass_fields__},
    )


def events_from_lines(source_type: SourceType, lines: list[str]) -> list[DetectionEvent]:
    """Parses raw records exactly as ingestion does and turns them into detection events."""
    context = ParseContext(received_at=T0 + timedelta(days=1), timezone=ZoneInfo("UTC"))
    parsed = [parse_record(source_type, line.encode(), context) for line in lines]
    normalized = [p for p in parsed if isinstance(p, NormalizedEvent)]
    return [from_normalized(n, i) for i, n in enumerate(normalized)]


def run_library(events: list[DetectionEvent]) -> dict[str, list[Detection]]:
    """Every library rule over the events (no history for new_value rules)."""
    results = {}
    for rule_id, definition in get_library().rules.items():
        found = [build(definition, 1, m) for m in evaluate(definition, events)]
        if found:
            results[rule_id] = found
    return results


def shuffled(events: list[DetectionEvent], seed: int = 7) -> list[DetectionEvent]:
    copy = list(events)
    random.Random(seed).shuffle(copy)  # noqa: S311  (test data order, not cryptography)
    return copy
