"""Turns an evaluator match into a Detection with an explanation built from its evidence.

The explanation answers what happened, why the rule fired, which events, which entities, and
what to look at next (brief §7), using only facts computed from the evidence: counts, times,
spans, and the values the events share. There is no fixed prose disconnected from the data.

Text substitution uses string.Template: `$name` placeholders only, no attribute or index
access, so a value taken from a log can never reach into objects. Values from logs are
inserted as text; the UI renders them as text, never as HTML.
"""

from collections import Counter
from datetime import datetime, timedelta
from string import Template
from typing import Any

from app.detection.events import DetectionEvent
from app.detection.model import Detection, Match, Rule, format_duration

EVIDENCE_HEAD = 50
EVIDENCE_TAIL = 50
MAX_ENTITY_VALUES = 10
ENTITY_FIELDS = (
    "host",
    "username",
    "target_username",
    "source_ip",
    "destination_ip",
    "process_name",
)
# Facts every explanation may use. A value that differs across the evidence is shown as
# "several (N)" instead of picking one arbitrarily.
SHARED_FIELDS = (
    "host",
    "username",
    "target_username",
    "target_account",
    "source_ip",
    "source_ip_scope",
    "destination",
    "process_name",
    "command_line",
)


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def _shared(events: list[DetectionEvent], name: str, group: dict[str, Any]) -> str:
    if name in group:
        return str(group[name])
    values = {str(v) for e in events if (v := e.get(name)) not in (None, "")}
    if not values:
        return "unknown"
    if len(values) == 1:
        return values.pop()
    return f"several ({len(values)})"


def _entities(events: list[DetectionEvent]) -> dict[str, list[str]]:
    entities: dict[str, list[str]] = {}
    for name in ENTITY_FIELDS:
        counts = Counter(str(v) for e in events if (v := e.get(name)) not in (None, ""))
        if counts:
            entities[name] = [value for value, _ in counts.most_common(MAX_ENTITY_VALUES)]
    return entities


def _text(value: Any) -> str:
    if isinstance(value, timedelta):
        return format_duration(value)
    if isinstance(value, datetime):
        return _stamp(value)
    return str(value)


def evidence_ids(events: list[DetectionEvent]) -> list[str]:
    """The first 50 and last 50 events. The exact count is kept separately, and the full set
    is reachable by querying the detection's group and time span."""
    if len(events) <= EVIDENCE_HEAD + EVIDENCE_TAIL:
        return [e.id for e in events]
    return [e.id for e in events[:EVIDENCE_HEAD] + events[-EVIDENCE_TAIL:]]


def build(rule: Rule, version: int, match: Match) -> Detection:
    events: list[DetectionEvent] = match.events
    first, last = events[0].timestamp, events[-1].timestamp
    facts: dict[str, Any] = {
        "rule_id": rule.id,
        "rule_name": rule.name,
        "count": len(events),
        "first_seen": first,
        "last_seen": last,
        "span": last - first,
        **{name: _shared(events, name, match.group) for name in SHARED_FIELDS},
        **{
            f"attr_{key}": value
            for key, value in events[-1].attributes.items()
            if isinstance(value, str | int | float | bool)
        },
        **match.facts,
    }
    indicator = match.indicator
    if indicator is not None:
        facts["indicator"] = indicator.id
        facts["indicator_name"] = indicator.name
    text = {key: _text(value) for key, value in facts.items()}

    def fill(template: str) -> str:
        return Template(template).safe_substitute(text)

    return Detection(
        rule_id=rule.id,
        rule_name=rule.name,
        rule_version=version,
        kind=rule.kind,
        category=rule.category,
        severity=(indicator.severity if indicator and indicator.severity else rule.severity),
        confidence=(
            indicator.confidence if indicator and indicator.confidence else rule.confidence
        ),
        group=match.group,
        evidence_event_ids=evidence_ids(events),
        event_count=len(events),
        first_seen=first,
        last_seen=last,
        facts={key: _jsonable(value) for key, value in facts.items()},
        entities=_entities(events),
        indicator=indicator.id if indicator else None,
        mitre=list(indicator.mitre if indicator else rule.mitre),
        explanation=fill(rule.explanation),
        investigation=[fill(step) for step in rule.investigation],
        response=[fill(step) for step in rule.response],
        batch_ids=sorted({e.batch_id for e in events if e.batch_id}),
    )


def _jsonable(value: Any) -> Any:
    if isinstance(value, timedelta):
        return int(value.total_seconds())
    if isinstance(value, datetime):
        return value.isoformat()
    return value
