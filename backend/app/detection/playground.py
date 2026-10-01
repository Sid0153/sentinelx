"""Detection testing playground (brief §44, Phase 12).

An analyst chooses a rule, pastes sample log lines, and sees whether the rule fires, why, on
which lines, and with which severity and confidence. It runs the real pipeline: the source's
parser, normalization, enrichment against the current inventory (read-only), the rule's own
exclusions and the same evaluator and explanation as production. Nothing is stored: no raw
records, no events, no alerts, no run. Optionally with "what-if" tuning values, checked
against the rule's bounds exactly like a real change, so a trial never uses a value a real
change would refuse.

Limits (documented in docs/detection-engine.md): the rule sees only the sample. A new-value
rule (AUTH-004) builds its history from earlier lines of the same sample, not from stored
events; the batch scoping and alert dedup of production runs do not apply.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import AppError
from app.detection.evaluate import evaluate
from app.detection.evaluators.common import excluded
from app.detection.events import DetectionEvent, sort_key
from app.detection.explain import build
from app.detection.model import Detection, Rule
from app.detection.storage import TunableValues, checked_values, effective, get_rule
from app.events.schema import NormalizedEvent, SourceType
from app.ingestion.enrich import enrich, load_snapshot
from app.ingestion.parsers import ParseContext, Skipped, parse_record

MAX_LINES = 500
MAX_LINE_BYTES = 8192
MAX_TOTAL_BYTES = 256 * 1024

_EVENT_FIELDS = (
    "timestamp",
    "source_type",
    "event_category",
    "event_action",
    "event_outcome",
    "host",
    "host_ip",
    "username",
    "user_domain",
    "target_username",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "protocol",
    "service",
    "process_name",
    "parent_process_name",
    "command_line",
    "session_id",
    "message",
    "attributes",
)


class PlaygroundRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_type: SourceType
    records: list[Annotated[str, Field(max_length=MAX_LINE_BYTES)]] = Field(
        min_length=1, max_length=MAX_LINES
    )
    timezone: str = Field(default="UTC", max_length=64)
    default_host: str | None = Field(default=None, max_length=253)
    changes: TunableValues | None = None  # what-if tuning, within the rule's bounds

    @field_validator("records")
    @classmethod
    def _sizes(cls, records: list[str]) -> list[str]:
        sizes = [len(r.encode()) for r in records]
        if any(size > MAX_LINE_BYTES for size in sizes):
            raise ValueError(f"each line is at most {MAX_LINE_BYTES} bytes")
        if sum(sizes) > MAX_TOTAL_BYTES:
            raise ValueError(f"the sample is at most {MAX_TOTAL_BYTES // 1024} KiB")
        return records

    @field_validator("timezone")
    @classmethod
    def _zone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("unknown time zone") from None
        return value


@dataclass
class LineResult:
    line: int  # 1-based, as the analyst numbers the sample
    status: str  # parsed, skipped, failed
    code: str | None = None
    event: DetectionEvent | None = None
    excluded: bool = False
    matched: bool | None = None  # passed the rule's condition (None: sequence rules)
    steps: list[str] = field(default_factory=list)  # sequence steps the event matches


@dataclass
class PlaygroundResult:
    rule: Rule
    version: int
    tried: dict[str, Any]  # the what-if values used (empty: the rule as it runs)
    lines: list[LineResult]
    detections: list[Detection]


def _event(index: int, normalized: NormalizedEvent, enrichment: Any) -> DetectionEvent:
    values: dict[str, Any] = {name: getattr(normalized, name) for name in _EVENT_FIELDS}
    for name in ("source_type", "event_category", "event_outcome"):
        values[name] = str(values[name])
    return DetectionEvent(
        id=f"line-{index}",
        source_ip_scope=str(enrichment.source_ip_scope) if enrichment.source_ip_scope else None,
        asset_criticality=(
            str(enrichment.asset_criticality) if enrichment.asset_criticality else None
        ),
        identity_privileged=enrichment.identity_privileged,
        **values,
    )


def run(
    db: Session, rule_id: str, request: PlaygroundRequest, settings: Settings
) -> PlaygroundResult:
    row = get_rule(db, rule_id)
    if not row.in_library:
        raise AppError(409, "This rule was removed from the library")
    rule = effective(row)
    tried: dict[str, Any] = {}
    if request.changes is not None:
        if request.changes.enabled is not None:
            raise AppError(400, "enabled does not apply to a test run: the rule always runs here")
        tried = checked_values(rule_id, rule, request.changes)
        rule = Rule.model_validate({**row.library_definition, **row.overrides, **tried})

    context = ParseContext(
        received_at=datetime.now(UTC),
        timezone=ZoneInfo(request.timezone),
        default_host=request.default_host,
    )
    snapshot = load_snapshot(db, settings.internal_network_list)
    lines: list[LineResult] = []
    for index, record in enumerate(request.records, start=1):
        outcome = parse_record(request.source_type, record.encode(), context)
        if isinstance(outcome, NormalizedEvent):
            event = _event(index, outcome, enrich(outcome, snapshot))
            lines.append(LineResult(index, "parsed", event=event))
        elif isinstance(outcome, Skipped):
            lines.append(LineResult(index, "skipped", outcome.code))
        else:
            lines.append(LineResult(index, "failed", outcome.code))

    events = [line.event for line in lines if line.event is not None]
    for line in lines:
        if line.event is None:
            continue
        line.excluded = excluded(line.event, rule.exclusions)
        if rule.steps:
            line.steps = [step.name for step in rule.steps if step.match.evaluate(line.event)]
        elif rule.match is not None:
            line.matched = rule.match.evaluate(line.event)
    matches = evaluate(rule, sorted(events, key=sort_key), {})
    return PlaygroundResult(
        rule=rule,
        version=row.version,
        tried=tried,
        lines=lines,
        detections=[build(rule, row.version, match) for match in matches],
    )
