"""The ingestion pipeline for one batch (docs/architecture.md, ADR-0008):

    records -> duplicate check -> parse + normalize -> enrich -> store raw (+ event) -> report

One batch is one transaction: all its records are stored or none are. Every received record
ends in exactly one bucket (parsed, skipped, failed, duplicate or rejected) and the batch row
counts them; a database check makes the counts add up. Detection (Phase 6) will run after this
transaction commits, so a detection failure can never lose evidence.
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session

from app.audit.events import AuditAction, AuditResult, EntityType
from app.audit.service import record as audit
from app.core.config import Settings
from app.core.errors import AppError
from app.detection.engine import run_for_batch
from app.events.schema import NormalizedEvent, SourceType
from app.events.store import (
    add_event,
    add_raw_event,
    as_bytes,
    existing_fingerprints,
    fingerprint,
)
from app.ingestion.enrich import enrich, load_snapshot
from app.ingestion.parsers import ParseContext, Skipped, parse_record
from app.models.event import (
    MAX_RAW_BYTES,
    BatchChannel,
    BatchStatus,
    IngestionBatch,
    LogSource,
    ParseStatus,
    RawEvent,
)
from app.models.user import User

logger = logging.getLogger(__name__)

MAX_ISSUES = 50  # the batch report lists the first issues; counts are always exact


@dataclass(frozen=True)
class IngestRequest:
    source: LogSource
    records: list[bytes]
    channel: BatchChannel
    submitted_by: User | None
    simulated: bool = False
    detect: bool = True  # run detection after storing (tests may switch it off)


def reject(db: Session, actor: User | None, source_id: uuid.UUID | None, reason: str) -> None:
    """Audits a refused ingest request (nothing was stored). The caller raises the error."""
    audit(
        db,
        AuditAction.INGEST_REJECTED,
        result=AuditResult.FAILURE,
        actor=actor,
        entity_type=EntityType.LOG_SOURCE if source_id else None,
        entity_id=source_id,
        details={"reason": reason},
    )
    db.commit()


def ingest(db: Session, request: IngestRequest, settings: Settings) -> IngestionBatch:
    source = request.source
    if not source.enabled:
        reject(db, request.submitted_by, source.id, "source_disabled")
        raise AppError(409, "This log source is disabled")
    if len(request.records) > settings.ingest_max_records:
        reject(db, request.submitted_by, source.id, "too_many_records")
        raise AppError(413, f"At most {settings.ingest_max_records} records per request")

    now = datetime.now(UTC)
    batch = IngestionBatch(
        id=uuid.uuid4(),
        source_id=source.id,
        submitted_by=request.submitted_by.id if request.submitted_by else None,
        channel=request.channel,
        status=BatchStatus.STORED,
        received_count=len(request.records),
        simulated=request.simulated,
        created_at=now,
    )
    db.add(batch)
    counts = {status: 0 for status in ("parsed", "skipped", "failed", "duplicate", "rejected")}
    issues: list[dict[str, object]] = []

    def note(index: int, status: str, code: str) -> None:
        if len(issues) < MAX_ISSUES:
            issues.append({"index": index, "status": status, "code": code})

    def store(raw: bytes, status: ParseStatus, detail: str | None) -> RawEvent:
        return add_raw_event(
            db,
            source_id=source.id,
            batch_id=batch.id,
            raw=raw,
            status=status,
            detail=detail,
            simulated=request.simulated,
        )

    context = ParseContext(
        received_at=now, timezone=ZoneInfo(source.timezone), default_host=source.default_host
    )
    snapshot = load_snapshot(db, settings.internal_network_list)
    source_type = SourceType(source.source_type)
    records = [as_bytes(r) for r in request.records]
    already_stored = existing_fingerprints(db, [fingerprint(source.id, r) for r in records])
    seen: set[str] = set()
    event_times: list[datetime] = []
    # Events are added after every raw record is flushed: an event references its raw record,
    # and without ORM relationships the unit of work does not order the two tables itself.
    parsed: list[tuple[RawEvent, NormalizedEvent]] = []

    for index, raw in enumerate(records):
        if len(raw) > MAX_RAW_BYTES:
            # Cannot be stored without changing it, so it is refused and reported instead.
            counts["rejected"] += 1
            note(index, "REJECTED", "record_too_large")
            continue
        key = fingerprint(source.id, raw)
        if key in already_stored or key in seen:
            counts["duplicate"] += 1
            continue
        seen.add(key)

        outcome = parse_record(source_type, raw, context)
        if isinstance(outcome, NormalizedEvent):
            parsed.append((store(raw, ParseStatus.PARSED, None), outcome))
            counts["parsed"] += 1
            event_times.append(outcome.timestamp)
        elif isinstance(outcome, Skipped):
            store(raw, ParseStatus.SKIPPED, outcome.code)
            counts["skipped"] += 1
        else:
            store(raw, ParseStatus.FAILED, outcome.code)
            counts["failed"] += 1
            note(index, "FAILED", outcome.code)

    # The counts are final before the batch row is first written: a database check requires
    # them to add up to received_count.
    batch.parsed_count = counts["parsed"]
    batch.skipped_count = counts["skipped"]
    batch.failed_count = counts["failed"]
    batch.duplicate_count = counts["duplicate"]
    batch.rejected_count = counts["rejected"]
    batch.issues = issues
    if event_times:
        batch.first_event_at, batch.last_event_at = min(event_times), max(event_times)

    db.flush()  # the batch and all raw records (one batched INSERT per table)
    for stored, event in parsed:
        add_event(db, stored, event, enrich(event, snapshot))
    db.commit()  # the evidence is safe from here on, whatever happens to detection

    logger.info(
        "ingest.batch_stored",
        extra={
            "fields": {
                "batch_id": str(batch.id),
                "source_id": str(source.id),
                "channel": str(request.channel),
                "received": batch.received_count,
                **counts,
                "duration_ms": round((datetime.now(UTC) - now).total_seconds() * 1000, 1),
            }
        },
    )
    if request.detect:
        run_for_batch(db, batch)
    return batch
