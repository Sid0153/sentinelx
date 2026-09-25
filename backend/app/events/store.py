"""Writes and reads of the event store. The only code that inserts raw_events and events
(docs/architecture.md). Ingestion (Phase 5) calls these; nothing ever updates them.
"""

import hashlib
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.events.schema import Criticality, IpScope, NormalizedEvent
from app.models.event import Event, ParseStatus, RawEvent

_SEPARATOR = b"\x1f"  # cannot appear in a UUID's text form


def as_bytes(raw: bytes | str) -> bytes:
    """Text input (API JSON, file lines) is stored as its UTF-8 bytes."""
    return raw.encode("utf-8") if isinstance(raw, str) else raw


def fingerprint(source_id: uuid.UUID, raw: bytes | str) -> str:
    """Identity of a received record: the same bytes from the same source are one record.

    The same bytes from two sources are two observations, so the source is part of it. The
    separator cannot appear in a UUID, so (source, record) pairs cannot collide by
    concatenation.
    """
    return hashlib.sha256(str(source_id).encode() + _SEPARATOR + as_bytes(raw)).hexdigest()


@dataclass(frozen=True)
class Enrichment:
    """Context attached at ingest time (Phase 5). Every field is optional: unknown stays None."""

    source_ip_scope: IpScope | None = None
    asset_id: uuid.UUID | None = None
    asset_criticality: Criticality | None = None
    identity_id: uuid.UUID | None = None
    identity_privileged: bool | None = None


def find_raw_event(db: Session, source_id: uuid.UUID, raw: bytes | str) -> RawEvent | None:
    return db.scalar(select(RawEvent).where(RawEvent.fingerprint == fingerprint(source_id, raw)))


def add_raw_event(
    db: Session,
    source_id: uuid.UUID,
    raw: bytes | str,
    *,
    parse_error: str | None = None,
    simulated: bool = False,
) -> RawEvent:
    """Stores the record exactly as received. The caller checks for duplicates first
    (find_raw_event); the unique fingerprint index is the final guarantee."""
    record = RawEvent(
        source_id=source_id,
        raw_data=as_bytes(raw),
        fingerprint=fingerprint(source_id, raw),
        parse_status=ParseStatus.FAILED if parse_error else ParseStatus.PARSED,
        parse_error=parse_error,
        simulated=simulated,
    )
    db.add(record)
    db.flush()
    return record


def add_event(
    db: Session, raw: RawEvent, normalized: NormalizedEvent, enrichment: Enrichment | None = None
) -> Event:
    if raw.parse_status != ParseStatus.PARSED:
        raise ValueError("only a parsed raw record can have a normalized event")
    context = enrichment or Enrichment()
    event = Event(
        raw_event_id=raw.id,
        source_id=raw.source_id,
        simulated=raw.simulated,
        **normalized.model_dump(),
        source_ip_scope=context.source_ip_scope,
        asset_id=context.asset_id,
        asset_criticality=context.asset_criticality,
        identity_id=context.identity_id,
        identity_privileged=context.identity_privileged,
    )
    db.add(event)
    db.flush()
    return event
