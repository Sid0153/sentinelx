"""Log sources, ingestion, batch reports and the events they produced."""

import json
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query, Request, status
from pydantic import ValidationError
from sqlalchemy import func, select
from starlette.concurrency import run_in_threadpool

from app.alerts.queries import alerts_citing
from app.api.deps import DbSession, SettingsDep
from app.auth.deps import AdminUser, AnalystUser, CurrentUser
from app.core.errors import AppError
from app.events import queries
from app.events.schema import EventCategory, EventOutcome
from app.ingestion import sources as source_service
from app.ingestion.normalize import optional_ip
from app.ingestion.service import IngestRequest, ingest, reject
from app.models.event import BatchChannel, IngestionBatch, ParseStatus, RawEvent
from app.schemas.common import Page, error_responses
from app.schemas.ingestion import (
    AlertRef,
    BatchPublic,
    EventDetail,
    EventPage,
    EventPublic,
    IngestRecords,
    RawRecordPublic,
    SourceCreate,
    SourcePublic,
    SourceUpdate,
)

sources = APIRouter(prefix="/sources", tags=["sources"], responses=error_responses(401, 403))
ingestion = APIRouter(prefix="/ingest", tags=["ingest"], responses=error_responses(401, 403))
events = APIRouter(prefix="/events", tags=["events"], responses=error_responses(401, 403))

Limit = Annotated[int, Query(ge=1, le=200)]
Offset = Annotated[int, Query(ge=0)]


# ---------- sources ----------


@sources.get("", response_model=Page[SourcePublic])
def list_sources(
    _user: CurrentUser, db: DbSession, limit: Limit = 50, offset: Offset = 0
) -> Page[SourcePublic]:
    items, total = source_service.list_sources(db, limit, offset)
    return Page(
        items=[SourcePublic.model_validate(s) for s in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@sources.get("/{source_id}", response_model=SourcePublic, responses=error_responses(404))
def get_source(source_id: uuid.UUID, _user: CurrentUser, db: DbSession) -> SourcePublic:
    return SourcePublic.model_validate(source_service.get_source(db, source_id))


@sources.post(
    "",
    response_model=SourcePublic,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(409),
)
def create_source(payload: SourceCreate, admin: AdminUser, db: DbSession) -> SourcePublic:
    return SourcePublic.model_validate(source_service.create_source(db, payload, admin))


@sources.patch("/{source_id}", response_model=SourcePublic, responses=error_responses(404, 409))
def update_source(
    source_id: uuid.UUID, payload: SourceUpdate, admin: AdminUser, db: DbSession
) -> SourcePublic:
    """The source type is fixed after creation; disable a source with `enabled: false`."""
    return SourcePublic.model_validate(source_service.update_source(db, source_id, payload, admin))


# ---------- ingestion ----------


async def _read_body(request: Request, limit: int) -> bytes:
    """The request body, refusing more than `limit` bytes without reading it all first."""
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise AppError(413, f"The request body can be at most {limit} bytes")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise AppError(413, f"The request body can be at most {limit} bytes")
    return bytes(body)


def _split_records(request: Request, body: bytes) -> tuple[list[bytes], BatchChannel]:
    media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if media_type == "application/json":
        try:
            payload = IngestRecords.model_validate(json.loads(body))
        except (ValueError, ValidationError):
            raise AppError(
                422, 'Expected {"records": ["...", ...]} with at least one string record'
            ) from None
        return [record.encode("utf-8") for record in payload.records], BatchChannel.API
    if media_type == "text/plain":
        # One record per line; a trailing CR (Windows line endings) and blank lines are not
        # records.
        lines = (line.removesuffix(b"\r") for line in body.split(b"\n"))
        return [line for line in lines if line.strip()], BatchChannel.TEXT
    raise AppError(415, "Send application/json or text/plain")


@ingestion.post(
    "/{source_id}",
    response_model=BatchPublic,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(404, 409, 413, 415, 422),
)
async def ingest_records(
    source_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: DbSession,
    settings: SettingsDep,
) -> BatchPublic:
    """Store and normalize a batch of records for one log source (ANALYST+).

    - `application/json`: `{"records": ["<raw line or JSON text>", ...]}`
    - `text/plain`: one record per line (a log file as-is; NDJSON for JSON sources).

    At most INGEST_MAX_BYTES (5 MB) and INGEST_MAX_RECORDS (5,000 records) per request; each
    record at most 64 KiB. Records already stored for this source are counted as duplicates
    and not stored again, so resending a file is safe.
    """
    # The body is read here, on the event loop, with a size cap. The database work is
    # synchronous, so it runs in the thread pool instead of blocking other requests.
    source = await run_in_threadpool(source_service.get_source, db, source_id)
    try:
        body = await _read_body(request, settings.ingest_max_bytes)
        records, channel = _split_records(request, body)
    except AppError as error:
        await run_in_threadpool(reject, db, analyst, source.id, error.code)
        raise
    batch = await run_in_threadpool(
        ingest, db, IngestRequest(source, records, channel, analyst), settings
    )
    return BatchPublic.model_validate(batch)


def _batch(db: DbSession, batch_id: uuid.UUID) -> IngestionBatch:
    batch = db.get(IngestionBatch, batch_id)
    if batch is None:
        raise AppError(404, "Batch not found")
    return batch


@ingestion.get("/batches", response_model=Page[BatchPublic])
def list_batches(
    _user: CurrentUser,
    db: DbSession,
    source_id: uuid.UUID | None = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> Page[BatchPublic]:
    statement = select(IngestionBatch)
    if source_id is not None:
        statement = statement.where(IngestionBatch.source_id == source_id)
    total = db.scalar(select(func.count()).select_from(statement.subquery())) or 0
    rows = db.scalars(
        statement.order_by(IngestionBatch.created_at.desc()).limit(limit).offset(offset)
    )
    return Page(
        items=[BatchPublic.model_validate(b) for b in rows],
        total=int(total),
        limit=limit,
        offset=offset,
    )


@ingestion.get("/batches/{batch_id}", response_model=BatchPublic, responses=error_responses(404))
def get_batch(batch_id: uuid.UUID, _user: CurrentUser, db: DbSession) -> BatchPublic:
    return BatchPublic.model_validate(_batch(db, batch_id))


def raw_record(raw: RawEvent) -> RawRecordPublic:
    text = raw.display_text
    return RawRecordPublic(
        id=raw.id,
        batch_id=raw.batch_id,
        received_at=raw.received_at,
        parse_status=ParseStatus(raw.parse_status),
        parse_detail=raw.parse_detail,
        size_bytes=len(raw.raw_data),
        text=text[: queries.DISPLAY_LIMIT],
        truncated=len(text) > queries.DISPLAY_LIMIT,
        simulated=raw.simulated,
    )


@ingestion.get(
    "/batches/{batch_id}/records",
    response_model=Page[RawRecordPublic],
    responses=error_responses(404),
)
def list_batch_records(
    batch_id: uuid.UUID,
    _user: CurrentUser,
    db: DbSession,
    parse_status: ParseStatus | None = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> Page[RawRecordPublic]:
    """The stored raw records of a batch, e.g. `?parse_status=FAILED` to see what failed."""
    _batch(db, batch_id)
    rows, total = queries.list_batch_records(db, batch_id, parse_status, limit, offset)
    return Page(items=[raw_record(r) for r in rows], total=total, limit=limit, offset=offset)


# ---------- events ----------


@events.get("", response_model=EventPage, responses=error_responses(400))
def list_events(
    _user: CurrentUser,
    db: DbSession,
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    source_id: uuid.UUID | None = None,
    batch_id: uuid.UUID | None = None,
    category: EventCategory | None = None,
    action: Annotated[str | None, Query(max_length=40)] = None,
    outcome: EventOutcome | None = None,
    host: Annotated[str | None, Query(max_length=253)] = None,
    username: Annotated[str | None, Query(max_length=256)] = None,
    source_ip: Annotated[str | None, Query(max_length=45)] = None,
    limit: Limit = 50,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
) -> EventPage:
    """Normalized events, newest first (event time). The range defaults to the last 24 hours
    and can span at most 31 days. Filters match exactly (host and username case-insensitively).
    """
    if source_ip is not None and optional_ip(source_ip) is None:
        raise AppError(400, "source_ip must be an IP address")
    filters = queries.EventFilters(
        start, end, source_id, batch_id, category, action, outcome, host, username, source_ip
    )
    rows, next_cursor = queries.list_events(db, filters, limit, cursor)
    return EventPage(
        items=[EventPublic.model_validate(e) for e in rows], next_cursor=next_cursor, limit=limit
    )


@events.get("/{event_id}", response_model=EventDetail, responses=error_responses(404))
def get_event(event_id: uuid.UUID, _user: CurrentUser, db: DbSession) -> EventDetail:
    """One event with the raw record it came from, as received, and the alerts that cite
    it as evidence."""
    event, raw, source = queries.get_event(db, event_id)
    return EventDetail.model_validate(
        {
            **EventPublic.model_validate(event).model_dump(),
            "raw": raw_record(raw),
            "source_name": source.name,
            "alerts": [
                AlertRef(id=a.id, title=a.title, status=a.status, priority_band=a.priority_band)
                for a in alerts_citing(db, event.id)
            ],
        }
    )
