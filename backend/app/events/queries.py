"""Read queries over the event store: the events list (keyset-paginated) and raw records.

Every events query is bounded by a time range of at most MAX_RANGE, which keeps it on the
time-leading indexes (docs/database-schema.md). Pagination is keyset on (timestamp, id): the
next page starts strictly after the last row seen, so pages are stable while new events arrive
and deep pages cost the same as the first.
"""

import base64
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import Select, and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.models.event import Event, LogSource, ParseStatus, RawEvent

MAX_RANGE = timedelta(days=31)
DEFAULT_RANGE = timedelta(hours=24)
DISPLAY_LIMIT = 4096  # characters of a raw record shown in lists and detail


@dataclass(frozen=True)
class EventFilters:
    start: datetime | None = None
    end: datetime | None = None
    source_id: uuid.UUID | None = None
    batch_id: uuid.UUID | None = None
    category: str | None = None
    action: str | None = None
    outcome: str | None = None
    host: str | None = None
    username: str | None = None
    source_ip: str | None = None


def time_range(filters: EventFilters, now: datetime) -> tuple[datetime, datetime]:
    end = filters.end or now
    start = filters.start or end - DEFAULT_RANGE
    if start >= end:
        raise AppError(400, "The time range is empty: 'from' must be before 'to'")
    if end - start > MAX_RANGE:
        raise AppError(400, "The time range can be at most 31 days")
    return start, end


def encode_cursor(event: Event) -> str:
    text = f"{event.timestamp.isoformat()}|{event.id}"
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        stamp, _, event_id = base64.urlsafe_b64decode(padded).decode().partition("|")
        parsed = datetime.fromisoformat(stamp)
        if parsed.tzinfo is None:
            raise ValueError
        return parsed, uuid.UUID(event_id)
    except (ValueError, UnicodeDecodeError):
        raise AppError(400, "Invalid cursor") from None


def _filtered(filters: EventFilters, start: datetime, end: datetime) -> Select[tuple[Event]]:
    statement = select(Event).where(Event.timestamp >= start, Event.timestamp <= end)
    if filters.batch_id is not None:
        statement = statement.join(RawEvent, RawEvent.id == Event.raw_event_id).where(
            RawEvent.batch_id == filters.batch_id
        )
    for column, value in (
        (Event.source_id, filters.source_id),
        (Event.event_category, filters.category),
        (Event.event_action, filters.action),
        (Event.event_outcome, filters.outcome),
        (Event.host, filters.host.lower() if filters.host else None),
        (Event.username, filters.username.lower() if filters.username else None),
        (Event.source_ip, filters.source_ip),
    ):
        if value is not None:
            statement = statement.where(column == value)
    return statement


def list_events(
    db: Session, filters: EventFilters, limit: int, cursor: str | None, now: datetime | None = None
) -> tuple[list[Event], str | None]:
    start, end = time_range(filters, now or datetime.now(UTC))
    statement = _filtered(filters, start, end)
    if cursor:
        after_time, after_id = decode_cursor(cursor)
        statement = statement.where(
            or_(
                Event.timestamp < after_time,
                and_(Event.timestamp == after_time, Event.id < after_id),
            )
        )
    rows = list(
        db.scalars(statement.order_by(Event.timestamp.desc(), Event.id.desc()).limit(limit + 1))
    )
    has_more = len(rows) > limit
    rows = rows[:limit]
    return rows, encode_cursor(rows[-1]) if has_more and rows else None


def get_event(db: Session, event_id: uuid.UUID) -> tuple[Event, RawEvent, LogSource]:
    row = db.execute(
        select(Event, RawEvent, LogSource)
        .join(RawEvent, RawEvent.id == Event.raw_event_id)
        .join(LogSource, LogSource.id == Event.source_id)
        .where(Event.id == event_id)
    ).first()
    if row is None:
        raise AppError(404, "Event not found")
    return row[0], row[1], row[2]


def list_batch_records(
    db: Session, batch_id: uuid.UUID, status: ParseStatus | None, limit: int, offset: int
) -> tuple[list[RawEvent], int]:
    statement = select(RawEvent).where(RawEvent.batch_id == batch_id)
    if status is not None:
        statement = statement.where(RawEvent.parse_status == status)
    total = db.scalar(select(func.count()).select_from(statement.subquery())) or 0
    rows = db.scalars(
        statement.order_by(RawEvent.received_at, RawEvent.id).limit(limit).offset(offset)
    )
    return list(rows), int(total)
