import uuid
from datetime import datetime
from typing import Any, ClassVar, Self
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.events.schema import SourceType, canonical_hostname
from app.models.event import BatchChannel, BatchStatus, ParseStatus


def valid_timezone(value: str) -> str:
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError(
            "unknown time zone; use an IANA name such as 'UTC' or 'Europe/Berlin'"
        ) from None
    return value


# ---------- log sources ----------


class SourcePublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    source_type: SourceType
    description: str | None
    default_host: str | None
    timezone: str
    enabled: bool
    created_at: datetime
    updated_at: datetime


class SourceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    source_type: SourceType
    description: str | None = Field(default=None, max_length=500)
    default_host: str | None = Field(default=None, max_length=253)
    timezone: str = Field(default="UTC", max_length=64)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("name cannot be empty")
        return cleaned

    @field_validator("default_host")
    @classmethod
    def _host(cls, value: str | None) -> str | None:
        return canonical_hostname(value) if value else None

    @field_validator("timezone")
    @classmethod
    def _timezone(cls, value: str) -> str:
        return valid_timezone(value)


class SourceUpdate(BaseModel):
    """The source type cannot change: records already stored were parsed as that type.
    To parse a different format, create a new source."""

    model_config = ConfigDict(extra="forbid")
    CLEARABLE: ClassVar[frozenset[str]] = frozenset({"description", "default_host"})

    name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    default_host: str | None = Field(default=None, max_length=253)
    timezone: str | None = Field(default=None, max_length=64)
    enabled: bool | None = None

    @field_validator("default_host")
    @classmethod
    def _host(cls, value: str | None) -> str | None:
        return canonical_hostname(value) if value else None

    @field_validator("timezone")
    @classmethod
    def _timezone(cls, value: str | None) -> str | None:
        return None if value is None else valid_timezone(value)

    @model_validator(mode="after")
    def _fields(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("provide at least one field to change")
        for field in self.model_fields_set - self.CLEARABLE:
            if getattr(self, field) is None:
                raise ValueError(f"{field} cannot be empty")
        return self


# ---------- ingestion ----------


class IngestRecords(BaseModel):
    """JSON form of an ingest request: each record is the raw line or JSON text, as a string.

    Records are strings, not parsed objects, so the stored raw record is exactly what the
    sender produced (re-serializing an object would change its bytes).
    """

    model_config = ConfigDict(extra="forbid")

    records: list[str] = Field(min_length=1)


class BatchIssue(BaseModel):
    index: int
    status: str
    code: str


class BatchPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_id: uuid.UUID
    submitted_by: uuid.UUID | None
    channel: BatchChannel
    status: BatchStatus
    received_count: int
    parsed_count: int
    skipped_count: int
    failed_count: int
    duplicate_count: int
    rejected_count: int
    detection_count: int  # detections the batch's events took part in (Phase 6)
    issues: list[BatchIssue]
    first_event_at: datetime | None
    last_event_at: datetime | None
    simulated: bool
    created_at: datetime


class RawRecordPublic(BaseModel):
    """A stored raw record. `text` is for display only: undecodable bytes show as U+FFFD."""

    id: uuid.UUID
    batch_id: uuid.UUID
    received_at: datetime
    parse_status: ParseStatus
    parse_detail: str | None
    size_bytes: int
    text: str
    truncated: bool
    simulated: bool


# ---------- events ----------


class EventPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    raw_event_id: uuid.UUID
    source_id: uuid.UUID
    source_type: SourceType
    timestamp: datetime
    ingested_at: datetime
    host: str | None
    host_ip: str | None
    event_category: str
    event_action: str
    event_outcome: str
    username: str | None
    user_domain: str | None
    target_username: str | None
    source_ip: str | None
    source_port: int | None
    destination_ip: str | None
    destination_port: int | None
    protocol: str | None
    service: str | None
    process_name: str | None
    parent_process_name: str | None
    command_line: str | None
    session_id: str | None
    message: str | None
    attributes: dict[str, Any]
    source_ip_scope: str | None
    asset_id: uuid.UUID | None
    asset_criticality: str | None
    identity_id: uuid.UUID | None
    identity_privileged: bool | None
    simulated: bool

    @field_validator("host_ip", "source_ip", "destination_ip", mode="before")
    @classmethod
    def _ip_text(cls, value: object) -> str | None:
        return None if value is None else str(value)


class EventDetail(EventPublic):
    raw: RawRecordPublic
    source_name: str


class EventPage(BaseModel):
    """Keyset pagination: pass `next_cursor` back as `cursor` for the next (older) page.
    There is no total: counting a month of events on every page would be wasted work."""

    items: list[EventPublic]
    next_cursor: str | None
    limit: int
