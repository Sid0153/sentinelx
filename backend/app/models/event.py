"""The event store: where records came from, what arrived, and what it means.

- LogSource: a configured origin ("web-01 auth.log"); decides the parser and the timezone.
- RawEvent: exactly what was received, for every record, even ones that failed to parse.
- Event: the normalized, enriched representation of one parsed raw record.

RawEvent and Event are append-only (database triggers, migration 0003): evidence is never
changed or removed by the application. See docs/event-model.md and docs/database-schema.md.
"""

import enum
import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.events.schema import (
    MAX_COMMAND_LINE,
    MAX_MESSAGE,
    Criticality,
    EventCategory,
    EventOutcome,
    IpScope,
    SourceType,
)

# Records are stored as the exact bytes received: log lines can hold NUL bytes or invalid
# UTF-8, which a PostgreSQL text column cannot, and evidence must not be silently altered.
MAX_RAW_BYTES = 65_536


class ParseStatus(enum.StrEnum):
    PARSED = "PARSED"
    FAILED = "FAILED"


def _check_in(column: str, values: type[enum.StrEnum], nullable: bool = False) -> str:
    listed = f"{column} IN ({', '.join(repr(v.value) for v in values)})"
    return f"({column} IS NULL OR {listed})" if nullable else listed


def _port_check(column: str) -> str:
    return f"{column} IS NULL OR {column} BETWEEN 0 AND 65535"


class LogSource(Base):
    __tablename__ = "log_sources"
    __table_args__ = (
        sa.CheckConstraint(_check_in("source_type", SourceType), name="source_type_valid"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(sa.String(100), unique=True)
    source_type: Mapped[str] = mapped_column(sa.String(32))
    description: Mapped[str | None] = mapped_column(sa.String(500))
    # Used when the record itself does not say: syslog lines name the host, but a JSON app
    # log may not; RFC 3164 syslog has no year and no zone.
    default_host: Mapped[str | None] = mapped_column(sa.String(253))
    timezone: Mapped[str] = mapped_column(sa.String(64), default="UTC")
    enabled: Mapped[bool] = mapped_column(default=True, server_default=sa.true())
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()
    )


class RawEvent(Base):
    __tablename__ = "raw_events"
    __table_args__ = (
        sa.CheckConstraint(_check_in("parse_status", ParseStatus), name="parse_status_valid"),
        sa.CheckConstraint(f"octet_length(raw_data) <= {MAX_RAW_BYTES}", name="raw_data_size"),
        # A failed record says why; a parsed one has no error.
        sa.CheckConstraint(
            "(parse_status = 'FAILED') = (parse_error IS NOT NULL)", name="parse_error_matches"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("log_sources.id"), index=True)
    received_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    raw_data: Mapped[bytes] = mapped_column(sa.LargeBinary)
    # sha256(source_id ‖ raw_data): the same record from the same source is stored once.
    fingerprint: Mapped[str] = mapped_column(sa.String(64), unique=True)
    parse_status: Mapped[str] = mapped_column(sa.String(8))
    parse_error: Mapped[str | None] = mapped_column(sa.String(64))  # a short code, not text
    simulated: Mapped[bool] = mapped_column(default=False, server_default=sa.false())

    @property
    def display_text(self) -> str:
        """For showing to people only: undecodable bytes become U+FFFD. Never for matching."""
        return self.raw_data.decode("utf-8", errors="replace")


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        sa.CheckConstraint(_check_in("source_type", SourceType), name="source_type_valid"),
        sa.CheckConstraint(_check_in("event_category", EventCategory), name="category_valid"),
        sa.CheckConstraint(_check_in("event_outcome", EventOutcome), name="outcome_valid"),
        sa.CheckConstraint(
            _check_in("source_ip_scope", IpScope, nullable=True), name="ip_scope_valid"
        ),
        sa.CheckConstraint(
            _check_in("asset_criticality", Criticality, nullable=True), name="criticality_valid"
        ),
        sa.CheckConstraint("event_action ~ '^[a-z][a-z_]{1,39}$'", name="action_format"),
        sa.CheckConstraint(_port_check("source_port"), name="source_port_range"),
        sa.CheckConstraint(_port_check("destination_port"), name="destination_port_range"),
        sa.CheckConstraint(f"length(command_line) <= {MAX_COMMAND_LINE}", name="command_line_size"),
        sa.CheckConstraint(f"length(message) <= {MAX_MESSAGE}", name="message_size"),
        sa.CheckConstraint("host = lower(host)", name="host_lowercase"),
        sa.CheckConstraint("username = lower(username)", name="username_lowercase"),
        # Indexes follow the queries we know we will run (docs/database-schema.md):
        # "value X in time range T", newest first, keyset-paginated on (timestamp, id).
        sa.Index("ix_events_timestamp_id", sa.text("timestamp DESC"), sa.text("id DESC")),
        sa.Index("ix_events_category_action_ts", "event_category", "event_action", "timestamp"),
        sa.Index("ix_events_source_ip_ts", "source_ip", "timestamp"),
        sa.Index("ix_events_destination_ip_ts", "destination_ip", "timestamp"),
        sa.Index("ix_events_username_ts", "username", "timestamp"),
        sa.Index("ix_events_host_ts", "host", "timestamp"),
        sa.Index(
            "ix_events_command_line_trgm",
            "command_line",
            postgresql_using="gin",
            postgresql_ops={"command_line": "gin_trgm_ops"},
        ),
        sa.Index(
            "ix_events_message_trgm",
            "message",
            postgresql_using="gin",
            postgresql_ops={"message": "gin_trgm_ops"},
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    raw_event_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("raw_events.id"), unique=True)
    source_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("log_sources.id"))
    source_type: Mapped[str] = mapped_column(sa.String(32))
    timestamp: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))  # event time
    ingested_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    host: Mapped[str | None] = mapped_column(sa.String(253))
    host_ip: Mapped[str | None] = mapped_column(INET)
    event_category: Mapped[str] = mapped_column(sa.String(32))
    event_action: Mapped[str] = mapped_column(sa.String(40))
    event_outcome: Mapped[str] = mapped_column(sa.String(8))
    username: Mapped[str | None] = mapped_column(sa.String(256))
    user_domain: Mapped[str | None] = mapped_column(sa.String(256))
    target_username: Mapped[str | None] = mapped_column(sa.String(256))
    source_ip: Mapped[str | None] = mapped_column(INET)
    source_port: Mapped[int | None] = mapped_column(sa.Integer)
    destination_ip: Mapped[str | None] = mapped_column(INET)
    destination_port: Mapped[int | None] = mapped_column(sa.Integer)
    protocol: Mapped[str | None] = mapped_column(sa.String(32))
    service: Mapped[str | None] = mapped_column(sa.String(128))
    process_name: Mapped[str | None] = mapped_column(sa.String(256))
    parent_process_name: Mapped[str | None] = mapped_column(sa.String(256))
    command_line: Mapped[str | None] = mapped_column(sa.Text)
    session_id: Mapped[str | None] = mapped_column(sa.String(128))
    message: Mapped[str | None] = mapped_column(sa.Text)
    attributes: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=sa.text("'{}'::jsonb")
    )

    # Enrichment (Phase 5). Criticality and privilege are snapshots taken at ingest time:
    # they show what was known when the event arrived (docs/event-model.md).
    source_ip_scope: Mapped[str | None] = mapped_column(sa.String(16))
    asset_id: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("assets.id"), index=True)
    asset_criticality: Mapped[str | None] = mapped_column(sa.String(16))
    identity_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("identities.id"), index=True
    )
    identity_privileged: Mapped[bool | None] = mapped_column(sa.Boolean)
    simulated: Mapped[bool] = mapped_column(default=False, server_default=sa.false())
