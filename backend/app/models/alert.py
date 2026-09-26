"""Alerts: what an analyst works on (docs/detection-engine.md, "Detection → alert").

- Alert: one per deduplication key while it is open. Detections with the same key (rule,
  indicator, grouped values) extend the open alert instead of creating another. The database
  enforces "one open alert per key" with a partial unique index. A closed alert is never
  reopened by the engine: new activity opens a new alert pointing to it (previous_alert_id).
- AlertEvent: the events an alert rests on. The primary key (alert_id, event_id) makes linking
  the same evidence twice impossible, so re-running detection changes nothing.
"""

import enum
import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


def _check_in(column: str, values: type[enum.StrEnum], nullable: bool = False) -> str:
    check = f"{column} IN ({', '.join(repr(v.value) for v in values)})"
    return f"({column} IS NULL OR {check})" if nullable else check


class AlertStatus(enum.StrEnum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


ACTIVE_STATUSES = (AlertStatus.NEW, AlertStatus.TRIAGED, AlertStatus.IN_PROGRESS)


class Disposition(enum.StrEnum):
    """Why a RESOLVED alert was closed (brief §45: confirmed / resolved)."""

    CONFIRMED_MALICIOUS = "confirmed_malicious"
    BENIGN_EXPECTED = "benign_expected"


class SeverityLevel(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConfidenceLevel(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


_ACTIVE_SQL = ", ".join(repr(s.value) for s in ACTIVE_STATUSES)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        sa.CheckConstraint(_check_in("status", AlertStatus), name="status_valid"),
        sa.CheckConstraint(_check_in("severity", SeverityLevel), name="severity_valid"),
        sa.CheckConstraint(_check_in("confidence", ConfidenceLevel), name="confidence_valid"),
        sa.CheckConstraint(_check_in("priority_band", SeverityLevel), name="priority_band_valid"),
        sa.CheckConstraint(
            _check_in("disposition", Disposition, nullable=True), name="disposition_valid"
        ),
        # A disposition belongs to RESOLVED and only to RESOLVED.
        sa.CheckConstraint(
            "(status = 'RESOLVED') = (disposition IS NOT NULL)", name="disposition_when_resolved"
        ),
        sa.CheckConstraint("priority_score BETWEEN 0 AND 100", name="priority_score_range"),
        sa.CheckConstraint("event_count >= 1", name="event_count_positive"),
        sa.CheckConstraint("first_event_at <= last_event_at", name="event_times_ordered"),
        sa.Index(
            "uq_alerts_dedup_key_active",
            "dedup_key",
            unique=True,
            postgresql_where=sa.text(f"status IN ({_ACTIVE_SQL})"),
        ),
        sa.Index("ix_alerts_status_priority", "status", sa.text("priority_score DESC")),
        sa.Index("ix_alerts_rule_created", "rule_id", "created_at"),
        sa.Index("ix_alerts_last_event_at", "last_event_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[str] = mapped_column(sa.ForeignKey("detection_rules.rule_id"))
    rule_version: Mapped[int]
    indicator: Mapped[str | None] = mapped_column(sa.String(40))
    kind: Mapped[str] = mapped_column(sa.String(16))
    category: Mapped[str] = mapped_column(sa.String(32))
    title: Mapped[str] = mapped_column(sa.String(300))
    description: Mapped[str] = mapped_column(sa.Text)  # what the rule looks for
    severity: Mapped[str] = mapped_column(sa.String(16))
    confidence: Mapped[str] = mapped_column(sa.String(16))
    status: Mapped[str] = mapped_column(sa.String(16), default=AlertStatus.NEW)
    disposition: Mapped[str | None] = mapped_column(sa.String(32))

    priority_score: Mapped[int]
    priority_band: Mapped[str] = mapped_column(sa.String(16))
    priority_breakdown: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    risk_model_version: Mapped[str] = mapped_column(sa.String(16))

    dedup_key: Mapped[str] = mapped_column(sa.String(64))
    group_values: Mapped[dict[str, Any]] = mapped_column(JSONB)
    # The main entities (brief §8), for filtering and for the queue.
    host: Mapped[str | None] = mapped_column(sa.String(253), index=True)
    username: Mapped[str | None] = mapped_column(sa.String(256), index=True)
    target_username: Mapped[str | None] = mapped_column(sa.String(256))
    source_ip: Mapped[str | None] = mapped_column(INET, index=True)
    destination_ip: Mapped[str | None] = mapped_column(INET)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("assets.id"), index=True)
    identity_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("identities.id"), index=True
    )

    first_event_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    last_event_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    event_count: Mapped[int]  # distinct events linked as evidence
    # True when more events matched than are linked (a detection's evidence list is capped,
    # and so is an alert's): event_count is then a lower bound.
    evidence_truncated: Mapped[bool] = mapped_column(default=False)
    peak_count: Mapped[int]  # largest evidence count of one detection (priority input)
    detection_count: Mapped[int] = mapped_column(default=1)  # detections merged into it

    explanation: Mapped[str] = mapped_column(sa.Text)  # from the latest detection
    facts: Mapped[dict[str, Any]] = mapped_column(JSONB)
    entities: Mapped[dict[str, list[str]]] = mapped_column(JSONB)
    investigation: Mapped[list[str]] = mapped_column(JSONB)
    response: Mapped[list[str]] = mapped_column(JSONB)
    mitre: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)  # snapshot: id, name, tactics
    history: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)  # each merged detection

    previous_alert_id: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("alerts.id"))
    simulated: Mapped[bool] = mapped_column(default=False)

    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    status_changed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    status_changed_by: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("users.id"))
    triaged_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    resolved_by: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("users.id"))
    # The note given with the latest status change (resolution, false positive, reopen);
    # every change with its note is in the audit log.
    status_note: Mapped[str | None] = mapped_column(sa.String(2000))


class AlertEvent(Base):
    __tablename__ = "alert_events"

    alert_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("alerts.id"), primary_key=True)
    # Indexed: "which alerts cite this event" (event page, correlation).
    event_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("events.id"), primary_key=True, index=True
    )
    linked_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
