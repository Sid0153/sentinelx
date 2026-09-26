"""Incidents: related alerts grouped into one investigation (docs/correlation.md).

- Incident: the investigation. Entities (hosts, users, sources), time span, severity, risk,
  tactics and techniques are derived from its linked alerts and stored for listing and for
  finding candidate incidents quickly (GIN indexes on the entity arrays).
- IncidentAlert: which alert belongs to which incident and WHY (strength, shared entities, a
  sentence). An alert belongs to at most one incident (unique alert_id).
- IncidentNote, IncidentEvidence, IncidentActivity: the investigation record. Append-only
  (database triggers): a note is never edited, an unpin is a new row, and every change to
  the incident is an activity row.
- AppSetting: admin-configurable values (the correlation windows), audited.
"""

import enum
import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.models.alert import SeverityLevel


def _check_in(column: str, values: type[enum.StrEnum], nullable: bool = False) -> str:
    check = f"{column} IN ({', '.join(repr(v.value) for v in values)})"
    return f"({column} IS NULL OR {check})" if nullable else check


class IncidentStatus(enum.StrEnum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


# Incidents that still accept alerts.
ACTIVE_INCIDENT_STATUSES = (
    IncidentStatus.OPEN,
    IncidentStatus.TRIAGED,
    IncidentStatus.INVESTIGATING,
    IncidentStatus.CONTAINED,
)


class IncidentDisposition(enum.StrEnum):
    CONFIRMED_MALICIOUS = "confirmed_malicious"
    BENIGN_EXPECTED = "benign_expected"
    FALSE_POSITIVE = "false_positive"


class LinkStrength(enum.StrEnum):
    STRONG = "STRONG"
    MEDIUM = "MEDIUM"
    WEAK = "WEAK"
    MANUAL = "MANUAL"  # linked by an analyst
    ORIGIN = "ORIGIN"  # the alert that opened the incident


class LinkSource(enum.StrEnum):
    ENGINE = "engine"
    ANALYST = "analyst"


class EvidenceTag(enum.StrEnum):
    INITIAL_ACCESS = "initial_access"
    PRIVILEGE = "privilege"
    PERSISTENCE = "persistence"
    BENIGN = "benign"
    NEEDS_REVIEW = "needs_review"


class EvidenceAction(enum.StrEnum):
    PIN = "PIN"
    UNPIN = "UNPIN"


class ActivityKind(enum.StrEnum):
    CREATED = "CREATED"
    LINK = "LINK"
    UNLINK = "UNLINK"
    STATUS = "STATUS"
    ASSIGN = "ASSIGN"
    NOTE = "NOTE"
    EVIDENCE = "EVIDENCE"
    RENAME = "RENAME"


_ACTIVE_SQL = ", ".join(repr(s.value) for s in ACTIVE_INCIDENT_STATUSES)


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        sa.CheckConstraint(_check_in("status", IncidentStatus), name="status_valid"),
        sa.CheckConstraint(_check_in("severity", SeverityLevel), name="severity_valid"),
        sa.CheckConstraint(_check_in("risk_band", SeverityLevel), name="risk_band_valid"),
        sa.CheckConstraint(
            _check_in("disposition", IncidentDisposition, nullable=True), name="disposition_valid"
        ),
        # Resolved and closed incidents say how they ended; open ones do not.
        sa.CheckConstraint(
            "(status IN ('RESOLVED', 'CLOSED')) "
            "= (disposition IS NOT NULL AND resolution IS NOT NULL)",
            name="resolution_when_resolved",
        ),
        sa.CheckConstraint("risk_score BETWEEN 0 AND 100", name="risk_score_range"),
        sa.CheckConstraint("first_activity_at <= last_activity_at", name="activity_ordered"),
        sa.Index("ix_incidents_status_risk", "status", sa.text("risk_score DESC")),
        sa.Index("ix_incidents_last_activity_at", "last_activity_at"),
        sa.Index("ix_incidents_hosts", "hosts", postgresql_using="gin"),
        sa.Index("ix_incidents_usernames", "usernames", postgresql_using="gin"),
        sa.Index("ix_incidents_source_ips", "source_ips", postgresql_using="gin"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    # A short reference for people ("INC-42"); the UUID stays the key.
    number: Mapped[int] = mapped_column(sa.Identity(always=True), unique=True)
    title: Mapped[str] = mapped_column(sa.String(300))
    title_edited: Mapped[bool] = mapped_column(default=False)  # renamed by an analyst: kept
    summary: Mapped[str] = mapped_column(sa.Text)
    created_reason: Mapped[str] = mapped_column(sa.String(500))
    status: Mapped[str] = mapped_column(sa.String(16), default=IncidentStatus.OPEN)
    severity: Mapped[str] = mapped_column(sa.String(16))  # the highest of its alerts
    risk_score: Mapped[int]
    risk_band: Mapped[str] = mapped_column(sa.String(16))
    risk_breakdown: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    risk_model_version: Mapped[str] = mapped_column(sa.String(16))
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("users.id"), index=True)

    hosts: Mapped[list[str]] = mapped_column(ARRAY(sa.String(253)), default=list)
    usernames: Mapped[list[str]] = mapped_column(ARRAY(sa.String(256)), default=list)
    source_ips: Mapped[list[str]] = mapped_column(ARRAY(sa.String(45)), default=list)
    tactics: Mapped[list[str]] = mapped_column(ARRAY(sa.String(64)), default=list)
    techniques: Mapped[list[str]] = mapped_column(ARRAY(sa.String(16)), default=list)
    alert_count: Mapped[int] = mapped_column(default=0)
    first_activity_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    last_activity_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    simulated: Mapped[bool] = mapped_column(default=False)

    disposition: Mapped[str | None] = mapped_column(sa.String(32))
    resolution: Mapped[str | None] = mapped_column(sa.String(4000))
    resolved_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    resolved_by: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("users.id"))
    closed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    related_incident_id: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("incidents.id"))

    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"
    __table_args__ = (
        sa.CheckConstraint(_check_in("link_strength", LinkStrength), name="link_strength_valid"),
        sa.CheckConstraint(_check_in("link_source", LinkSource), name="link_source_valid"),
    )

    incident_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("incidents.id"), primary_key=True)
    # One incident per alert at most: the primary key column is also unique on its own.
    alert_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("alerts.id"), primary_key=True, unique=True
    )
    link_strength: Mapped[str] = mapped_column(sa.String(8))
    shared_entities: Mapped[list[str]] = mapped_column(JSONB)
    reason: Mapped[str] = mapped_column(sa.String(500))
    link_source: Mapped[str] = mapped_column(sa.String(8))
    linked_by: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("users.id"))
    linked_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))


class IncidentNote(Base):
    __tablename__ = "incident_notes"
    __table_args__ = (
        sa.CheckConstraint("char_length(body) BETWEEN 1 AND 10000", name="body_length"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("incidents.id"), index=True)
    author_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("users.id"))
    body: Mapped[str] = mapped_column(sa.Text)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))


class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"
    __table_args__ = (
        sa.CheckConstraint(_check_in("tag", EvidenceTag), name="tag_valid"),
        sa.CheckConstraint(_check_in("action", EvidenceAction), name="action_valid"),
        sa.CheckConstraint("(event_id IS NULL) <> (alert_id IS NULL)", name="event_or_alert"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("incidents.id"), index=True)
    event_id: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("events.id"))
    alert_id: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("alerts.id"))
    tag: Mapped[str] = mapped_column(sa.String(16))
    comment: Mapped[str | None] = mapped_column(sa.String(1000))
    action: Mapped[str] = mapped_column(sa.String(8))
    actor_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))


class IncidentActivity(Base):
    __tablename__ = "incident_activity"
    __table_args__ = (sa.CheckConstraint(_check_in("kind", ActivityKind), name="kind_valid"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    # Insertion order: several entries share a timestamp (an incident and its first links are
    # written together), and the record must read in the order it happened.
    seq: Mapped[int] = mapped_column(sa.BigInteger, sa.Identity(always=True), unique=True)
    incident_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("incidents.id"), index=True)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("users.id"))  # None: engine
    kind: Mapped[str] = mapped_column(sa.String(16))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    value: Mapped[Any] = mapped_column(JSONB)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    updated_by: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("users.id"))
