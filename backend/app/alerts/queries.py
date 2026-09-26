"""Reading alerts: the queue, one alert's evidence, related alerts and status history."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from sqlalchemy import ColumnElement, and_, func, or_, select
from sqlalchemy.orm import Session

from app.audit.events import AuditAction, EntityType
from app.core.errors import AppError
from app.models.alert import Alert, AlertEvent
from app.models.audit_log import AuditLog
from app.models.event import Event, RawEvent

RELATED_WINDOW = timedelta(hours=24)
MAX_RELATED = 20

Sort = Literal["priority", "recent"]


@dataclass(frozen=True)
class AlertFilters:
    status: list[str] = field(default_factory=list)
    severity: list[str] = field(default_factory=list)
    band: list[str] = field(default_factory=list)
    rule_id: str | None = None
    host: str | None = None
    username: str | None = None
    source_ip: str | None = None
    since: datetime | None = None  # last event at or after
    until: datetime | None = None  # first event at or before
    sort: Sort = "priority"


def _conditions(filters: AlertFilters) -> list[ColumnElement[bool]]:
    found: list[ColumnElement[bool]] = []
    if filters.status:
        found.append(Alert.status.in_(filters.status))
    if filters.severity:
        found.append(Alert.severity.in_(filters.severity))
    if filters.band:
        found.append(Alert.priority_band.in_(filters.band))
    if filters.rule_id:
        found.append(Alert.rule_id == filters.rule_id)
    if filters.host:
        found.append(Alert.host == filters.host.lower())
    if filters.username:
        found.append(Alert.username == filters.username.lower())
    if filters.source_ip:
        found.append(Alert.source_ip == filters.source_ip)
    if filters.since:
        found.append(Alert.last_event_at >= filters.since)
    if filters.until:
        found.append(Alert.first_event_at <= filters.until)
    return found


def list_alerts(
    db: Session, filters: AlertFilters, limit: int, offset: int
) -> tuple[list[Alert], int]:
    where = _conditions(filters)
    total = db.scalar(select(func.count()).select_from(Alert).where(*where)) or 0
    order = (
        (Alert.priority_score.desc(), Alert.last_event_at.desc(), Alert.id)
        if filters.sort == "priority"
        else (Alert.last_event_at.desc(), Alert.id)
    )
    rows = db.scalars(select(Alert).where(*where).order_by(*order).limit(limit).offset(offset))
    return list(rows), int(total)


def get_alert(db: Session, alert_id: uuid.UUID) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise AppError(404, "Alert not found")
    return alert


def evidence(
    db: Session, alert_id: uuid.UUID, limit: int, offset: int
) -> tuple[list[tuple[Event, RawEvent]], int]:
    """The alert's evidence events in time order, each with its raw record."""
    linked = select(AlertEvent.event_id).where(AlertEvent.alert_id == alert_id)
    total = db.scalar(select(func.count()).where(AlertEvent.alert_id == alert_id)) or 0
    rows = db.execute(
        select(Event, RawEvent)
        .join(RawEvent, RawEvent.id == Event.raw_event_id)
        .where(Event.id.in_(linked))
        .order_by(Event.timestamp, Event.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return [(event, raw) for event, raw in rows], int(total)


def related(db: Session, alert: Alert) -> list[tuple[Alert, list[str]]]:
    """Other alerts sharing a host, user or source address within a day of this one.
    (Correlation into incidents, with a stated reason per link, is Phase 8.)"""
    shared: list[tuple[str, ColumnElement[bool]]] = []
    if alert.host:
        shared.append((f"host {alert.host}", Alert.host == alert.host))
    if alert.username:
        shared.append((f"user {alert.username}", Alert.username == alert.username))
    if alert.source_ip:
        shared.append((f"source {alert.source_ip}", Alert.source_ip == str(alert.source_ip)))
    if not shared:
        return []
    candidates = db.scalars(
        select(Alert)
        .where(
            Alert.id != alert.id,
            or_(*(condition for _, condition in shared)),
            and_(
                Alert.last_event_at >= alert.first_event_at - RELATED_WINDOW,
                Alert.first_event_at <= alert.last_event_at + RELATED_WINDOW,
            ),
        )
        .order_by(Alert.priority_score.desc(), Alert.last_event_at.desc())
        .limit(MAX_RELATED)
    )
    result = []
    for other in candidates:
        labels = []
        if alert.host and other.host == alert.host:
            labels.append(f"host {alert.host}")
        if alert.username and other.username == alert.username:
            labels.append(f"user {alert.username}")
        if alert.source_ip and str(other.source_ip) == str(alert.source_ip):
            labels.append(f"source {alert.source_ip}")
        result.append((other, labels))
    return result


def activity(db: Session, alert_id: uuid.UUID) -> list[dict[str, Any]]:
    """Status changes of the alert, oldest first, from the audit log (the one record of
    who did what; the alert row only keeps the latest state)."""
    entries = db.scalars(
        select(AuditLog)
        .where(
            AuditLog.action == str(AuditAction.ALERT_STATUS_CHANGED),
            AuditLog.entity_type == str(EntityType.ALERT),
            AuditLog.entity_id == str(alert_id),
        )
        .order_by(AuditLog.occurred_at, AuditLog.id)
    )
    return [
        {
            "at": entry.occurred_at,
            "actor": entry.actor_label,
            "from_status": entry.details.get("from"),
            "to_status": entry.details.get("to"),
            "disposition": entry.details.get("disposition"),
            "reason": entry.details.get("reason"),
        }
        for entry in entries
    ]


def alerts_citing(db: Session, event_id: uuid.UUID) -> list[Alert]:
    return list(
        db.scalars(
            select(Alert)
            .join(AlertEvent, AlertEvent.alert_id == Alert.id)
            .where(AlertEvent.event_id == event_id)
            .order_by(Alert.created_at)
        )
    )
