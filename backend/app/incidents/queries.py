"""Reading incidents: the queue, the workspace data, and the timeline.

The timeline is built on request from stored rows, never kept as its own copy: the evidence
events of the linked alerts (each once), the alerts themselves, and the incident's activity,
merged in one query and paged by a keyset on (time, kind, id).
"""

import base64
import binascii
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from sqlalchemy import ColumnElement, String, cast, func, literal, or_, select, tuple_, union_all
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.models.alert import Alert, AlertEvent
from app.models.event import Event, RawEvent
from app.models.incident import (
    Incident,
    IncidentActivity,
    IncidentAlert,
    IncidentNote,
)
from app.models.user import User

Sort = Literal["risk", "recent"]


@dataclass(frozen=True)
class IncidentFilters:
    status: list[str] = field(default_factory=list)
    severity: list[str] = field(default_factory=list)
    assigned_to: uuid.UUID | None = None
    unassigned: bool = False
    host: str | None = None
    username: str | None = None
    source_ip: str | None = None
    sort: Sort = "risk"


def list_incidents(
    db: Session, filters: IncidentFilters, limit: int, offset: int
) -> tuple[list[Incident], int]:
    where: list[ColumnElement[bool]] = []
    if filters.status:
        where.append(Incident.status.in_(filters.status))
    if filters.severity:
        where.append(Incident.severity.in_(filters.severity))
    if filters.assigned_to:
        where.append(Incident.assigned_to == filters.assigned_to)
    if filters.unassigned:
        where.append(Incident.assigned_to.is_(None))
    if filters.host:
        where.append(Incident.hosts.contains([filters.host.lower()]))
    if filters.username:
        where.append(Incident.usernames.contains([filters.username.lower()]))
    if filters.source_ip:
        where.append(Incident.source_ips.contains([filters.source_ip]))
    total = db.scalar(select(func.count()).select_from(Incident).where(*where)) or 0
    order = (
        (Incident.risk_score.desc(), Incident.last_activity_at.desc(), Incident.number)
        if filters.sort == "risk"
        else (Incident.last_activity_at.desc(), Incident.number)
    )
    rows = db.scalars(select(Incident).where(*where).order_by(*order).limit(limit).offset(offset))
    return list(rows), int(total)


def get_incident(db: Session, incident_id: uuid.UUID) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise AppError(404, "Incident not found")
    return incident


def links(db: Session, incident_id: uuid.UUID) -> list[tuple[IncidentAlert, Alert]]:
    return [
        (link_row, alert)
        for link_row, alert in db.execute(
            select(IncidentAlert, Alert)
            .join(Alert, Alert.id == IncidentAlert.alert_id)
            .where(IncidentAlert.incident_id == incident_id)
            .order_by(Alert.first_event_at, Alert.last_event_at, Alert.rule_id, Alert.id)
        )
    ]


def notes(db: Session, incident_id: uuid.UUID) -> list[tuple[IncidentNote, str | None]]:
    return [
        (note, email)
        for note, email in db.execute(
            select(IncidentNote, User.email)
            .outerjoin(User, User.id == IncidentNote.author_id)
            .where(IncidentNote.incident_id == incident_id)
            .order_by(IncidentNote.created_at, IncidentNote.id)
        )
    ]


def activity(db: Session, incident_id: uuid.UUID) -> list[tuple[IncidentActivity, str | None]]:
    return [
        (row, email)
        for row, email in db.execute(
            select(IncidentActivity, User.email)
            .outerjoin(User, User.id == IncidentActivity.actor_id)
            .where(IncidentActivity.incident_id == incident_id)
            .order_by(IncidentActivity.created_at, IncidentActivity.seq)
        )
    ]


def mitre(alerts: list[Alert]) -> list[dict[str, Any]]:
    """Techniques across the incident's alerts, each with the rules that map to it."""
    found: dict[str, dict[str, Any]] = {}
    for alert in alerts:
        for technique in alert.mitre:
            entry = found.setdefault(
                technique["technique"],
                {
                    "technique": technique["technique"],
                    "name": technique["name"],
                    "tactics": technique["tactics"],
                    "attack_version": technique.get("attack_version", ""),
                    "reasons": [],
                    "rules": [],
                },
            )
            if alert.rule_id not in entry["rules"]:
                entry["rules"].append(alert.rule_id)
                entry["reasons"].append(technique["reason"])
    return sorted(found.values(), key=lambda t: t["technique"])


def response(alerts: list[Alert]) -> list[dict[str, Any]]:
    """Recommended response, grouped by finding and de-duplicated. Recommendations only:
    SentinelX never changes anything on monitored systems."""
    seen: set[str] = set()
    groups = []
    for alert in alerts:
        steps = [s for s in alert.response if s not in seen]
        seen.update(steps)
        if steps:
            groups.append({"rule_id": alert.rule_id, "title": alert.title, "steps": steps})
    return groups


# ---------- timeline ----------


def _encode(at: datetime, kind: str, ref: str) -> str:
    return base64.urlsafe_b64encode(f"{at.isoformat()}|{kind}|{ref}".encode()).decode()


def _decode(cursor: str) -> tuple[datetime, str, str]:
    try:
        at, kind, ref = base64.urlsafe_b64decode(cursor.encode()).decode().split("|")
        return datetime.fromisoformat(at), kind, ref
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise AppError(400, "Invalid cursor") from None


def timeline(
    db: Session, incident_id: uuid.UUID, limit: int, cursor: str | None
) -> tuple[list[dict[str, Any]], str | None]:
    linked = select(IncidentAlert.alert_id).where(IncidentAlert.incident_id == incident_id)
    evidence = select(AlertEvent.event_id).where(AlertEvent.alert_id.in_(linked))
    events = select(
        Event.timestamp.label("at"),
        literal("1event").label("kind"),
        cast(Event.id, String).label("ref"),
    ).where(Event.id.in_(evidence))
    alerts = select(
        Alert.created_at.label("at"),
        literal("2alert").label("kind"),
        cast(Alert.id, String).label("ref"),
    ).where(Alert.id.in_(linked))
    actions = select(
        IncidentActivity.created_at.label("at"),
        literal("3activity").label("kind"),
        func.lpad(cast(IncidentActivity.seq, String), 20, "0").label("ref"),
    ).where(IncidentActivity.incident_id == incident_id)
    merged = union_all(events, alerts, actions).subquery()
    statement = select(merged.c.at, merged.c.kind, merged.c.ref)
    if cursor:
        at, kind, ref = _decode(cursor)
        statement = statement.where(
            tuple_(merged.c.at, merged.c.kind, merged.c.ref)
            > tuple_(literal(at), literal(kind), literal(ref))
        )
    rows = db.execute(
        statement.order_by(merged.c.at, merged.c.kind, merged.c.ref).limit(limit + 1)
    ).all()
    page, more = rows[:limit], len(rows) > limit
    entries = _hydrate(db, incident_id, [(r.at, r.kind, r.ref) for r in page])
    next_cursor = _encode(*page[-1]) if more and page else None
    return entries, next_cursor


def _hydrate(
    db: Session, incident_id: uuid.UUID, keys: list[tuple[datetime, str, str]]
) -> list[dict[str, Any]]:
    ids = {
        kind: [uuid.UUID(ref) for _, k, ref in keys if k == kind] for kind in ("1event", "2alert")
    }
    sequence = [int(ref) for _, k, ref in keys if k == "3activity"]  # activity: by insertion
    events = {
        e.id: (e, raw)
        for e, raw in db.execute(
            select(Event, RawEvent)
            .join(RawEvent, RawEvent.id == Event.raw_event_id)
            .where(Event.id.in_(ids["1event"]))
        )
    }
    citing: dict[uuid.UUID, list[str]] = {}
    for event_id, rule_id in db.execute(
        select(AlertEvent.event_id, Alert.rule_id)
        .join(Alert, Alert.id == AlertEvent.alert_id)
        .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
        .where(IncidentAlert.incident_id == incident_id, AlertEvent.event_id.in_(ids["1event"]))
    ):
        citing.setdefault(event_id, []).append(rule_id)
    alerts = {a.id: a for a in db.scalars(select(Alert).where(Alert.id.in_(ids["2alert"])))}
    actions = {
        row.seq: (row, email)
        for row, email in db.execute(
            select(IncidentActivity, User.email)
            .outerjoin(User, User.id == IncidentActivity.actor_id)
            .where(IncidentActivity.seq.in_(sequence))
        )
    }
    entries: list[dict[str, Any]] = []
    for at, kind, ref in keys:
        if kind == "3activity":
            row, email = actions[int(ref)]
            entries.append(
                {
                    "at": at,
                    "kind": "activity",
                    "id": row.id,
                    "activity": {"kind": row.kind, "actor": email, "details": row.details},
                }
            )
            continue
        key = uuid.UUID(ref)
        if kind == "1event" and key in events:
            event, raw = events[key]
            entries.append(
                {
                    "at": at,
                    "kind": "event",
                    "id": key,
                    "event": {
                        "category": event.event_category,
                        "action": event.event_action,
                        "outcome": event.event_outcome,
                        "host": event.host,
                        "username": event.username,
                        "target_username": event.target_username,
                        "source_ip": str(event.source_ip) if event.source_ip else None,
                        "process_name": event.process_name,
                        "command_line": event.command_line,
                        "raw_text": raw.display_text[:1024],
                        "rules": sorted(set(citing.get(key, []))),
                        "simulated": event.simulated,
                    },
                }
            )
        elif kind == "2alert" and key in alerts:
            alert = alerts[key]
            entries.append(
                {
                    "at": at,
                    "kind": "alert",
                    "id": key,
                    "alert": {
                        "rule_id": alert.rule_id,
                        "title": alert.title,
                        "severity": alert.severity,
                        "priority_score": alert.priority_score,
                        "status": alert.status,
                    },
                }
            )
    return entries


def alert_incident(db: Session, alert_id: uuid.UUID) -> Incident | None:
    return db.scalar(
        select(Incident)
        .join(IncidentAlert, IncidentAlert.incident_id == Incident.id)
        .where(IncidentAlert.alert_id == alert_id)
    )


def assignees(db: Session) -> list[User]:
    """Who incidents can be assigned to: active analysts and admins."""
    return list(
        db.scalars(
            select(User)
            .where(User.is_active, or_(User.role == "ANALYST", User.role == "ADMIN"))
            .order_by(User.email)
        )
    )
