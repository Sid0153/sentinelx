"""What analysts do with incidents. Each action locks the incident row, writes an activity entry
(shown in the workspace) and an audit entry (the security record), and commits them together
with the change. Notes, evidence and activity are append-only in the database.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.events import AuditAction, EntityType
from app.audit.service import record
from app.core.errors import AppError
from app.incidents import records, workflow
from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import (
    ActivityKind,
    EvidenceAction,
    EvidenceTag,
    Incident,
    IncidentAlert,
    IncidentDisposition,
    IncidentEvidence,
    IncidentNote,
    IncidentStatus,
)
from app.models.user import Role, User

MAX_NOTE = 10_000


def _now() -> datetime:
    return datetime.now(UTC)


def _locked(db: Session, incident_id: uuid.UUID) -> Incident:
    incident = db.scalars(
        select(Incident).where(Incident.id == incident_id).with_for_update()
    ).first()
    if incident is None:
        raise AppError(404, "Incident not found")
    return incident


def _not_closed(incident: Incident) -> None:
    if incident.status == IncidentStatus.CLOSED:
        raise AppError(409, "A closed incident is final and cannot be changed")


def _audit(
    db: Session, action: AuditAction, actor: User, incident: Incident, **details: object
) -> None:
    record(
        db,
        action,
        actor=actor,
        entity_type=EntityType.INCIDENT,
        entity_id=incident.id,
        details={"number": incident.number, **details},
    )


def transition(
    db: Session,
    incident_id: uuid.UUID,
    target: IncidentStatus,
    disposition: IncidentDisposition | None,
    resolution: str | None,
    reason: str | None,
    actor: User,
) -> Incident:
    incident = _locked(db, incident_id)
    current = IncidentStatus(incident.status)
    try:
        workflow.check(current, target, disposition, resolution, reason)
    except workflow.TransitionError as exc:
        raise AppError(409, str(exc)) from exc
    except workflow.MissingInput as exc:
        raise AppError(400, str(exc)) from exc
    now = _now()
    incident.status = target
    incident.updated_at = now
    if target == IncidentStatus.RESOLVED:
        incident.disposition = disposition
        incident.resolution = resolution
        incident.resolved_at = now
        incident.resolved_by = actor.id
    elif target == IncidentStatus.CLOSED:
        incident.closed_at = now
    else:  # reopened or moved along while open
        incident.disposition = None
        incident.resolution = None
        incident.resolved_at = None
        incident.resolved_by = None
    details = {
        "from": str(current),
        "to": str(target),
        "disposition": str(disposition) if disposition else None,
        "resolution": resolution,
        "reason": reason,
    }
    records.activity(db, incident, ActivityKind.STATUS, details, now, actor)
    _audit(db, AuditAction.INCIDENT_STATUS_CHANGED, actor, incident, **details)
    db.commit()
    return incident


def assign(
    db: Session, incident_id: uuid.UUID, assignee_id: uuid.UUID | None, actor: User
) -> Incident:
    incident = _locked(db, incident_id)
    _not_closed(incident)
    assignee = None
    if assignee_id is not None:
        assignee = db.get(User, assignee_id)
        if assignee is None or not assignee.is_active or assignee.role == Role.VIEWER:
            raise AppError(400, "Incidents can be assigned to active analysts and admins only")
    previous = db.get(User, incident.assigned_to) if incident.assigned_to else None
    if (previous.id if previous else None) == (assignee.id if assignee else None):
        return incident
    now = _now()
    incident.assigned_to = assignee.id if assignee else None
    incident.updated_at = now
    details = {
        "from": previous.email if previous else None,
        "to": assignee.email if assignee else None,
    }
    records.activity(db, incident, ActivityKind.ASSIGN, details, now, actor)
    _audit(db, AuditAction.INCIDENT_ASSIGNED, actor, incident, **details)
    db.commit()
    return incident


def add_note(db: Session, incident_id: uuid.UUID, body: str, actor: User) -> IncidentNote:
    incident = _locked(db, incident_id)
    _not_closed(incident)
    text = body.strip()
    if not text or len(text) > MAX_NOTE:
        raise AppError(400, f"A note has 1 to {MAX_NOTE} characters")
    now = _now()
    note = IncidentNote(
        id=uuid.uuid4(), incident_id=incident.id, author_id=actor.id, body=text, created_at=now
    )
    db.add(note)
    incident.updated_at = now
    records.activity(db, incident, ActivityKind.NOTE, {"note_id": str(note.id)}, now, actor)
    # The audit log gets the note's ID only: notes can hold investigation detail that does not
    # belong in the security log (docs/security.md).
    _audit(db, AuditAction.INCIDENT_NOTE_ADDED, actor, incident, note_id=str(note.id))
    db.commit()
    return note


def current_pins(db: Session, incident_id: uuid.UUID) -> list[IncidentEvidence]:
    """Pinned evidence now: the latest PIN of each target that was not unpinned since."""
    latest: dict[tuple[str, str], IncidentEvidence] = {}
    for row in db.scalars(
        select(IncidentEvidence)
        .where(IncidentEvidence.incident_id == incident_id)
        .order_by(IncidentEvidence.created_at, IncidentEvidence.id)
    ):
        key = ("event", str(row.event_id)) if row.event_id else ("alert", str(row.alert_id))
        latest[key] = row
    return [row for row in latest.values() if row.action == EvidenceAction.PIN]


def change_evidence(
    db: Session,
    incident_id: uuid.UUID,
    *,
    event_id: uuid.UUID | None,
    alert_id: uuid.UUID | None,
    action: EvidenceAction,
    tag: EvidenceTag,
    comment: str | None,
    actor: User,
) -> IncidentEvidence:
    incident = _locked(db, incident_id)
    _not_closed(incident)
    if (event_id is None) == (alert_id is None):
        raise AppError(400, "Pin either an event or an alert")
    if event_id is not None and db.get(Event, event_id) is None:
        raise AppError(404, "Event not found")
    if alert_id is not None and db.get(Alert, alert_id) is None:
        raise AppError(404, "Alert not found")
    pinned = any(
        (p.event_id == event_id if event_id else p.alert_id == alert_id)
        for p in current_pins(db, incident.id)
    )
    if action == EvidenceAction.PIN and pinned:
        raise AppError(409, "This evidence is already pinned")
    if action == EvidenceAction.UNPIN and not pinned:
        raise AppError(409, "This evidence is not pinned")
    now = _now()
    row = IncidentEvidence(
        id=uuid.uuid4(),
        incident_id=incident.id,
        event_id=event_id,
        alert_id=alert_id,
        tag=tag,
        comment=comment,
        action=action,
        actor_id=actor.id,
        created_at=now,
    )
    db.add(row)
    incident.updated_at = now
    details = {
        "change": str(action),
        "event_id": str(event_id) if event_id else None,
        "alert_id": str(alert_id) if alert_id else None,
        "tag": str(tag),
        "comment": comment,
    }
    records.activity(db, incident, ActivityKind.EVIDENCE, details, now, actor)
    _audit(db, AuditAction.INCIDENT_EVIDENCE_CHANGED, actor, incident, **details)
    db.commit()
    return row


def link_alert(
    db: Session, incident_id: uuid.UUID, alert_id: uuid.UUID, reason: str, actor: User
) -> Incident:
    incident = _locked(db, incident_id)
    if not workflow.accepts_alerts(IncidentStatus(incident.status)):
        raise AppError(409, "Only open incidents take alerts; reopen it first")
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise AppError(404, "Alert not found")
    other = db.scalar(select(IncidentAlert.incident_id).where(IncidentAlert.alert_id == alert.id))
    if other is not None:
        raise AppError(409, f"This alert already belongs to an incident ({other})")
    now = _now()
    records.link(db, incident, alert, None, now, actor, reason)
    records.refresh(db, incident, now)
    _audit(
        db,
        AuditAction.INCIDENT_ALERT_LINKED,
        actor,
        incident,
        alert_id=str(alert.id),
        reason=reason,
    )
    db.commit()
    return incident


def unlink_alert(
    db: Session, incident_id: uuid.UUID, alert_id: uuid.UUID, reason: str, actor: User
) -> Incident:
    incident = _locked(db, incident_id)
    _not_closed(incident)
    row = db.get(IncidentAlert, (incident.id, alert_id))
    if row is None:
        raise AppError(404, "This alert is not part of the incident")
    alert = db.get(Alert, alert_id)
    now = _now()
    db.delete(row)
    details = {"alert_id": str(alert_id), "title": alert.title if alert else None, "reason": reason}
    # The engine reads this entry and never links the alert back to this incident.
    records.activity(db, incident, ActivityKind.UNLINK, details, now, actor)
    records.refresh(db, incident, now)
    _audit(db, AuditAction.INCIDENT_ALERT_UNLINKED, actor, incident, **details)
    db.commit()
    return incident


def rename(db: Session, incident_id: uuid.UUID, title: str, actor: User) -> Incident:
    incident = _locked(db, incident_id)
    _not_closed(incident)
    text = title.strip()
    if not 3 <= len(text) <= 300:
        raise AppError(400, "A title has 3 to 300 characters")
    if text == incident.title:
        return incident
    now = _now()
    details = {"from": incident.title, "to": text}
    incident.title = text
    incident.title_edited = True  # generated titles no longer replace it
    incident.updated_at = now
    records.activity(db, incident, ActivityKind.RENAME, details, now, actor)
    _audit(db, AuditAction.INCIDENT_RENAMED, actor, incident, **details)
    db.commit()
    return incident


def escalate(db: Session, alert_id: uuid.UUID, reason: str, actor: User) -> Incident:
    """An analyst opens an incident from an alert the engine left standalone."""
    alert = db.scalars(select(Alert).where(Alert.id == alert_id).with_for_update()).first()
    if alert is None:
        raise AppError(404, "Alert not found")
    other = db.scalar(select(IncidentAlert.incident_id).where(IncidentAlert.alert_id == alert.id))
    if other is not None:
        raise AppError(409, f"This alert already belongs to an incident ({other})")
    now = _now()
    incident = records.create(db, alert, f"Escalated by {actor.email}: {reason}", now, actor)
    records.link(db, incident, alert, None, now, actor, reason)
    records.refresh(db, incident, now)
    _audit(db, AuditAction.INCIDENT_CREATED, actor, incident, alert_id=str(alert.id), reason=reason)
    db.commit()
    return incident
