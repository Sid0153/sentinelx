"""Incidents: the queue, the investigation workspace, the timeline, and analyst actions
(ANALYST+, each one audited and recorded as incident activity). Also the correlation settings
(ADMIN) and escalating an alert into an incident (ANALYST+)."""

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Query, status

from app.api.deps import DbSession
from app.auth.deps import AdminUser, AnalystUser, CurrentUser
from app.core.errors import AppError
from app.incidents import queries, service, workflow
from app.incidents import settings as settings_service
from app.ingestion.normalize import optional_ip
from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import EvidenceTag, Incident, IncidentDisposition, IncidentStatus
from app.models.user import User
from app.schemas.alert import AlertSummary, PriorityFactor
from app.schemas.common import Page, error_responses
from app.schemas.incident import (
    ActivityPublic,
    AssignRequest,
    EvidenceRequest,
    IncidentDetail,
    IncidentSummary,
    IncidentTechnique,
    IncidentTransition,
    LinkedAlert,
    LinkRequest,
    NotePublic,
    NoteRequest,
    PinPublic,
    ReasonRequest,
    RelatedIncident,
    RenameRequest,
    ResponseGroup,
    SettingsPublic,
    TimelinePage,
    UserRef,
)

incidents = APIRouter(prefix="/incidents", tags=["incidents"], responses=error_responses(401, 403))
settings = APIRouter(prefix="/settings", tags=["settings"], responses=error_responses(401, 403))
escalation = APIRouter(prefix="/alerts", tags=["alerts"], responses=error_responses(401, 403))

Limit = Annotated[int, Query(ge=1, le=200)]
Offset = Annotated[int, Query(ge=0)]
Levels = Annotated[list[str], Query(max_length=4)]
LEVELS = {"low", "medium", "high", "critical"}


def _user_ref(db: DbSession, user_id: uuid.UUID | None) -> UserRef | None:
    user = db.get(User, user_id) if user_id else None
    return UserRef(id=user.id, email=user.email) if user else None


def _summary(db: DbSession, incident: Incident) -> IncidentSummary:
    fields = {n: getattr(incident, n) for n in IncidentSummary.model_fields if n != "assigned_to"}
    return IncidentSummary(**fields, assigned_to=_user_ref(db, incident.assigned_to))


def _pin_label(db: DbSession, event_id: uuid.UUID | None, alert_id: uuid.UUID | None) -> str:
    if alert_id:
        alert = db.get(Alert, alert_id)
        return f"Alert: {alert.title}" if alert else "Alert"
    event = db.get(Event, event_id) if event_id else None
    if event is None:
        return "Event"
    who = f" · {event.username}" if event.username else ""
    return (
        f"Event {event.timestamp:%Y-%m-%d %H:%M:%S} UTC · {event.event_category}/"
        f"{event.event_action} {event.event_outcome} · {event.host or '—'}{who}"
    )


def _detail(db: DbSession, incident: Incident) -> IncidentDetail:
    linked = queries.links(db, incident.id)
    alerts = [alert for _, alert in linked]
    related = (
        db.get(Incident, incident.related_incident_id) if incident.related_incident_id else None
    )
    resolved_by = _user_ref(db, incident.resolved_by)
    return IncidentDetail(
        **_summary(db, incident).model_dump(),
        summary=incident.summary,
        created_reason=incident.created_reason,
        risk_breakdown=[PriorityFactor(**f) for f in incident.risk_breakdown],
        risk_model_version=incident.risk_model_version,
        techniques=incident.techniques,
        disposition=IncidentDisposition(incident.disposition) if incident.disposition else None,
        resolution=incident.resolution,
        resolved_at=incident.resolved_at,
        resolved_by=resolved_by.email if resolved_by else None,
        closed_at=incident.closed_at,
        title_edited=incident.title_edited,
        related_incident=RelatedIncident(
            id=related.id,
            number=related.number,
            title=related.title,
            status=IncidentStatus(related.status),
        )
        if related
        else None,
        alerts=[
            LinkedAlert(
                alert=AlertSummary.model_validate(alert),
                link_strength=row.link_strength,
                shared_entities=row.shared_entities,
                reason=row.reason,
                link_source=row.link_source,
                linked_at=row.linked_at,
            )
            for row, alert in linked
        ],
        notes=[
            NotePublic(id=note.id, author=email, body=note.body, created_at=note.created_at)
            for note, email in queries.notes(db, incident.id)
        ],
        evidence=[
            PinPublic(
                id=pin.id,
                event_id=pin.event_id,
                alert_id=pin.alert_id,
                label=_pin_label(db, pin.event_id, pin.alert_id),
                tag=EvidenceTag(pin.tag),
                comment=pin.comment,
                pinned_by=(ref.email if (ref := _user_ref(db, pin.actor_id)) else None),
                pinned_at=pin.created_at,
            )
            for pin in service.current_pins(db, incident.id)
        ],
        activity=[
            ActivityPublic(at=row.created_at, actor=email, kind=row.kind, details=row.details)
            for row, email in queries.activity(db, incident.id)
        ],
        mitre=[
            IncidentTechnique(
                **t,
                url="https://attack.mitre.org/techniques/" + t["technique"].replace(".", "/") + "/",
            )
            for t in queries.mitre(alerts)
        ],
        response=[ResponseGroup(**group) for group in queries.response(alerts)],
        allowed_transitions=workflow.allowed(IncidentStatus(incident.status)),
    )


@incidents.get("", response_model=Page[IncidentSummary], responses=error_responses(400))
def list_incidents(
    user: CurrentUser,
    db: DbSession,
    status: Annotated[list[IncidentStatus], Query(max_length=6)] = [],  # noqa: B006
    severity: Levels = [],  # noqa: B006
    assigned: Literal["me", "unassigned"] | None = None,
    host: Annotated[str | None, Query(max_length=253)] = None,
    username: Annotated[str | None, Query(max_length=256)] = None,
    source_ip: Annotated[str | None, Query(max_length=45)] = None,
    sort: queries.Sort = "risk",
    limit: Limit = 50,
    offset: Offset = 0,
) -> Page[IncidentSummary]:
    """The incident queue: by risk, then latest activity (`sort=recent`: latest activity).
    Filters: `status` and `severity` (repeatable), `assigned` (`me` or `unassigned`), and an
    affected host, user or source address."""
    if not set(severity) <= LEVELS:
        raise AppError(400, "severity takes low, medium, high or critical")
    ip = optional_ip(source_ip) if source_ip else None
    if source_ip and ip is None:
        raise AppError(400, "source_ip must be an IP address")
    filters = queries.IncidentFilters(
        status=[str(s) for s in status],
        severity=severity,
        assigned_to=user.id if assigned == "me" else None,
        unassigned=assigned == "unassigned",
        host=host,
        username=username,
        source_ip=ip,
        sort=sort,
    )
    rows, total = queries.list_incidents(db, filters, limit, offset)
    return Page(items=[_summary(db, i) for i in rows], total=total, limit=limit, offset=offset)


@incidents.get("/assignees", response_model=list[UserRef])
def list_assignees(_user: AnalystUser, db: DbSession) -> list[UserRef]:
    """Who incidents can be assigned to (active analysts and admins)."""
    return [UserRef(id=u.id, email=u.email) for u in queries.assignees(db)]


@incidents.get("/{incident_id}", response_model=IncidentDetail, responses=error_responses(404))
def get_incident(incident_id: uuid.UUID, _user: CurrentUser, db: DbSession) -> IncidentDetail:
    """The workspace: summary, risk breakdown, linked alerts with the reason for each link,
    notes, pinned evidence, activity, ATT&CK, recommended response, related incident."""
    return _detail(db, queries.get_incident(db, incident_id))


@incidents.get(
    "/{incident_id}/timeline",
    response_model=TimelinePage,
    responses=error_responses(400, 404),
)
def get_timeline(
    incident_id: uuid.UUID,
    _user: CurrentUser,
    db: DbSession,
    limit: Limit = 100,
    cursor: Annotated[str | None, Query(max_length=300)] = None,
) -> TimelinePage:
    """Oldest first, from stored rows: the linked alerts' evidence events (each once, with the
    rules that cite it and its raw record, up to 1,024 characters), the alerts, and the
    incident's activity. Pass `next_cursor` back as `cursor` for the next page."""
    queries.get_incident(db, incident_id)
    items, next_cursor = queries.timeline(db, incident_id, limit, cursor)
    return TimelinePage.model_validate({"items": items, "next_cursor": next_cursor, "limit": limit})


@incidents.post(
    "/{incident_id}/transition",
    response_model=IncidentDetail,
    responses=error_responses(400, 404, 409),
)
def transition(
    incident_id: uuid.UUID, payload: IncidentTransition, analyst: AnalystUser, db: DbSession
) -> IncidentDetail:
    """Change the status. RESOLVED needs a `disposition` and a `resolution`; reopening needs a
    `reason`. CLOSED is final. Changes the workflow does not allow are 409."""
    incident = service.transition(
        db,
        incident_id,
        payload.status,
        payload.disposition,
        payload.resolution,
        payload.reason,
        analyst,
    )
    return _detail(db, incident)


@incidents.post(
    "/{incident_id}/assign", response_model=IncidentDetail, responses=error_responses(400, 404, 409)
)
def assign(
    incident_id: uuid.UUID, payload: AssignRequest, analyst: AnalystUser, db: DbSession
) -> IncidentDetail:
    return _detail(db, service.assign(db, incident_id, payload.assignee_id, analyst))


@incidents.post(
    "/{incident_id}/notes",
    response_model=NotePublic,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(400, 404, 409),
)
def add_note(
    incident_id: uuid.UUID, payload: NoteRequest, analyst: AnalystUser, db: DbSession
) -> NotePublic:
    """Notes are append-only: they cannot be edited or deleted. A correction is a new note."""
    note = service.add_note(db, incident_id, payload.body, analyst)
    return NotePublic(id=note.id, author=analyst.email, body=note.body, created_at=note.created_at)


@incidents.post(
    "/{incident_id}/evidence",
    response_model=IncidentDetail,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(400, 404, 409),
)
def change_evidence(
    incident_id: uuid.UUID, payload: EvidenceRequest, analyst: AnalystUser, db: DbSession
) -> IncidentDetail:
    """Pin (or unpin) an event or an alert as evidence, with a tag and a comment. Unpinning
    adds a row; nothing is deleted."""
    service.change_evidence(
        db,
        incident_id,
        event_id=payload.event_id,
        alert_id=payload.alert_id,
        action=payload.action,
        tag=payload.tag,
        comment=payload.comment,
        actor=analyst,
    )
    return _detail(db, queries.get_incident(db, incident_id))


@incidents.post(
    "/{incident_id}/alerts",
    response_model=IncidentDetail,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(404, 409),
)
def link_alert(
    incident_id: uuid.UUID, payload: LinkRequest, analyst: AnalystUser, db: DbSession
) -> IncidentDetail:
    """Add an alert by hand (with a reason). An alert belongs to one incident at most."""
    return _detail(
        db, service.link_alert(db, incident_id, payload.alert_id, payload.reason, analyst)
    )


@incidents.post(
    "/{incident_id}/alerts/{alert_id}/unlink",
    response_model=IncidentDetail,
    responses=error_responses(404, 409),
)
def unlink_alert(
    incident_id: uuid.UUID,
    alert_id: uuid.UUID,
    payload: ReasonRequest,
    analyst: AnalystUser,
    db: DbSession,
) -> IncidentDetail:
    """Take an alert out (with a reason). The engine never links it back to this incident."""
    return _detail(db, service.unlink_alert(db, incident_id, alert_id, payload.reason, analyst))


@incidents.patch(
    "/{incident_id}", response_model=IncidentDetail, responses=error_responses(400, 404, 409)
)
def rename(
    incident_id: uuid.UUID, payload: RenameRequest, analyst: AnalystUser, db: DbSession
) -> IncidentDetail:
    """Rename. A renamed incident keeps its title when new alerts join."""
    return _detail(db, service.rename(db, incident_id, payload.title, analyst))


@escalation.post(
    "/{alert_id}/escalate",
    response_model=IncidentDetail,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(404, 409),
)
def escalate(
    alert_id: uuid.UUID, payload: ReasonRequest, analyst: AnalystUser, db: DbSession
) -> IncidentDetail:
    """Open an incident from an alert the engine left standalone. Audited."""
    return _detail(db, service.escalate(db, alert_id, payload.reason, analyst))


@settings.get("", response_model=SettingsPublic)
def get_settings_values(_admin: AdminUser, db: DbSession) -> SettingsPublic:
    return SettingsPublic(**settings_service.current(db))


@settings.patch("", response_model=SettingsPublic, responses=error_responses(400))
def update_settings(
    payload: settings_service.SettingsUpdate, admin: AdminUser, db: DbSession
) -> SettingsPublic:
    """Correlation window (15–1,440 min) and sequence window (5–240 min, not longer than the
    correlation window). Audited as SETTINGS_CHANGED; applies to the next detection run."""
    return SettingsPublic(**settings_service.update(db, payload, admin))
