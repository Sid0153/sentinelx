"""Alerts: the queue, one alert with everything needed to investigate it, its evidence, and
status changes (ANALYST+, audited)."""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Query

from app.alerts import queries, service, workflow
from app.api.deps import DbSession
from app.auth.deps import AnalystUser, CurrentUser
from app.core.errors import AppError
from app.events.queries import DISPLAY_LIMIT
from app.incidents.queries import alert_incident
from app.ingestion.normalize import optional_ip
from app.models.alert import Alert, AlertStatus
from app.models.context import Asset, Identity
from app.models.user import User
from app.schemas.alert import (
    AlertActivity,
    AlertDetail,
    AlertSummary,
    AlertTechnique,
    EvidenceEvent,
    PriorityFactor,
    RelatedAlert,
    TransitionRequest,
)
from app.schemas.common import Page, error_responses
from app.schemas.ingestion import EventPublic

alerts = APIRouter(prefix="/alerts", tags=["alerts"], responses=error_responses(401, 403))

Limit = Annotated[int, Query(ge=1, le=200)]
Offset = Annotated[int, Query(ge=0)]
Severity = Annotated[list[str], Query(max_length=4)]


def _technique_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def _email(db: DbSession, user_id: uuid.UUID | None) -> str | None:
    if user_id is None:
        return None
    user = db.get(User, user_id)
    return user.email if user else None


def _detail(db: DbSession, alert: Alert) -> AlertDetail:
    asset = db.get(Asset, alert.asset_id) if alert.asset_id else None
    identity = db.get(Identity, alert.identity_id) if alert.identity_id else None
    return AlertDetail(
        **AlertSummary.model_validate(alert).model_dump(),
        rule_version=alert.rule_version,
        indicator=alert.indicator,
        kind=alert.kind,
        category=alert.category,
        description=alert.description,
        target_username=alert.target_username,
        asset_id=alert.asset_id,
        asset_hostname=asset.hostname if asset else None,
        identity_id=alert.identity_id,
        identity_username=identity.username if identity else None,
        priority_breakdown=[PriorityFactor(**f) for f in alert.priority_breakdown],
        risk_model_version=alert.risk_model_version,
        group_values=alert.group_values,
        explanation=alert.explanation,
        facts=alert.facts,
        entities=alert.entities,
        investigation=alert.investigation,
        response=alert.response,
        mitre=[AlertTechnique(**m, url=_technique_url(m["technique"])) for m in alert.mitre],
        history=alert.history,
        peak_count=alert.peak_count,
        previous_alert_id=alert.previous_alert_id,
        triaged_at=alert.triaged_at,
        resolved_at=alert.resolved_at,
        resolved_by=_email(db, alert.resolved_by),
        status_changed_at=alert.status_changed_at,
        status_changed_by=_email(db, alert.status_changed_by),
        status_note=alert.status_note,
        allowed_transitions=workflow.allowed(AlertStatus(alert.status)),
        activity=[AlertActivity(**a) for a in queries.activity(db, alert.id)],
        incident_id=incident.id if (incident := alert_incident(db, alert.id)) else None,
        incident_number=incident.number if incident else None,
        related=[
            RelatedAlert(
                id=other.id,
                rule_id=other.rule_id,
                title=other.title,
                status=AlertStatus(other.status),
                priority_score=other.priority_score,
                priority_band=other.priority_band,
                last_event_at=other.last_event_at,
                shared=shared,
            )
            for other, shared in queries.related(db, alert)
        ],
    )


@alerts.get("", response_model=Page[AlertSummary], responses=error_responses(400))
def list_alerts(
    _user: CurrentUser,
    db: DbSession,
    status: Annotated[list[AlertStatus], Query(max_length=5)] = [],  # noqa: B006
    severity: Severity = [],  # noqa: B006
    band: Severity = [],  # noqa: B006
    rule_id: Annotated[str | None, Query(pattern=r"^[A-Z]{3,5}-\d{3}$")] = None,
    host: Annotated[str | None, Query(max_length=253)] = None,
    username: Annotated[str | None, Query(max_length=256)] = None,
    source_ip: Annotated[str | None, Query(max_length=45)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    sort: queries.Sort = "priority",
    limit: Limit = 50,
    offset: Offset = 0,
) -> Page[AlertSummary]:
    """The alert queue. Default order: priority score, then most recent activity. Filters:
    `status`, `severity` and `band` (each repeatable), rule, host, user, source address, and
    `since` / `until` on the alert's event times."""
    levels = {"low", "medium", "high", "critical"}
    if not set(severity) <= levels or not set(band) <= levels:
        raise AppError(400, "severity and band take low, medium, high or critical")
    if source_ip is not None and optional_ip(source_ip) is None:
        raise AppError(400, "source_ip must be an IP address")
    filters = queries.AlertFilters(
        status=[str(s) for s in status],
        severity=severity,
        band=band,
        rule_id=rule_id,
        host=host,
        username=username,
        source_ip=optional_ip(source_ip) if source_ip else None,
        since=since,
        until=until,
        sort=sort,
    )
    rows, total = queries.list_alerts(db, filters, limit, offset)
    return Page(
        items=[AlertSummary.model_validate(a) for a in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@alerts.get("/{alert_id}", response_model=AlertDetail, responses=error_responses(404))
def get_alert(alert_id: uuid.UUID, _user: CurrentUser, db: DbSession) -> AlertDetail:
    """Everything to investigate one alert: what and why (explanation, facts), the priority
    breakdown, entities and their inventory context, ATT&CK, next steps, the detections it
    merges, status history, related alerts, and the status changes allowed now."""
    return _detail(db, queries.get_alert(db, alert_id))


@alerts.get(
    "/{alert_id}/events", response_model=Page[EvidenceEvent], responses=error_responses(404)
)
def list_evidence(
    alert_id: uuid.UUID,
    _user: CurrentUser,
    db: DbSession,
    limit: Limit = 50,
    offset: Offset = 0,
) -> Page[EvidenceEvent]:
    """The events the alert rests on, in time order: normalized, with the raw record each
    came from (as text, at most 4,096 characters)."""
    queries.get_alert(db, alert_id)
    rows, total = queries.evidence(db, alert_id, limit, offset)
    items = []
    for event, raw in rows:
        text = raw.display_text
        items.append(
            EvidenceEvent(
                **EventPublic.model_validate(event).model_dump(),
                raw_text=text[:DISPLAY_LIMIT],
                raw_truncated=len(text) > DISPLAY_LIMIT,
            )
        )
    return Page(items=items, total=total, limit=limit, offset=offset)


@alerts.post(
    "/{alert_id}/transition",
    response_model=AlertDetail,
    responses=error_responses(400, 404, 409),
)
def transition_alert(
    alert_id: uuid.UUID, payload: TransitionRequest, analyst: AnalystUser, db: DbSession
) -> AlertDetail:
    """Change the status. RESOLVED needs a `disposition`; FALSE_POSITIVE and reopening need
    a `reason`. Changes the workflow does not allow are 409 (the alert's
    `allowed_transitions` lists what is possible now); a missing disposition or reason is 400.
    Audited as ALERT_STATUS_CHANGED."""
    alert = service.transition(
        db,
        alert_id,
        payload.status,
        payload.disposition,
        payload.reason,
        analyst,
        datetime.now(UTC),
    )
    return _detail(db, alert)
