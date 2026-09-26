"""Writing incidents: creation, alert links, the activity record, and what an incident derives
from its alerts. Used by correlation (the engine) and by analyst actions. The caller commits.
"""

import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.correlation.scoring import ACCESS_TACTICS, Link, Subject
from app.models.alert import Alert, AlertEvent
from app.models.context import Identity, PrivilegeLevel
from app.models.event import Event
from app.models.incident import (
    ActivityKind,
    Incident,
    IncidentActivity,
    IncidentAlert,
    IncidentStatus,
    LinkSource,
    LinkStrength,
)
from app.models.user import User
from app.risk.priority import incident_risk

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass(frozen=True)
class Evidence:
    """What an alert's linked evidence shows: every host, user and source address in it (not
    the 10 most frequent kept for display), and whether any event succeeded."""

    hosts: frozenset[str] = frozenset()
    users: frozenset[str] = frozenset()
    sources: frozenset[str] = frozenset()
    succeeded: bool = False


def evidence(db: Session, alert_ids: list[uuid.UUID]) -> dict[uuid.UUID, Evidence]:
    """For each alert, its entities and outcome over all its linked evidence (one query)."""
    found: dict[uuid.UUID, dict[str, set[str]]] = {}
    worked: set[uuid.UUID] = set()
    if not alert_ids:
        return {}
    rows = db.execute(
        select(
            AlertEvent.alert_id,
            Event.host,
            Event.username,
            Event.target_username,
            Event.source_ip,
            Event.event_outcome,
        )
        .join(Event, Event.id == AlertEvent.event_id)
        .where(AlertEvent.alert_id.in_(alert_ids))
        .distinct()
    )
    for alert_id, host, username, target, source, outcome in rows:
        entry = found.setdefault(alert_id, {"hosts": set(), "users": set(), "sources": set()})
        if host:
            entry["hosts"].add(host)
        entry["users"].update(u for u in (username, target) if u)
        if source:
            entry["sources"].add(str(source))
        if outcome == "success":
            worked.add(alert_id)
    return {
        alert_id: Evidence(
            frozenset(e["hosts"]),
            frozenset(e["users"]),
            frozenset(e["sources"]),
            alert_id in worked,
        )
        for alert_id, e in found.items()
    }


def alert_subject(alert: Alert, seen: Evidence | None = None) -> Subject:
    """An alert's entities, time span and ATT&CK mapping, for correlation. `seen`: what its
    evidence shows (all entities, and whether an event succeeded, which together with an
    access tactic makes the alert a foothold on its host; a refused sudo is not one)."""
    seen = seen or Evidence()
    hosts = {alert.host} | seen.hosts
    users = {alert.username, alert.target_username} | seen.users
    sources = {str(alert.source_ip) if alert.source_ip else None} | seen.sources
    tactics = frozenset(t for m in alert.mitre for t in m.get("tactics", []))
    host_set = frozenset(h for h in hosts if h)
    access = (
        tuple((h, alert.first_event_at) for h in sorted(host_set))
        if seen.succeeded and tactics & ACCESS_TACTICS
        else ()
    )
    return Subject(
        hosts=host_set,
        users=frozenset(u for u in users if u),
        sources=frozenset(s for s in sources if s),
        tactics=tactics,
        techniques=frozenset(m["technique"] for m in alert.mitre),
        first=alert.first_event_at,
        last=alert.last_event_at,
        access=access,
    )


def subjects(db: Session, alerts: list[Alert]) -> dict[uuid.UUID, Subject]:
    seen = evidence(db, [a.id for a in alerts])
    return {a.id: alert_subject(a, seen.get(a.id)) for a in alerts}


def incident_subject(db: Session, incident: Incident) -> Subject:
    """The incident as the union of its linked alerts, with where and since when it shows
    access (from those alerts)."""
    alerts = linked_alerts(db, incident.id)
    access = tuple(pair for s in subjects(db, alerts).values() for pair in s.access)
    return Subject(
        hosts=frozenset(incident.hosts),
        users=frozenset(incident.usernames),
        sources=frozenset(incident.source_ips),
        tactics=frozenset(incident.tactics),
        techniques=frozenset(incident.techniques),
        first=incident.first_activity_at,
        last=incident.last_activity_at,
        access=access,
    )


def activity(
    db: Session,
    incident: Incident,
    kind: ActivityKind,
    details: dict[str, Any],
    now: datetime,
    actor: User | None = None,
) -> None:
    db.add(
        IncidentActivity(
            incident_id=incident.id,
            actor_id=actor.id if actor else None,
            kind=kind,
            details=details,
            created_at=now,
        )
    )


def linked_alerts(db: Session, incident_id: uuid.UUID) -> list[Alert]:
    return list(
        db.scalars(
            select(Alert)
            .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
            .where(IncidentAlert.incident_id == incident_id)
            .order_by(Alert.first_event_at, Alert.last_event_at, Alert.rule_id, Alert.id)
        )
    )


def create(
    db: Session,
    first: Alert,
    reason: str,
    now: datetime,
    actor: User | None = None,
    related_incident_id: uuid.UUID | None = None,
) -> Incident:
    """A new incident around `first` (not linked yet: the caller links it with its reason)."""
    incident = Incident(
        id=uuid.uuid4(),
        title=first.title,
        summary="",
        created_reason=reason[:500],
        status=IncidentStatus.OPEN,
        severity=first.severity,
        risk_score=first.priority_score,
        risk_band=first.priority_band,
        risk_breakdown=[],
        risk_model_version="",
        first_activity_at=first.first_event_at,
        last_activity_at=first.last_event_at,
        related_incident_id=related_incident_id,
        created_at=now,
        updated_at=now,
    )
    db.add(incident)
    db.flush()
    activity(db, incident, ActivityKind.CREATED, {"reason": reason}, now, actor)
    return incident


def link(
    db: Session,
    incident: Incident,
    alert: Alert,
    why: Link | None,
    now: datetime,
    actor: User | None = None,
    note: str | None = None,
) -> None:
    """Links an alert with the reason it belongs (engine: `why`; analyst: MANUAL + note)."""
    manual = actor is not None
    strength = LinkStrength.MANUAL if manual else (why.strength if why else LinkStrength.MANUAL)
    reason = f"Linked by {actor.email}: {note}" if manual and actor else (why.reason if why else "")
    db.add(
        IncidentAlert(
            incident_id=incident.id,
            alert_id=alert.id,
            link_strength=strength,
            shared_entities=why.shared if why else [],
            reason=reason[:500],
            link_source=LinkSource.ANALYST if manual else LinkSource.ENGINE,
            linked_by=actor.id if actor else None,
            linked_at=now,
        )
    )
    activity(
        db,
        incident,
        ActivityKind.LINK,
        {
            "alert_id": str(alert.id),
            "title": alert.title,
            "strength": str(strength),
            "reason": reason,
        },
        now,
        actor,
    )
    # Visible at once to later lookups in the same pass ("is this alert in an incident?");
    # sessions do not autoflush.
    db.flush()


def refresh(db: Session, incident: Incident, now: datetime) -> None:
    """Recomputes everything an incident derives from its linked alerts."""
    db.flush()
    alerts = linked_alerts(db, incident.id)
    incident.alert_count = len(alerts)
    incident.updated_at = now
    if not alerts:  # every alert was unlinked by analysts: keep the last known values
        return
    found = list(subjects(db, alerts).values())
    incident.hosts = sorted(set().union(*(s.hosts for s in found)))
    incident.usernames = sorted(set().union(*(s.users for s in found)))
    incident.source_ips = sorted(set().union(*(s.sources for s in found)))
    incident.tactics = sorted(set().union(*(s.tactics for s in found)))
    incident.techniques = sorted({m["technique"] for a in alerts for m in a.mitre})
    incident.first_activity_at = min(a.first_event_at for a in alerts)
    incident.last_activity_at = max(a.last_event_at for a in alerts)
    incident.severity = max((a.severity for a in alerts), key=lambda s: _SEVERITY_ORDER[s])
    incident.simulated = any(a.simulated for a in alerts)

    top = max(alerts, key=lambda a: (a.priority_score, a.last_event_at))
    privileged = _privileged_identity(db, alerts)
    risk = incident_risk(
        top_alert_score=top.priority_score,
        top_alert_title=top.title,
        top_alert_has_privileged=any(f["factor"] == "identity" for f in top.priority_breakdown),
        stages=_stages(alerts),
        host_count=len(incident.hosts),
        privileged_identity=privileged,
    )
    incident.risk_score = risk.score
    incident.risk_band = risk.band
    incident.risk_breakdown = risk.breakdown()
    incident.risk_model_version = risk.version
    if not incident.title_edited:
        incident.title = _title(incident, alerts)
    incident.summary = _summary(incident, alerts)


def _stages(alerts: list[Alert]) -> list[str]:
    """The distinct kinds of finding (rule and indicator): the attack stages the incident
    shows. Tactics would overcount: one technique can span several (ADR-0012)."""
    return sorted({f"{a.rule_id}:{a.indicator}" if a.indicator else a.rule_id for a in alerts})


def _privileged_identity(db: Session, alerts: list[Alert]) -> str | None:
    ids = {a.identity_id for a in alerts if a.identity_id}
    if not ids:
        return None
    return db.scalar(
        select(Identity.username)
        .where(Identity.id.in_(ids), Identity.privilege_level == PrivilegeLevel.PRIVILEGED)
        .order_by(Identity.username)
        .limit(1)
    )


def _names(values: list[str], limit: int = 2) -> str:
    shown = ", ".join(values[:limit])
    return shown + (f" and {len(values) - limit} more" if len(values) > limit else "")


def _most_common(values: list[str]) -> str | None:
    counts = Counter(v for v in values if v)
    return min(counts, key=lambda v: (-counts[v], v)) if counts else None


def _title(incident: Incident, alerts: list[Alert]) -> str:
    """`Multi-stage activity on web-01 (deploy from 203.0.113.45)`: the kind of story, where,
    and the main actor and source (the ones most alerts share; target accounts such as a new
    account are in the summary). One alert: its own title."""
    if len(alerts) == 1:
        return alerts[0].title
    if len(_stages(alerts)) > 1:
        stage = "Multi-stage activity"
    else:  # one kind of finding on several hosts or from several sources: name the finding
        stage = alerts[0].title.split(" (", 1)[0]
    where = f" on {_names(incident.hosts)}" if incident.hosts else ""
    who = _most_common([a.username or "" for a in alerts])
    source = _most_common([str(a.source_ip) if a.source_ip else "" for a in alerts])
    detail = " from ".join(part for part in (who, source) if part)
    return (f"{stage}{where}" + (f" ({detail})" if detail else ""))[:300]


def _summary(incident: Incident, alerts: list[Alert]) -> str:
    """What the incident is about, from its alerts: counts, stages, entities, time span."""
    stages = ", ".join(incident.tactics) or "no mapped tactic"
    parts = [
        f"{len(alerts)} alert(s) from {len({a.rule_id for a in alerts})} rule(s) "
        f"({', '.join(sorted({a.rule_id for a in alerts}))}); ATT&CK tactics: {stages}.",
    ]
    if incident.hosts:
        parts.append(f"Hosts: {', '.join(incident.hosts)}.")
    if incident.usernames:
        parts.append(f"Accounts: {', '.join(incident.usernames)}.")
    if incident.source_ips:
        parts.append(f"Sources: {', '.join(incident.source_ips)}.")
    parts.append(
        f"Activity from {incident.first_activity_at:%Y-%m-%d %H:%M:%S} to "
        f"{incident.last_activity_at:%Y-%m-%d %H:%M:%S} UTC."
    )
    return " ".join(parts)
