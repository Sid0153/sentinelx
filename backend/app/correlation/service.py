"""Correlation: alerts touched by a detection run become part of incidents (docs/correlation.md).

Runs inside the detection run's transaction, under its advisory lock, so two concurrent
batches cannot create two incidents for the same activity. Candidate incidents are locked
(FOR UPDATE) before they are extended, so an analyst resolving an incident at the same moment
is either seen (the incident is skipped) or waits.

For each touched alert, oldest activity first:
1. Already in an incident: refresh that incident.
2. Otherwise link it to the best open incident it shares enough with (STRONG or MEDIUM, see
   scoring.py), unless an analyst unlinked it from that incident before.
3. Otherwise open an incident:
   - for a high or critical alert on its own ("high-severity alert"), or
   - for a low or medium alert only together with at least one partner: another open alert,
     not in any incident, linked to it STRONG or MEDIUM ("multi-stage activity").
   A lone low or medium alert stays a standalone alert. Partners join the new incident.
   A new incident points to a resolved or closed one for the same activity, if any.
An incident is refreshed as soon as it changes, so the next alert in the same pass sees it as
it is now. Then every changed incident is swept: open alerts in no incident that now belong
with it (it may have grown: a new host, user, or access) join it, until nothing more joins.
Incidents are never merged or split by the engine.
"""

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import partial

from sqlalchemy import ColumnElement, or_, select
from sqlalchemy.orm import Session

from app.core.client_ip import Network, parse_networks
from app.core.config import get_settings
from app.correlation.scoring import AUTO_LINK, Link, Subject, link
from app.incidents import records
from app.incidents.settings import Windows, windows
from app.models.alert import ACTIVE_STATUSES, Alert
from app.models.incident import (
    ACTIVE_INCIDENT_STATUSES,
    ActivityKind,
    Incident,
    IncidentActivity,
    IncidentAlert,
    LinkStrength,
)

HIGH = ("high", "critical")
_STRENGTH_ORDER = {"STRONG": 2, "MEDIUM": 1}
RELATED_LOOKBACK = timedelta(days=30)  # how far back a closed incident counts as "the same"
MAX_SWEEPS = 5  # each round can only add alerts, and there are finitely many; a safety cap

ScoreFn = Callable[[Subject], Link | None]
_ORDER = (Alert.first_event_at, Alert.last_event_at, Alert.rule_id, Alert.id)


@dataclass
class Result:
    created: set[uuid.UUID] = field(default_factory=set)
    updated: set[uuid.UUID] = field(default_factory=set)


@dataclass(frozen=True)
class _Context:
    db: Session
    config: Windows
    internal: tuple[Network, ...]
    now: datetime

    def score(self, alert: Subject, target: Subject) -> Link | None:
        return link(
            alert,
            target,
            internal=self.internal,
            correlation_window=self.config.correlation,
            sequence_window=self.config.sequence,
        )


def correlate(db: Session, alert_ids: list[uuid.UUID], now: datetime) -> Result:
    result = Result()
    if not alert_ids:
        return result
    ctx = _Context(db, windows(db), parse_networks(get_settings().internal_networks), now)
    for alert in db.scalars(select(Alert).where(Alert.id.in_(alert_ids)).order_by(*_ORDER)):
        _correlate_one(ctx, alert, result)
    for incident_id in list(result.created | result.updated):
        incident = db.get(Incident, incident_id)
        if incident is not None:
            records.refresh(db, incident, now)
            _sweep(ctx, incident, result)
    result.updated -= result.created
    return result


def standalone_in(db: Session, start: datetime, end: datetime) -> list[uuid.UUID]:
    """Open alerts in no incident whose activity overlaps [start, end]: what a manual run
    correlates again (backfill: alerts from before correlation existed, or that only belong
    with an incident that grew since)."""
    return list(
        db.scalars(
            select(Alert.id).where(
                Alert.status.in_(ACTIVE_STATUSES),
                Alert.id.notin_(select(IncidentAlert.alert_id)),
                Alert.first_event_at <= end,
                Alert.last_event_at >= start,
            )
        )
    )


def _incident_of(db: Session, alert: Alert) -> uuid.UUID | None:
    return db.scalar(select(IncidentAlert.incident_id).where(IncidentAlert.alert_id == alert.id))


def _join(ctx: _Context, incident: Incident, alert: Alert, why: Link) -> None:
    records.link(ctx.db, incident, alert, why, ctx.now)
    records.refresh(ctx.db, incident, ctx.now)  # the next alert sees the incident as it is now


def _correlate_one(ctx: _Context, alert: Alert, result: Result) -> None:
    db = ctx.db
    current = _incident_of(db, alert)
    if current is not None:
        result.updated.add(current)
        return
    # From its full evidence; as a target (partners join it), its own foothold counts too.
    subject = records.subjects(db, [alert])[alert.id]

    best: tuple[Incident, Link] | None = None
    for incident in _candidates(db, subject, ctx.config.correlation, ACTIVE_INCIDENT_STATUSES):
        why = ctx.score(subject, records.incident_subject(db, incident))
        if why is None or why.strength not in AUTO_LINK or _unlinked_before(db, incident, alert):
            continue
        rank = (_STRENGTH_ORDER[why.strength], incident.last_activity_at, -incident.number)
        if best is None or rank > (
            _STRENGTH_ORDER[best[1].strength],
            best[0].last_activity_at,
            -best[0].number,
        ):
            best = (incident, why)
    if best is not None:
        _join(ctx, best[0], alert, best[1])
        result.updated.add(best[0].id)
        return

    # A partner is the one joining: how does it belong with this alert?
    partners = _standalone(
        db,
        _shares_with_alert(alert),
        exclude=alert.id,
        score=lambda partner: ctx.score(partner, subject),
    )
    if alert.severity in HIGH:
        reason = f"High-severity alert: {alert.title}"
    elif partners:
        reason = f"Multi-stage activity: {alert.title} with {len(partners)} related alert(s)"
    else:
        return  # a lone low or medium alert stays a standalone alert
    related = _related_closed(ctx, subject)
    incident = records.create(db, alert, reason, ctx.now, related_incident_id=related)
    _join(ctx, incident, alert, Link(LinkStrength.ORIGIN, [], f"{reason}."))
    for partner, why in partners:
        _join(ctx, incident, partner, why)
    result.created.add(incident.id)


def _sweep(ctx: _Context, incident: Incident, result: Result) -> None:
    """Standalone open alerts that belong with this incident now join it, repeatedly: each
    one can widen the incident (a host, a user, an access) and let another one in."""
    db = ctx.db
    if incident.status not in ACTIVE_INCIDENT_STATUSES:
        return
    for _ in range(MAX_SWEEPS):
        target = records.incident_subject(db, incident)
        joining = [
            (alert, why)
            for alert, why in _standalone(
                db,
                _shares_with_incident(incident),
                exclude=None,
                score=partial(ctx.score, target=target),
            )
            if not _unlinked_before(db, incident, alert)
        ]
        if not joining:
            return
        for alert, why in joining:
            _join(ctx, incident, alert, why)
        if incident.id not in result.created:
            result.updated.add(incident.id)


def _shares_with_alert(alert: Alert) -> list[ColumnElement[bool]]:
    shares: list[ColumnElement[bool]] = [Alert.host == alert.host] if alert.host else []
    if alert.username:
        shares.append(Alert.username == alert.username)
    if alert.source_ip:
        shares.append(Alert.source_ip == str(alert.source_ip))
    return shares


def _shares_with_incident(incident: Incident) -> list[ColumnElement[bool]]:
    shares: list[ColumnElement[bool]] = [Alert.host.in_(incident.hosts)] if incident.hosts else []
    if incident.usernames:
        shares.append(Alert.username.in_(incident.usernames))
        shares.append(Alert.target_username.in_(incident.usernames))
    if incident.source_ips:
        shares.append(Alert.source_ip.in_(incident.source_ips))
    return shares


def _standalone(
    db: Session,
    shares: list[ColumnElement[bool]],
    *,
    exclude: uuid.UUID | None,
    score: ScoreFn,
) -> list[tuple[Alert, Link]]:
    """Open alerts in no incident, sharing something, that link STRONG or MEDIUM."""
    if not shares:
        return []
    statement = select(Alert).where(
        Alert.status.in_(ACTIVE_STATUSES),
        Alert.id.notin_(select(IncidentAlert.alert_id)),
        or_(*shares),
    )
    if exclude is not None:
        statement = statement.where(Alert.id != exclude)
    candidates = list(db.scalars(statement.order_by(*_ORDER)))
    seen = records.subjects(db, candidates)
    found = []
    for other in candidates:
        why = score(seen[other.id])
        if why is not None and why.strength in AUTO_LINK:
            found.append((other, why))
    return found


def _candidates(
    db: Session, subject: Subject, window: timedelta, statuses: tuple[str, ...]
) -> list[Incident]:
    shares = []
    if subject.hosts:
        shares.append(Incident.hosts.overlap(sorted(subject.hosts)))
    if subject.users:
        shares.append(Incident.usernames.overlap(sorted(subject.users)))
    if subject.sources:
        shares.append(Incident.source_ips.overlap(sorted(subject.sources)))
    if not shares:
        return []
    return list(
        db.scalars(
            select(Incident)
            .where(
                Incident.status.in_(statuses),
                or_(*shares),
                Incident.last_activity_at >= subject.first - window,
                Incident.first_activity_at <= subject.last + window,
            )
            .order_by(Incident.number)
            .with_for_update()
        )
    )


def _related_closed(ctx: _Context, subject: Subject) -> uuid.UUID | None:
    """A resolved or closed incident about the same activity, for the back-link."""
    closed = _candidates(ctx.db, subject, RELATED_LOOKBACK, ("RESOLVED", "CLOSED"))
    for incident in sorted(closed, key=lambda i: i.last_activity_at, reverse=True):
        target = records.incident_subject(ctx.db, incident)
        # Same activity, later: compare entities only, as if it were current.
        widened = Subject(
            target.hosts,
            target.users,
            target.sources,
            target.tactics,
            target.techniques,
            subject.first,
            subject.last,
        )
        why = ctx.score(subject, widened)
        if why is not None and why.strength in AUTO_LINK:
            return incident.id
    return None


def _unlinked_before(db: Session, incident: Incident, alert: Alert) -> bool:
    """An analyst took this alert out of this incident: the engine does not put it back."""
    return (
        db.scalar(
            select(IncidentActivity.id)
            .where(
                IncidentActivity.incident_id == incident.id,
                IncidentActivity.kind == ActivityKind.UNLINK,
                IncidentActivity.details["alert_id"].astext == str(alert.id),
            )
            .limit(1)
        )
        is not None
    )
