"""What the evidence says about an asset or an identity: its alerts, incidents and last activity
(the context the brief asks assets and identities to add, §17–18). Read-only.

An alert involves an asset when correlation linked the asset to it (`alerts.asset_id`), or when
its host is the asset's host name (short name match, the same rule as enrichment, so an asset
added after the events still finds them). An alert involves an identity when it is the recorded
identity, or the account acted as or upon.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ColumnElement, String, Uuid, column, func, or_, select, values
from sqlalchemy.orm import Session

from app.models.alert import ACTIVE_STATUSES, Alert
from app.models.context import Asset, Identity
from app.models.event import Event
from app.models.incident import ACTIVE_INCIDENT_STATUSES, Incident, IncidentAlert

RECENT = 10


def _short(value: Any) -> Any:
    return func.split_part(value, ".", 1)


def asset_alerts(asset: Asset) -> ColumnElement[bool]:
    return or_(
        Alert.asset_id == asset.id,
        Alert.host == asset.hostname,
        _short(Alert.host) == asset.hostname.split(".", 1)[0],
    )


def identity_alerts(identity: Identity) -> ColumnElement[bool]:
    return or_(
        Alert.identity_id == identity.id,
        Alert.username == identity.username,
        Alert.target_username == identity.username,
    )


def _incidents(involves: ColumnElement[bool], also: ColumnElement[bool]) -> Any:
    via_alerts = (
        select(IncidentAlert.incident_id)
        .join(Alert, Alert.id == IncidentAlert.alert_id)
        .where(involves)
    )
    return or_(Incident.id.in_(via_alerts), also)


def _activity(
    db: Session, alerts: ColumnElement[bool], incidents: Any, last_seen: Any
) -> dict[str, Any]:
    return {
        "open_alerts": int(
            db.scalar(select(func.count()).where(alerts, Alert.status.in_(ACTIVE_STATUSES))) or 0
        ),
        "total_alerts": int(db.scalar(select(func.count()).select_from(Alert).where(alerts)) or 0),
        "open_incidents": int(
            db.scalar(
                select(func.count())
                .select_from(Incident)
                .where(incidents, Incident.status.in_(ACTIVE_INCIDENT_STATUSES))
            )
            or 0
        ),
        "total_incidents": int(
            db.scalar(select(func.count()).select_from(Incident).where(incidents)) or 0
        ),
        "last_seen_at": db.scalar(last_seen),
        "recent_alerts": list(
            db.scalars(
                select(Alert)
                .where(alerts)
                .order_by(Alert.last_event_at.desc(), Alert.id)
                .limit(RECENT)
            )
        ),
        "incidents": list(
            db.scalars(
                select(Incident)
                .where(incidents)
                .order_by(Incident.last_activity_at.desc())
                .limit(RECENT)
            )
        ),
    }


def _latest(recorded: ColumnElement[bool], named: ColumnElement[bool]) -> Any:
    """The latest event time through either condition. Two lookups, each able to use its index
    ((host|username, timestamp) scanned backwards), instead of one OR that cannot."""
    return select(
        func.greatest(
            select(func.max(Event.timestamp)).where(recorded).scalar_subquery(),
            select(func.max(Event.timestamp)).where(named).scalar_subquery(),
        )
    )


def for_asset(db: Session, asset: Asset) -> dict[str, Any]:
    involves = asset_alerts(asset)
    last_seen = _latest(Event.asset_id == asset.id, Event.host == asset.hostname)
    return _activity(
        db, involves, _incidents(involves, Incident.hosts.contains([asset.hostname])), last_seen
    )


def for_identity(db: Session, identity: Identity) -> dict[str, Any]:
    involves = identity_alerts(identity)
    last_seen = _latest(Event.identity_id == identity.id, Event.username == identity.username)
    return _activity(
        db,
        involves,
        _incidents(involves, Incident.usernames.contains([identity.username])),
        last_seen,
    )


def list_activity(
    db: Session, rows: list[Asset] | list[Identity]
) -> dict[uuid.UUID, tuple[int, datetime | None]]:
    """Open alerts and the latest event for every row of a list page, in **one** statement
    (Phase 14: it was two per row). The page's rows become a VALUES list; the same conditions
    as `for_asset` / `for_identity` run as correlated subqueries per row inside PostgreSQL,
    so each can still use its index."""
    if not rows:
        return {}
    page = values(
        column("id", Uuid), column("name", String), column("short", String), name="page"
    ).data(
        [
            (r.id, r.hostname, r.hostname.split(".", 1)[0])
            if isinstance(r, Asset)
            else (r.id, r.username, r.username)
            for r in rows
        ]
    )
    if isinstance(rows[0], Asset):
        involves = or_(
            Alert.asset_id == page.c.id,
            Alert.host == page.c.name,
            _short(Alert.host) == page.c.short,
        )
        recorded, named = Event.asset_id == page.c.id, Event.host == page.c.name
    else:
        involves = or_(
            Alert.identity_id == page.c.id,
            Alert.username == page.c.name,
            Alert.target_username == page.c.name,
        )
        recorded, named = Event.identity_id == page.c.id, Event.username == page.c.name
    open_alerts = (
        select(func.count())
        .select_from(Alert)
        .where(involves, Alert.status.in_(ACTIVE_STATUSES))
        .scalar_subquery()
    )
    latest = func.greatest(
        select(func.max(Event.timestamp)).where(recorded).scalar_subquery(),
        select(func.max(Event.timestamp)).where(named).scalar_subquery(),
    )
    result = db.execute(select(page.c.id, open_alerts, latest)).tuples()
    return {row_id: (int(count or 0), seen) for row_id, count, seen in result}
