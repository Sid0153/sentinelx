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

from sqlalchemy import ColumnElement, func, or_, select
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


def open_alert_counts(db: Session, rows: list[Asset] | list[Identity]) -> dict[uuid.UUID, int]:
    """Open alerts per row, for a list page (one query per row; pages are at most 200)."""
    counts: dict[uuid.UUID, int] = {}
    for row in rows:
        involves = asset_alerts(row) if isinstance(row, Asset) else identity_alerts(row)
        counts[row.id] = int(
            db.scalar(select(func.count()).where(involves, Alert.status.in_(ACTIVE_STATUSES))) or 0
        )
    return counts


def last_seen(db: Session, rows: list[Asset] | list[Identity]) -> dict[uuid.UUID, datetime | None]:
    found: dict[uuid.UUID, datetime | None] = {}
    for row in rows:
        latest = (
            _latest(Event.asset_id == row.id, Event.host == row.hostname)
            if isinstance(row, Asset)
            else _latest(Event.identity_id == row.id, Event.username == row.username)
        )
        found[row.id] = db.scalar(latest)
    return found
