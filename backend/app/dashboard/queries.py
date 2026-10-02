"""SOC dashboard numbers, all counted in the database on request (brief §19): nothing is
cached, estimated or hardcoded. "Today" is the current UTC day, like every time in the UI.

Event and raw-record totals and the event trend come from `event_daily_counts`, which
database triggers keep equal to the stored rows (migration 0014), so the dashboard does not
count every event on each request (Phase 14, docs/performance.md). Only today's events in
the trend are counted from `events`, because that bucket stops at "now".

Definitions, as shown in the UI:
- records processed: raw records received (parsed, skipped or failed; duplicates excluded).
- events stored: normalized events. Events today: events whose own time is today.
- alerts today: alerts created today. Critical / high alerts: open alerts of that severity.
- open incidents: not resolved or closed. Under investigation: picked up (TRIAGED,
  INVESTIGATING or CONTAINED), as opposed to OPEN (not looked at yet).
- monitored hosts: distinct hosts that sent events in the last 24 hours.
- active rules: enabled rules of the shipped library.
- top rules and top source addresses: by alerts created in the last 7 days.
"""

from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import Date, cast, func, literal_column, select
from sqlalchemy.orm import Session

from app.models.alert import ACTIVE_STATUSES, Alert
from app.models.context import Asset, AssetStatus
from app.models.detection import DetectionRule
from app.models.event import Event
from app.models.incident import ACTIVE_INCIDENT_STATUSES, Incident, IncidentStatus
from app.models.summary import EventDailyCount

LEVELS = ("critical", "high", "medium", "low")
TOP = 5
RECENT_ALERTS = 8
RECENT_INCIDENTS = 5
WORKED = (IncidentStatus.TRIAGED, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED)


def _count(db: Session, statement: Any) -> int:
    return int(db.scalar(statement) or 0)


def _stored(db: Session, kind: str, since: date | None = None) -> int:
    """Rows of `kind` ('event' or 'raw') in the daily counts, from `since` on (UTC days)."""
    statement = select(func.sum(EventDailyCount.records)).where(EventDailyCount.kind == kind)
    if since is not None:
        statement = statement.where(EventDailyCount.day >= since)
    return _count(db, statement)


def summary(db: Session, now: datetime) -> dict[str, Any]:
    today = datetime(now.year, now.month, now.day, tzinfo=UTC)
    week = now - timedelta(days=7)
    open_alerts = Alert.status.in_(ACTIVE_STATUSES)
    by_severity: dict[str, int] = {
        severity: count
        for severity, count in db.execute(
            select(Alert.severity, func.count()).where(open_alerts).group_by(Alert.severity)
        )
    }
    top_rules = db.execute(
        select(Alert.rule_id, DetectionRule.name, func.count())
        .join(DetectionRule, DetectionRule.rule_id == Alert.rule_id)
        .where(Alert.created_at >= week)
        .group_by(Alert.rule_id, DetectionRule.name)
        .order_by(func.count().desc(), Alert.rule_id)
        .limit(TOP)
    ).all()
    top_sources = db.execute(
        select(func.host(Alert.source_ip), func.count())
        .where(Alert.created_at >= week, Alert.source_ip.isnot(None))
        .group_by(Alert.source_ip)
        .order_by(func.count().desc(), Alert.source_ip)
        .limit(TOP)
    ).all()
    return {
        "generated_at": now,
        "records_processed": _stored(db, "raw"),
        "events_stored": _stored(db, "event"),
        "events_today": _stored(db, "event", since=today.date()),
        "alerts_today": _count(
            db, select(func.count()).select_from(Alert).where(Alert.created_at >= today)
        ),
        "open_alerts": sum(by_severity.values()),
        "open_alerts_simulated": _count(
            db, select(func.count()).select_from(Alert).where(open_alerts, Alert.simulated)
        ),
        "critical_alerts": by_severity.get("critical", 0),
        "high_alerts": by_severity.get("high", 0),
        "severity_distribution": [{"severity": s, "count": by_severity.get(s, 0)} for s in LEVELS],
        "open_incidents": _count(
            db,
            select(func.count())
            .select_from(Incident)
            .where(Incident.status.in_(ACTIVE_INCIDENT_STATUSES)),
        ),
        "incidents_under_investigation": _count(
            db, select(func.count()).select_from(Incident).where(Incident.status.in_(WORKED))
        ),
        "monitored_hosts": _count(
            db,
            select(func.count(func.distinct(Event.host))).where(
                Event.timestamp >= now - timedelta(hours=24), Event.host.isnot(None)
            ),
        ),
        "inventory_assets": _count(
            db,
            select(func.count()).select_from(Asset).where(Asset.status == AssetStatus.ACTIVE),
        ),
        "active_rules": _count(
            db,
            select(func.count())
            .select_from(DetectionRule)
            .where(DetectionRule.enabled, DetectionRule.in_library),
        ),
        "library_rules": _count(
            db, select(func.count()).select_from(DetectionRule).where(DetectionRule.in_library)
        ),
        "top_rules": [
            {"rule_id": rule_id, "name": name, "alerts": count}
            for rule_id, name, count in top_rules
        ],
        "top_source_ips": [{"source_ip": ip, "alerts": count} for ip, count in top_sources],
    }


def recent_alerts(db: Session) -> list[Alert]:
    return list(
        db.scalars(select(Alert).order_by(Alert.created_at.desc(), Alert.id).limit(RECENT_ALERTS))
    )


def recent_incidents(db: Session) -> list[Incident]:
    return list(
        db.scalars(select(Incident).order_by(Incident.created_at.desc()).limit(RECENT_INCIDENTS))
    )


def _day(column: Any) -> Any:
    """The UTC calendar day of a timestamp column."""
    return cast(func.timezone("UTC", column), Date)


def trends(db: Session, days: int, now: datetime) -> list[dict[str, Any]]:
    """Per UTC day, oldest first, every day present (zero when nothing happened): alerts
    created (by severity), incidents created, and events (by their own time)."""
    first = (now - timedelta(days=days - 1)).date()
    start = datetime(first.year, first.month, first.day, tzinfo=UTC)
    rows: dict[date, dict[str, Any]] = {
        first + timedelta(days=i): {
            "day": first + timedelta(days=i),
            "alerts": {level: 0 for level in LEVELS},
            "incidents": 0,
            "events": 0,
        }
        for i in range(days)
    }
    for day, severity, count in db.execute(
        select(_day(Alert.created_at), Alert.severity, func.count())
        .where(Alert.created_at >= start)
        .group_by(literal_column("1"), Alert.severity)
    ):
        if day in rows:
            rows[day]["alerts"][severity] = count
    for day, count in db.execute(
        select(_day(Incident.created_at), func.count())
        .where(Incident.created_at >= start)
        .group_by(literal_column("1"))
    ):
        if day in rows:
            rows[day]["incidents"] = count
    today = now.date()
    for day, count in db.execute(
        select(EventDailyCount.day, EventDailyCount.records).where(
            EventDailyCount.kind == "event",
            EventDailyCount.day >= first,
            EventDailyCount.day < today,
        )
    ):
        if day in rows:
            rows[day]["events"] = count
    if today in rows:  # today stops at "now": events dated later today are not counted yet
        midnight = datetime(today.year, today.month, today.day, tzinfo=UTC)
        rows[today]["events"] = _count(
            db,
            select(func.count())
            .select_from(Event)
            .where(Event.timestamp >= midnight, Event.timestamp <= now),
        )
    return list(rows.values())
