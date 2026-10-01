from datetime import date, datetime

from pydantic import BaseModel

from app.schemas.alert import AlertSummary
from app.schemas.incident import IncidentSummary


class SeverityCount(BaseModel):
    severity: str
    count: int


class TopRule(BaseModel):
    rule_id: str
    name: str
    alerts: int


class TopSource(BaseModel):
    source_ip: str
    alerts: int


class DashboardSummary(BaseModel):
    """Every number is counted in the database when requested (definitions in docs/api.md)."""

    generated_at: datetime
    records_processed: int
    events_stored: int
    events_today: int
    alerts_today: int
    open_alerts: int
    open_alerts_simulated: int
    critical_alerts: int
    high_alerts: int
    severity_distribution: list[SeverityCount]
    open_incidents: int
    incidents_under_investigation: int
    monitored_hosts: int
    inventory_assets: int
    active_rules: int
    library_rules: int
    top_rules: list[TopRule]
    top_source_ips: list[TopSource]
    recent_alerts: list[AlertSummary]
    recent_incidents: list[IncidentSummary]


class AlertsBySeverity(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


class TrendDay(BaseModel):
    day: date
    alerts: AlertsBySeverity
    incidents: int
    events: int


class Trends(BaseModel):
    days: int
    items: list[TrendDay]


class ContextActivity(BaseModel):
    """An asset's or an identity's alerts, incidents and latest activity."""

    open_alerts: int
    total_alerts: int
    open_incidents: int
    total_incidents: int
    last_seen_at: datetime | None
    recent_alerts: list[AlertSummary]
    incidents: list[IncidentSummary]
