import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.alert import AlertStatus, Disposition
from app.schemas.ingestion import EventPublic


def _ip_text(value: object) -> str | None:
    return None if value is None else str(value)


class AlertSummary(BaseModel):
    """One row of the alert queue."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    rule_id: str
    title: str
    severity: str
    confidence: str
    status: AlertStatus
    disposition: Disposition | None
    priority_score: int
    priority_band: str
    host: str | None
    username: str | None
    source_ip: str | None
    destination_ip: str | None
    event_count: int
    evidence_truncated: bool
    detection_count: int
    first_event_at: datetime
    last_event_at: datetime
    created_at: datetime
    updated_at: datetime
    simulated: bool

    _ips = field_validator("source_ip", "destination_ip", mode="before")(_ip_text)


class PriorityFactor(BaseModel):
    factor: str
    value: str
    points: int


class AlertTechnique(BaseModel):
    technique: str
    name: str
    tactics: list[str]
    reason: str
    attack_version: str
    url: str


class AlertActivity(BaseModel):
    """A status change, from the audit log."""

    at: datetime
    actor: str | None
    from_status: str
    to_status: str
    disposition: str | None
    reason: str | None


class RelatedAlert(BaseModel):
    id: uuid.UUID
    rule_id: str
    title: str
    status: AlertStatus
    priority_score: int
    priority_band: str
    last_event_at: datetime
    shared: list[str]  # which entities it shares with this alert, e.g. ["host web-01"]


class AlertDetail(AlertSummary):
    rule_version: int
    indicator: str | None
    kind: str
    category: str
    description: str
    target_username: str | None
    asset_id: uuid.UUID | None
    asset_hostname: str | None
    identity_id: uuid.UUID | None
    identity_username: str | None
    priority_breakdown: list[PriorityFactor]
    risk_model_version: str
    group_values: dict[str, Any]
    explanation: str
    facts: dict[str, Any]
    entities: dict[str, list[str]]
    investigation: list[str]
    response: list[str]
    mitre: list[AlertTechnique]
    history: list[dict[str, Any]]
    peak_count: int
    previous_alert_id: uuid.UUID | None
    triaged_at: datetime | None
    resolved_at: datetime | None
    resolved_by: str | None
    status_changed_at: datetime | None
    status_changed_by: str | None
    status_note: str | None
    allowed_transitions: list[AlertStatus]
    activity: list[AlertActivity]
    related: list[RelatedAlert]
    incident_id: uuid.UUID | None = None
    incident_number: int | None = None


class EvidenceEvent(EventPublic):
    raw_text: str  # the raw record as text (at most 4,096 characters shown)
    raw_truncated: bool


class TransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AlertStatus
    disposition: Disposition | None = None
    reason: str | None = Field(default=None, min_length=3, max_length=2000)

    @field_validator("reason", mode="before")
    @classmethod
    def _blank_is_none(cls, value: object) -> object:
        return value.strip() or None if isinstance(value, str) else value
