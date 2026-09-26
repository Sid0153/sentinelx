import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.incident import (
    EvidenceAction,
    EvidenceTag,
    IncidentDisposition,
    IncidentStatus,
)
from app.schemas.alert import AlertSummary, PriorityFactor


def _blank_is_none(value: object) -> object:
    return value.strip() or None if isinstance(value, str) else value


class UserRef(BaseModel):
    id: uuid.UUID
    email: str


class IncidentSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    number: int
    title: str
    status: IncidentStatus
    severity: str
    risk_score: int
    risk_band: str
    alert_count: int
    hosts: list[str]
    usernames: list[str]
    source_ips: list[str]
    tactics: list[str]
    first_activity_at: datetime
    last_activity_at: datetime
    created_at: datetime
    updated_at: datetime
    simulated: bool
    assigned_to: UserRef | None = None


class LinkedAlert(BaseModel):
    alert: AlertSummary
    link_strength: str
    shared_entities: list[str]
    reason: str
    link_source: str
    linked_at: datetime


class NotePublic(BaseModel):
    id: uuid.UUID
    author: str | None
    body: str
    created_at: datetime


class PinPublic(BaseModel):
    id: uuid.UUID
    event_id: uuid.UUID | None
    alert_id: uuid.UUID | None
    label: str
    tag: EvidenceTag
    comment: str | None
    pinned_by: str | None
    pinned_at: datetime


class ActivityPublic(BaseModel):
    at: datetime
    actor: str | None  # None: the correlation engine
    kind: str
    details: dict[str, Any]


class IncidentTechnique(BaseModel):
    technique: str
    name: str
    tactics: list[str]
    attack_version: str
    url: str
    rules: list[str]
    reasons: list[str]


class ResponseGroup(BaseModel):
    rule_id: str
    title: str
    steps: list[str]


class RelatedIncident(BaseModel):
    id: uuid.UUID
    number: int
    title: str
    status: IncidentStatus


class IncidentDetail(IncidentSummary):
    summary: str
    created_reason: str
    risk_breakdown: list[PriorityFactor]
    risk_model_version: str
    techniques: list[str]
    disposition: IncidentDisposition | None
    resolution: str | None
    resolved_at: datetime | None
    resolved_by: str | None
    closed_at: datetime | None
    title_edited: bool
    related_incident: RelatedIncident | None
    alerts: list[LinkedAlert]
    notes: list[NotePublic]
    evidence: list[PinPublic]
    activity: list[ActivityPublic]
    mitre: list[IncidentTechnique]
    response: list[ResponseGroup]
    allowed_transitions: list[IncidentStatus]


class TimelineEntry(BaseModel):
    at: datetime
    kind: str  # event, alert, activity
    id: uuid.UUID
    event: dict[str, Any] | None = None
    alert: dict[str, Any] | None = None
    activity: dict[str, Any] | None = None


class TimelinePage(BaseModel):
    items: list[TimelineEntry]
    next_cursor: str | None
    limit: int


class IncidentTransition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: IncidentStatus
    disposition: IncidentDisposition | None = None
    resolution: str | None = Field(default=None, min_length=3, max_length=4000)
    reason: str | None = Field(default=None, min_length=3, max_length=2000)

    _blanks = field_validator("resolution", "reason", mode="before")(_blank_is_none)


class AssignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assignee_id: uuid.UUID | None  # None unassigns


class NoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: str = Field(min_length=1, max_length=10_000)


class EvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: uuid.UUID | None = None
    alert_id: uuid.UUID | None = None
    action: EvidenceAction = EvidenceAction.PIN
    tag: EvidenceTag = EvidenceTag.NEEDS_REVIEW
    comment: str | None = Field(default=None, max_length=1000)


class LinkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: uuid.UUID
    reason: str = Field(min_length=3, max_length=400)


class ReasonRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=3, max_length=400)


class RenameRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=3, max_length=300)


class SettingsPublic(BaseModel):
    correlation_window_minutes: int
    sequence_window_minutes: int
