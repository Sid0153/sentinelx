import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.detection import RunStatus, RunTrigger


class TechniqueRef(BaseModel):
    technique_id: str
    name: str
    tactics: list[str]
    url: str
    reason: str
    indicator: str | None  # None: the rule as a whole


class RuleSummary(BaseModel):
    rule_id: str
    name: str
    category: str
    kind: str
    severity: str
    confidence: str
    enabled: bool
    in_library: bool
    version: int
    techniques: list[str]
    match_count: int
    error_count: int
    last_run_at: datetime | None
    last_match_at: datetime | None


class RuleDetail(RuleSummary):
    description: str
    definition: dict[str, Any]  # the effective definition, as it runs
    overrides: dict[str, Any]  # what admins changed
    tunable: dict[str, Any]  # what admins may change, and within which bounds
    mitre: list[TechniqueRef]


class RuleVersionPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    version: int
    source: str
    changed_by: uuid.UUID | None
    change_reason: str | None
    overrides: dict[str, Any]
    definition: dict[str, Any]
    created_at: datetime


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    start: datetime = Field(alias="from")
    end: datetime = Field(alias="to")


class RunSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    trigger: RunTrigger
    batch_id: uuid.UUID | None
    requested_by: uuid.UUID | None
    range_start: datetime
    range_end: datetime
    status: RunStatus
    detection_count: int
    alerts_created: int
    alerts_updated: int
    duration_ms: int
    started_at: datetime


class RunDetail(RunSummary):
    rule_results: dict[str, Any]
    detections: list[dict[str, Any]]


class TechniquePublic(BaseModel):
    technique_id: str
    name: str
    tactics: list[str]
    attack_version: str
    url: str
    rules: list[str]  # SentinelX rules mapped to it: implemented coverage, not all of ATT&CK
