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
    incidents_created: int
    incidents_updated: int
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


class RuleMetricsPublic(BaseModel):
    rule_id: str
    name: str
    category: str
    severity: str
    enabled: bool
    in_library: bool
    alerts: int  # alerts the rule created in the period
    open: int
    confirmed: int  # resolved as confirmed malicious
    benign: int  # resolved as benign or expected
    false_positives: int
    closed: int
    false_positive_rate: float | None  # false positives / closed; null until one is closed
    median_triage_seconds: float | None  # creation to first triage
    median_resolve_seconds: float | None  # creation to closing (resolved or false positive)
    match_count: int  # detections, all time
    last_match_at: datetime | None


class DetectionMetrics(BaseModel):
    days: int
    start: datetime = Field(serialization_alias="from")
    end: datetime = Field(serialization_alias="to")
    items: list[RuleMetricsPublic]


class CoverageRule(BaseModel):
    rule_id: str
    name: str
    category: str
    severity: str
    enabled: bool
    indicator: str | None
    reason: str
    alerts: int
    last_triggered_at: datetime | None


class CoverageTechnique(BaseModel):
    technique_id: str
    name: str
    url: str
    tactics: list[str]
    active: bool  # at least one enabled rule
    alerts: int
    last_triggered_at: datetime | None
    rules: list[CoverageRule]


class CoverageTactic(BaseModel):
    id: str
    name: str
    url: str
    techniques: list[str]  # technique IDs covered under this tactic
    active: bool  # at least one of them has an enabled rule


class CoverageSummary(BaseModel):
    tactics_total: int
    tactics_covered: int
    techniques_covered: int
    rules_in_library: int
    rules_enabled: int
    categories: dict[str, int]  # enabled rules per category


class Coverage(BaseModel):
    label: str  # always "Implemented coverage"
    attack_version: str
    checked_on: str
    days: int
    start: datetime = Field(serialization_alias="from")
    end: datetime = Field(serialization_alias="to")
    summary: CoverageSummary
    tactics: list[CoverageTactic]
    techniques: list[CoverageTechnique]


class PlaygroundRule(BaseModel):
    rule_id: str
    name: str
    kind: str
    version: int
    severity: str
    confidence: str
    threshold: int | None
    time_window: str | None  # "5 min"
    tried: dict[str, Any]  # what-if values used; empty: the rule as it runs


class PlaygroundLine(BaseModel):
    line: int
    status: str  # parsed, skipped, failed
    code: str | None  # why it was skipped or failed
    timestamp: datetime | None = None
    event: str | None = None  # "authentication/logon failure"
    host: str | None = None
    username: str | None = None
    target_username: str | None = None
    source_ip: str | None = None
    process_name: str | None = None
    excluded: bool = False  # ignored by an exclusion or an active suppression
    matched: bool | None = None  # passed the rule's condition (null: sequence rules)
    steps: list[str] = []  # sequence steps this event matches
    evidence: bool = False  # part of a detection


class PlaygroundDetection(BaseModel):
    explanation: str
    severity: str
    confidence: str
    indicator: str | None
    event_count: int
    first_seen: datetime
    last_seen: datetime
    evidence_lines: list[int]
    group: dict[str, Any]
    mitre: list[str]
    investigation: list[str]
    response: list[str]


class PlaygroundSummary(BaseModel):
    lines: int
    parsed: int
    skipped: int
    failed: int
    excluded: int
    matched: int  # events passing the condition (or any sequence step)
    detections: int


class PlaygroundResult(BaseModel):
    triggered: bool
    rule: PlaygroundRule
    summary: PlaygroundSummary
    detections: list[PlaygroundDetection]
    lines: list[PlaygroundLine]
