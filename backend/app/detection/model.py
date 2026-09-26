"""Rule definitions and what evaluating them produces (docs/detection-engine.md, ADR-0004).

A rule is YAML validated against `Rule`. Validation is strict and happens when the library is
loaded, so a rule with a typo, an unknown field, a missing parameter for its kind or an
explanation placeholder that will never be filled stops the application from starting, instead
of failing quietly at run time.
"""

import enum
import ipaddress
import re
import string
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.detection.conditions import MAX_DEPTH, Condition, depth, valid_field

RULE_ID = re.compile(r"^[A-Z]{3,5}-\d{3}$")
TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_DURATION = re.compile(r"^(?P<amount>\d{1,6})(?P<unit>[smhd])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


class Severity(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


RuleKind = Literal["single", "threshold", "distinct", "sequence", "new_value"]
RuleCategory = Literal[
    "authentication", "privilege", "account", "process", "network", "web", "application"
]


def parse_duration(value: Any) -> Any:
    """'5m', '60s', '14d' -> timedelta. Anything else goes to pydantic (ISO 8601 durations,
    which is how stored definitions serialize)."""
    if isinstance(value, str) and (match := _DURATION.match(value.strip())):
        return timedelta(**{_UNITS[match["unit"]]: int(match["amount"])})
    return value


def format_duration(value: timedelta) -> str:
    """timedelta -> '5 min', '38 s', '2 h 5 min', '14 days' for explanations."""
    seconds = int(value.total_seconds())
    if seconds < 60:
        return f"{seconds} s"
    if seconds % 86400 == 0:
        days = seconds // 86400
        return f"{days} day{'s' if days != 1 else ''}"
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    parts = [f"{hours} h"] if hours else []
    if minutes:
        parts.append(f"{minutes} min")
    if secs and not hours:
        parts.append(f"{secs} s")
    return " ".join(parts)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class MitreRef(_Strict):
    technique: str
    reason: str = Field(min_length=10, max_length=600)

    @field_validator("technique")
    @classmethod
    def _technique(cls, value: str) -> str:
        if not TECHNIQUE_ID.match(value):
            raise ValueError("technique IDs look like T1110 or T1110.001")
        return value


class Step(_Strict):
    name: str = Field(pattern=r"^[a-z][a-z_]{0,31}$")
    match: Condition
    min_count: int = Field(default=1, ge=1, le=1000)


class Indicator(_Strict):
    """One named pattern of a single-event rule, with its own mapping (PROC-001, PRIV-001)."""

    id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,39}$")
    name: str = Field(min_length=3, max_length=120)
    match: Condition
    mitre: list[MitreRef] = Field(min_length=1)
    severity: Severity | None = None
    confidence: Confidence | None = None


class Exclusion(_Strict):
    """Events matching an exclusion are ignored by the rule (an allowlist entry)."""

    field: Literal["source_ip", "username", "target_username", "host"]
    value: str = Field(min_length=1, max_length=253)
    comment: str | None = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def _ip_is_network(self) -> Self:
        if self.field == "source_ip":
            ipaddress.ip_network(self.value, strict=False)
        return self


class IntRange(_Strict):
    min: int = Field(ge=1)
    max: int = Field(ge=1)


class DurationRange(_Strict):
    min: timedelta
    max: timedelta

    @field_validator("min", "max", mode="before")
    @classmethod
    def _duration(cls, value: Any) -> Any:
        return parse_duration(value)


class Tunables(_Strict):
    """What an admin may change (and within which bounds). Everything else is fixed: the
    logic of a rule changes only through a reviewed change to the library."""

    threshold: IntRange | None = None
    time_window: DurationRange | None = None
    severity: bool = True
    confidence: bool = True
    enabled: bool = True
    exclusions: bool = True


# Placeholders every explanation may use, plus per-kind extras (validated at load time).
COMMON_FACTS = frozenset(
    {
        "rule_id",
        "rule_name",
        "count",
        "first_seen",
        "last_seen",
        "span",
        "host",
        "username",
        "target_username",
        "target_account",
        "source_ip",
        "source_ip_scope",
        "destination",
        "process_name",
        "command_line",
    }
)
KIND_FACTS: dict[str, frozenset[str]] = {
    "single": frozenset({"indicator", "indicator_name"}),
    "threshold": frozenset({"threshold", "time_window"}),
    "distinct": frozenset({"threshold", "time_window", "distinct_count", "values_sample"}),
    "sequence": frozenset({"threshold", "time_window", "gap"}),
    "new_value": frozenset({"value", "lookback", "history_count"}),
}


class Rule(_Strict):
    id: str
    name: str = Field(min_length=5, max_length=120)
    description: str = Field(min_length=10, max_length=1000)
    category: RuleCategory
    kind: RuleKind
    severity: Severity
    confidence: Confidence
    enabled: bool = True

    match: Condition | None = None  # every kind except sequence
    steps: list[Step] | None = None  # sequence: ordered, 2 to 5 steps
    indicators: list[Indicator] | None = None  # single: named patterns (at least one matches)

    group_by: list[str] = Field(min_length=1, max_length=4)
    threshold: int | None = Field(default=None, ge=1, le=100_000)
    distinct_field: str | None = None
    time_window: timedelta | None = None
    max_gap: timedelta | None = None  # sequence: most time between consecutive steps
    value_field: str | None = None  # new_value
    value_transform: Literal["ip_network"] | None = None
    lookback: timedelta | None = None
    min_history: int | None = Field(default=None, ge=1, le=10_000)

    tunable: Tunables = Tunables()
    exclusions: list[Exclusion] = Field(default_factory=list, max_length=100)
    mitre: list[MitreRef] = Field(default_factory=list)
    explanation: str = Field(min_length=10, max_length=600)
    investigation: list[str] = Field(min_length=1, max_length=12)
    response: list[str] = Field(min_length=1, max_length=12)

    @field_validator("time_window", "max_gap", "lookback", mode="before")
    @classmethod
    def _durations(cls, value: Any) -> Any:
        return parse_duration(value)

    @field_validator("id")
    @classmethod
    def _rule_id(cls, value: str) -> str:
        if not RULE_ID.match(value):
            raise ValueError("rule IDs look like AUTH-001")
        return value

    @field_validator("group_by")
    @classmethod
    def _group_fields(cls, value: list[str]) -> list[str]:
        return [valid_field(name, allow_derived=True) for name in value]

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        kind = self.kind
        needs: dict[str, tuple[str, ...]] = {
            "single": ("match",),
            "threshold": ("match", "threshold", "time_window"),
            "distinct": ("match", "threshold", "time_window", "distinct_field"),
            "sequence": ("steps", "threshold", "time_window"),
            "new_value": ("match", "value_field", "lookback", "min_history"),
        }
        missing = [name for name in needs[kind] if getattr(self, name) is None]
        if missing:
            raise ValueError(f"a {kind} rule needs {', '.join(missing)}")
        if kind != "sequence" and self.steps is not None:
            raise ValueError("only sequence rules have steps")
        if kind == "sequence":
            if not 2 <= len(self.steps or []) <= 5:
                raise ValueError("a sequence has 2 to 5 steps")
            if self.match is not None:
                raise ValueError("a sequence rule filters with its steps, not match")
        if self.indicators is not None and kind != "single":
            raise ValueError("only single-event rules have indicators")
        if self.distinct_field:
            valid_field(self.distinct_field, allow_derived=True)
        if self.value_field:
            valid_field(self.value_field, allow_derived=True)
        if not self.mitre and not self.indicators:
            raise ValueError("map the rule to at least one ATT&CK technique")
        for condition in self._conditions():
            if depth(condition) > MAX_DEPTH:
                raise ValueError(f"conditions are nested at most {MAX_DEPTH} levels deep")
        if self.tunable.threshold and self.threshold is not None:
            bounds = self.tunable.threshold
            if not bounds.min <= self.threshold <= bounds.max:
                raise ValueError("the default threshold is outside its tunable bounds")
        if self.tunable.time_window and self.time_window is not None:
            window_bounds = self.tunable.time_window
            if not window_bounds.min <= self.time_window <= window_bounds.max:
                raise ValueError("the default time window is outside its tunable bounds")
        self._check_placeholders()
        return self

    def _conditions(self) -> list[Any]:
        found: list[Any] = [self.match] if self.match is not None else []
        found += [step.match for step in self.steps or []]
        found += [indicator.match for indicator in self.indicators or []]
        return found

    def _check_placeholders(self) -> None:
        allowed = COMMON_FACTS | KIND_FACTS[self.kind]
        if self.kind == "sequence":
            allowed |= {f"{step.name}_count" for step in self.steps or []}
        texts = [self.explanation, *self.investigation, *self.response]
        for text in texts:
            for match in string.Template.pattern.finditer(text):
                name = match["named"] or match["braced"]
                if name and name not in allowed and not name.startswith("attr_"):
                    raise ValueError(f"unknown placeholder ${name} in {text[:40]!r}")

    def techniques(self) -> set[str]:
        found = {ref.technique for ref in self.mitre}
        for indicator in self.indicators or []:
            found |= {ref.technique for ref in indicator.mitre}
        return found

    def window(self) -> timedelta:
        """How far around new events the engine must look to evaluate this rule."""
        return max(
            (d for d in (self.time_window, self.max_gap) if d is not None),
            default=timedelta(0),
        )


# ---------- what evaluation produces ----------


@dataclass(frozen=True)
class Match:
    """An evaluator's raw result: which events, grouped how, and the numbers behind it."""

    group: dict[str, Any]
    events: list[Any]  # DetectionEvent, in time order
    facts: dict[str, Any] = field(default_factory=dict)
    indicator: Indicator | None = None


@dataclass(frozen=True)
class Detection:
    """A rule matched: everything an analyst (and the alert engine, Phase 7) needs."""

    rule_id: str
    rule_name: str
    rule_version: int
    kind: str
    category: str
    severity: Severity
    confidence: Confidence
    group: dict[str, Any]
    evidence_event_ids: list[str]  # first 50 and last 50 events; event_count is exact
    event_count: int
    first_seen: datetime
    last_seen: datetime
    facts: dict[str, Any]
    entities: dict[str, list[str]]
    indicator: str | None
    mitre: list[MitreRef]
    explanation: str
    investigation: list[str]
    response: list[str]
    batch_ids: list[str] = field(default_factory=list)
