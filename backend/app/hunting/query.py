"""The structured hunt query and its compiler (docs/threat-hunting.md).

A hunt is data, never SQL: an allowlisted field, an operator from a fixed set and a value,
combined with AND, always inside a time range of at most 31 days. It compiles to a SQLAlchemy
expression; values are bound parameters.

Unlike a detection rule's SQL prefilter, which may select more rows than the rule (Python
decides there), a hunt's SQL IS the answer. So only operators PostgreSQL evaluates exactly
are accepted: no regex (`matches`), no substring operators on IP addresses. Where the
condition language's SQL is exact (`conditions.is_exact`), it is reused as is, so a hunt
filter and a rule condition mean the same thing (case-insensitive for ASCII letters only).
The few exact cases it leaves to Python (equality on ports and on identity_privileged, and
attribute values) are compiled here.
"""

import ipaddress
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import ColumnElement, and_, exists, not_, or_, select

from app.detection.conditions import (
    COLUMNS,
    IP_COLUMNS,
    NUMERIC_COLUMNS,
    Predicate,
    is_exact,
    text_sql,
    valid_field,
)
from app.events.queries import MAX_RANGE
from app.models.alert import Alert, AlertEvent
from app.models.event import Event

MAX_FILTERS = 20
MAX_LIST = 100
MAX_VALUE_LENGTH = 512
MAX_PAGE = 200

HuntOperator = Literal[
    "eq",
    "ne",
    "in",
    "not_in",
    "contains",
    "startswith",
    "endswith",
    "cidr",
    "exists",
    "gt",
    "gte",
    "lt",
    "lte",
]
BOOLEAN_COLUMNS = frozenset({"identity_privileged"})
_TEXT_OPS = {"eq", "ne", "in", "not_in", "contains", "startswith", "endswith", "exists"}
_IP_OPS = {"eq", "ne", "in", "not_in", "cidr", "exists"}
_NUMBER_OPS = {"eq", "ne", "in", "not_in", "gt", "gte", "lt", "lte", "exists"}
_BOOLEAN_OPS = {"eq", "ne", "exists"}

# Fields a hunt may name, for the UI and the docs: every normalized column, plus attributes.
FIELDS = sorted(COLUMNS)

_LAST = re.compile(r"^(?P<amount>\d{1,4})(?P<unit>[mhd])$")
_UNIT = {"m": "minutes", "h": "hours", "d": "days"}


def allowed_operators(field: str) -> set[str]:
    if field in IP_COLUMNS:
        return _IP_OPS
    if field in NUMERIC_COLUMNS:
        return _NUMBER_OPS
    if field in BOOLEAN_COLUMNS:
        return _BOOLEAN_OPS
    return _TEXT_OPS


class HuntFilter(BaseModel):
    """One condition on an event field."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    field: str
    op: HuntOperator
    value: Any = None

    @field_validator("field")
    @classmethod
    def _field(cls, value: str) -> str:
        return valid_field(value)

    @model_validator(mode="after")
    def _check(self) -> "HuntFilter":
        if self.op not in allowed_operators(self.field):
            raise ValueError(f"{self.op} cannot be used on {self.field}")
        values = self.value if isinstance(self.value, list) else [self.value]
        if self.op in ("in", "not_in") and len(values) > MAX_LIST:
            raise ValueError(f"{self.op} takes at most {MAX_LIST} values")
        if self.op != "exists":
            for value in values:
                self._check_value(value)
        self.predicate()  # the condition language validates the value's shape
        return self

    def _check_value(self, value: Any) -> None:
        if self.field in BOOLEAN_COLUMNS:
            if not isinstance(value, bool):
                raise ValueError(f"{self.field} takes true or false")
        elif self.field in NUMERIC_COLUMNS:
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 65535:
                raise ValueError(f"{self.field} takes a whole number from 0 to 65535")
        elif not isinstance(value, str) or len(value) > MAX_VALUE_LENGTH:
            raise ValueError(f"values are text of at most {MAX_VALUE_LENGTH} characters")
        elif self.field in IP_COLUMNS and self.op != "cidr":
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise ValueError(f"{value[:64]!r} is not an IP address") from None

    def predicate(self) -> Predicate:
        return Predicate(field=self.field, op=self.op, value=self.value)

    def to_sql(self) -> ColumnElement[bool]:
        predicate = self.predicate()
        if self.field.startswith("attributes."):
            return self._attribute_sql()
        if is_exact(predicate):
            return predicate.to_sql()
        column = getattr(Event, self.field)  # ports and identity_privileged: eq/ne/in/not_in
        values = self.value if isinstance(self.value, list) else [self.value]
        if self.op in ("eq", "in"):
            matched: ColumnElement[bool] = column.in_(values)
            return matched
        return or_(column.notin_(values), column.is_(None))

    def _attribute_sql(self) -> ColumnElement[bool]:
        """Attribute values compare as text: the JSON value as PostgreSQL writes it (a string
        as is, 5 as "5", true as "true"), ASCII letters ignoring case."""
        key = self.field.split(".", 1)[1]
        text = Event.attributes[key].astext  # NULL when missing or JSON null
        return text_sql(self.op, self.value, text)


class AlertContext(BaseModel):
    """Optional filters on the alerts an event is evidence in."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    in_alert: bool | None = None  # True: evidence in any alert; False: in none
    rule_ids: list[Annotated[str, Field(pattern=r"^[A-Z]{3,5}-\d{3}$")]] = Field(
        default_factory=list, max_length=50
    )
    severities: list[Literal["critical", "high", "medium", "low"]] = Field(
        default_factory=list, max_length=4
    )
    statuses: list[Literal["NEW", "TRIAGED", "IN_PROGRESS", "RESOLVED", "FALSE_POSITIVE"]] = Field(
        default_factory=list, max_length=5
    )

    @model_validator(mode="after")
    def _consistent(self) -> "AlertContext":
        if self.in_alert is False and (self.rule_ids or self.severities or self.statuses):
            raise ValueError("alert filters cannot be combined with in_alert: false")
        return self

    def to_sql(self) -> ColumnElement[bool] | None:
        conditions = []
        if self.rule_ids:
            conditions.append(Alert.rule_id.in_(self.rule_ids))
        if self.severities:
            conditions.append(Alert.severity.in_(self.severities))
        if self.statuses:
            conditions.append(Alert.status.in_(self.statuses))
        if not conditions and self.in_alert is None:
            return None
        cited = exists(
            select(AlertEvent.event_id)
            .join(Alert, Alert.id == AlertEvent.alert_id)
            .where(AlertEvent.event_id == Event.id, *conditions)
        )
        return not_(cited) if self.in_alert is False else cited


class TimeRange(BaseModel):
    """Either an absolute range (`from`, `to`) or a relative one (`last`: "15m", "24h",
    "7d"), which saved hunts use so they always look at recent data."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    start: datetime | None = Field(default=None, alias="from")
    end: datetime | None = Field(default=None, alias="to")
    last: str | None = None

    @model_validator(mode="after")
    def _check(self) -> "TimeRange":
        if self.last is not None:
            if self.start or self.end:
                raise ValueError("give either last or from/to, not both")
            span = self._last()
            if span is None or span <= timedelta(0) or span > MAX_RANGE:
                raise ValueError("last must look like 15m, 24h or 7d, at most 31 days")
            return self
        if self.start is None or self.end is None:
            raise ValueError("a time range needs last, or both from and to")
        for stamp in (self.start, self.end):
            if stamp.tzinfo is None:
                raise ValueError("times need a time zone, e.g. 2026-09-24T00:00:00Z")
        if self.start >= self.end:
            raise ValueError("from must be before to")
        if self.end - self.start > MAX_RANGE:
            raise ValueError("the time range can be at most 31 days")
        return self

    def _last(self) -> timedelta | None:
        match = _LAST.match(self.last or "")
        if not match:
            return None
        return timedelta(**{_UNIT[match["unit"]]: int(match["amount"])})

    def resolve(self, now: datetime | None = None) -> tuple[datetime, datetime]:
        span = self._last()
        if span is not None:
            end = now or datetime.now(UTC)
            return end - span, end
        if self.start is None or self.end is None:  # unreachable after validation
            raise ValueError("incomplete time range")
        return self.start, self.end


class HuntQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    time_range: TimeRange
    filters: list[HuntFilter] = Field(default_factory=list, max_length=MAX_FILTERS)
    alert: AlertContext = Field(default_factory=AlertContext)
    sort: Literal["newest", "oldest"] = "newest"
    limit: int = Field(default=50, ge=1, le=MAX_PAGE)

    def where(self, start: datetime, end: datetime) -> list[ColumnElement[bool]]:
        clauses: list[ColumnElement[bool]] = [Event.timestamp >= start, Event.timestamp <= end]
        clauses += [f.to_sql() for f in self.filters]
        alert = self.alert.to_sql()
        if alert is not None:
            clauses.append(alert)
        return clauses


def after_cursor(sort: str, stamp: datetime, event_id: uuid.UUID) -> ColumnElement[bool]:
    """Rows strictly after (timestamp, id) in the hunt's order (keyset pagination)."""
    if sort == "oldest":
        return or_(Event.timestamp > stamp, and_(Event.timestamp == stamp, Event.id > event_id))
    return or_(Event.timestamp < stamp, and_(Event.timestamp == stamp, Event.id < event_id))
