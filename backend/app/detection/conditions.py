"""The safe condition language rules are written in (docs/detection-engine.md).

A condition is data, never code:

    {"all": [{"field": "event_category", "op": "eq", "value": "authentication"},
             {"any": [...]}, {"not": {...}}]}

- Fields come from an allowlist (normalized columns, `attributes.<key>`, and a few derived
  fields); an unknown field fails validation when the rule is loaded.
- Operators come from a fixed set. There is no eval, exec or templating anywhere.
- Text comparisons ignore the case of ASCII letters only: `fold()` here and `translate()` in
  SQL do exactly the same thing whatever the database locale. Unicode case folding is not
  used on purpose: it maps look-alikes onto ASCII ("ſvc" -> "svc", Kelvin sign -> "k"), which
  would let a crafted name match an exclusion, and PostgreSQL's lower() folds differently
  depending on the locale.
- `matches` (regex) patterns are compiled once at load time, input is capped at 8 KiB, and
  only rules shipped in the repository contain them: admins cannot write conditions at all,
  only tune numbers (ADR-0004).

The same condition is evaluated in Python (authoritative) and compiled to a SQL prefilter
(`to_sql`). The prefilter may select MORE rows than the Python condition, never fewer: an
operator SQL cannot express exactly becomes TRUE there, and Python decides.
"""

import ipaddress
import re
import string
from dataclasses import dataclass
from functools import cached_property
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import ColumnElement, and_, false, func, not_, or_, true

from app.detection.events import DERIVED_FIELDS, DetectionEvent
from app.models.event import Event

MAX_MATCH_INPUT = 8192
MAX_DEPTH = 4

# Normalized columns a condition may name. `attributes.<key>` is also allowed.
COLUMNS = frozenset(
    {
        "source_type",
        "event_category",
        "event_action",
        "event_outcome",
        "host",
        "host_ip",
        "username",
        "user_domain",
        "target_username",
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_port",
        "protocol",
        "service",
        "process_name",
        "parent_process_name",
        "command_line",
        "session_id",
        "message",
        "source_ip_scope",
        "asset_criticality",
        "identity_privileged",
    }
)
IP_COLUMNS = frozenset({"host_ip", "source_ip", "destination_ip"})
NUMERIC_COLUMNS = frozenset({"source_port", "destination_port"})
# Text columns stored without ASCII capitals: controlled vocabularies, and names the normalizer
# lowercases (NormalizedEvent; host and username also have a database check). The prefilter
# compares them directly, so their indexes can be used.
LOWERCASE_COLUMNS = frozenset(
    {
        "source_type",
        "event_category",
        "event_action",
        "event_outcome",
        "source_ip_scope",
        "asset_criticality",
        "host",
        "username",
        "target_username",
        "user_domain",
        "process_name",
        "parent_process_name",
        "protocol",
        "service",
    }
)
_ATTRIBUTE = re.compile(r"^attributes\.[a-z][a-z0-9_]{0,63}$")

Operator = Literal[
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
    "matches",
]


def valid_field(name: str, *, allow_derived: bool = False) -> str:
    if name in COLUMNS or _ATTRIBUTE.match(name) or (allow_derived and name in DERIVED_FIELDS):
        return name
    raise ValueError(f"unknown field {name[:64]!r}")


_UPPER, _LOWER = string.ascii_uppercase, string.ascii_lowercase
_ASCII_LOWER = str.maketrans(_UPPER, _LOWER)


def fold(value: Any) -> str:
    """Case-insensitive comparison key: ASCII letters lowered, everything else unchanged."""
    if isinstance(value, bool):
        return "true" if value else "false"  # as JSON (and so PostgreSQL) writes it
    return str(value).translate(_ASCII_LOWER)


def _sql_fold(column: ColumnElement[Any]) -> ColumnElement[str]:
    folded: ColumnElement[str] = func.translate(column, _UPPER, _LOWER)
    return folded


class Predicate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    field: str
    op: Operator
    value: Any = None

    @field_validator("field")
    @classmethod
    def _field(cls, value: str) -> str:
        return valid_field(value)

    @model_validator(mode="after")
    def _value_fits_operator(self) -> "Predicate":
        op, value = self.op, self.value
        if op == "exists":
            if value not in (None, True, False):
                raise ValueError("exists takes true, false or nothing")
        elif op in ("in", "not_in"):
            if not isinstance(value, list) or not value or len(value) > 200:
                raise ValueError(f"{op} needs a list of 1 to 200 values")
        elif op in ("gt", "gte", "lt", "lte"):
            if self.field not in NUMERIC_COLUMNS or not isinstance(value, int):
                raise ValueError(f"{op} needs a numeric field and an integer")
        elif op == "cidr":
            if self.field not in IP_COLUMNS:
                raise ValueError("cidr needs an IP field")
            ipaddress.ip_network(str(value), strict=False)
        elif op == "matches":
            if not isinstance(value, str) or len(value) > 512:
                raise ValueError("matches needs a pattern of at most 512 characters")
            try:
                re.compile(value)
            except re.error as exc:  # not a ValueError: pydantic would let it escape
                raise ValueError(f"invalid pattern: {exc}") from exc
        elif value is None or isinstance(value, list | dict):
            raise ValueError(f"{op} needs a single value")
        return self

    @cached_property
    def _pattern(self) -> re.Pattern[str]:
        return re.compile(str(self.value))

    @cached_property
    def _network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        return ipaddress.ip_network(str(self.value), strict=False)

    def evaluate(self, event: DetectionEvent) -> bool:
        actual = event.get(self.field)
        op = self.op
        if op == "exists":
            present = actual is not None and actual != ""
            return present if self.value in (None, True) else not present
        if actual is None:
            return op in ("ne", "not_in")
        if op == "eq":
            return fold(actual) == fold(self.value)
        if op == "ne":
            return fold(actual) != fold(self.value)
        if op == "in":
            return fold(actual) in {fold(v) for v in self.value}
        if op == "not_in":
            return fold(actual) not in {fold(v) for v in self.value}
        if op == "contains":
            return fold(self.value) in fold(actual)
        if op == "startswith":
            return fold(actual).startswith(fold(self.value))
        if op == "endswith":
            return fold(actual).endswith(fold(self.value))
        if op == "cidr":
            try:
                ip = ipaddress.ip_address(str(actual))
            except ValueError:
                return False
            return ip.version == self._network.version and ip in self._network
        if op == "matches":
            return self._pattern.search(str(actual)[:MAX_MATCH_INPUT]) is not None
        if not isinstance(actual, int) or isinstance(actual, bool):
            return False
        limit = int(self.value)
        if op == "gt":
            return actual > limit
        if op == "gte":
            return actual >= limit
        if op == "lt":
            return actual < limit
        return actual <= limit

    def to_sql(self) -> ColumnElement[bool]:
        op, value = self.op, self.value
        if op == "matches":
            return true()  # Python regex semantics differ from PostgreSQL's: Python decides
        if self.field.startswith("attributes."):
            return self._attribute_sql()
        column: ColumnElement[Any] = getattr(Event, self.field)
        if self.field in IP_COLUMNS:
            return self._ip_sql(column)
        if self.field in NUMERIC_COLUMNS or self.field == "identity_privileged":
            if op == "exists":
                present: ColumnElement[bool] = column.isnot(None)
                return present if value in (None, True) else column.is_(None)
            if op in ("gt", "gte", "lt", "lte"):
                bound = int(value)
                comparisons = {
                    "gt": column > bound,
                    "gte": column >= bound,
                    "lt": column < bound,
                    "lte": column <= bound,
                }
                return comparisons[op]
            return true()  # equality on numbers/booleans: rare in rules, Python decides
        return self._text_sql(column, stored_lowercase=self.field in LOWERCASE_COLUMNS)

    def _text_sql(
        self, column: ColumnElement[Any], *, stored_lowercase: bool = False
    ) -> ColumnElement[bool]:
        """Exactly evaluate() for a text value (NULL is "absent", like None)."""
        op, value = self.op, self.value
        if op == "exists":
            present: ColumnElement[bool] = and_(column.isnot(None), column != "")
            return present if value in (None, True) else not_(present) | column.is_(None)
        # Folding a column that holds no ASCII capitals changes nothing, and comparing the
        # column itself lets PostgreSQL use its indexes (event_category, event_action, ...).
        folded = column if stored_lowercase else _sql_fold(column)
        if op == "eq":
            return folded == fold(value)
        if op == "ne":
            return (folded != fold(value)) | column.is_(None)
        if op == "in":
            return folded.in_([fold(v) for v in value])
        if op == "not_in":
            return folded.notin_([fold(v) for v in value]) | column.is_(None)
        pattern = fold(value).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        wildcard = {
            "contains": f"%{pattern}%",
            "startswith": f"{pattern}%",
            "endswith": f"%{pattern}",
        }
        return folded.like(wildcard[op], escape="\\")

    def _attribute_sql(self) -> ColumnElement[bool]:
        """Attributes are JSON scalars. Only string values are compared in SQL (their text is
        exactly what Python sees); numbers and booleans are written differently in JSON and in
        Python, so for them the prefilter lets the row through and Python decides."""
        key = self.field.split(".", 1)[1]
        value_text = Event.attributes[key].astext  # NULL when missing or JSON null
        if self.op == "exists":
            return self._text_sql(value_text)
        is_string = func.jsonb_typeof(Event.attributes[key]) == "string"
        not_string: ColumnElement[bool] = not_(is_string) | value_text.is_(None)
        return or_(and_(is_string, self._text_sql(value_text)), not_string)

    def _ip_sql(self, column: ColumnElement[Any]) -> ColumnElement[bool]:
        op, value = self.op, self.value
        if op == "exists":
            present: ColumnElement[bool] = column.isnot(None)
            return present if value in (None, True) else column.is_(None)
        if op == "cidr":
            contained: ColumnElement[bool] = column.op("<<=")(str(self._network))
            return contained
        if op in ("eq", "ne", "in", "not_in"):
            values = value if isinstance(value, list) else [value]
            # host() writes addresses in lower case, as Python does: fold the rule values.
            matched = func.host(column).in_([fold(v) for v in values])
            return not_(matched) | column.is_(None) if op in ("ne", "not_in") else matched
        return true()


class All(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    all: list["Condition"] = Field(min_length=1, max_length=50)

    def evaluate(self, event: DetectionEvent) -> bool:
        return all(c.evaluate(event) for c in self.all)

    def to_sql(self) -> ColumnElement[bool]:
        return and_(*(c.to_sql() for c in self.all))


class Any_(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    any: list["Condition"] = Field(min_length=1, max_length=50)

    def evaluate(self, event: DetectionEvent) -> bool:
        return any(c.evaluate(event) for c in self.any)

    def to_sql(self) -> ColumnElement[bool]:
        return or_(*(c.to_sql() for c in self.any))


class Not(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    not_: "Condition" = Field(alias="not")

    def evaluate(self, event: DetectionEvent) -> bool:
        return not self.not_.evaluate(event)

    def to_sql(self) -> ColumnElement[bool]:
        # NOT of a superset is not a superset of NOT: only exact sub-conditions may be
        # negated in SQL. Anything containing an inexact operator stays TRUE here.
        # SQL has three-valued logic: `username = 'root'` is NULL (not FALSE) for a missing
        # username, and NOT NULL is NULL, which would drop the row. Python says False there,
        # so its negation is True: COALESCE makes SQL agree.
        if _exact(self.not_):
            return not_(func.coalesce(self.not_.to_sql(), false()))
        return true()


Condition = Annotated[All | Any_ | Not | Predicate, Field(union_mode="left_to_right")]
All.model_rebuild()
Any_.model_rebuild()
Not.model_rebuild()


def _exact(condition: "All | Any_ | Not | Predicate") -> bool:
    """True when to_sql() selects exactly the rows evaluate() accepts."""
    if isinstance(condition, Predicate):
        inexact = condition.op == "matches" or (
            condition.field in NUMERIC_COLUMNS | {"identity_privileged"}
            and condition.op not in ("gt", "gte", "lt", "lte", "exists")
        )
        inexact |= condition.field in IP_COLUMNS and condition.op in (
            "contains",
            "startswith",
            "endswith",
        )
        inexact |= condition.field.startswith("attributes.") and condition.op != "exists"
        return not inexact
    if isinstance(condition, All):
        return all(_exact(c) for c in condition.all)
    if isinstance(condition, Any_):
        return all(_exact(c) for c in condition.any)
    return _exact(condition.not_)


def depth(condition: "All | Any_ | Not | Predicate") -> int:
    if isinstance(condition, Predicate):
        return 1
    if isinstance(condition, All):
        return 1 + max(depth(c) for c in condition.all)
    if isinstance(condition, Any_):
        return 1 + max(depth(c) for c in condition.any)
    return 1 + depth(condition.not_)


@dataclass(frozen=True)
class Always:
    """The empty condition (a rule step without extra filters)."""

    def evaluate(self, event: DetectionEvent) -> bool:
        return True

    def to_sql(self) -> ColumnElement[bool]:
        return true()
