"""A hunt's SQL is the answer (there is no Python pass after it), so it must select exactly
the events the condition language accepts: checked row for row for every operator a hunt
allows, on the stored events with awkward values from test_condition_sql (mixed case,
non-ASCII letters, LIKE wildcards, empty and missing values, IPv6). Injection-shaped values
must match literally."""

from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.detection.events import DetectionEvent
from app.hunting.query import HuntFilter
from app.models.event import Event
from tests.integration.test_condition_sql import PREDICATES, stored  # noqa: F401 (fixture)

pytestmark = pytest.mark.integration


def _hunt_filters() -> list[dict[str, Any]]:
    """Every predicate of the condition test a hunt accepts, plus the cases the condition
    language leaves to Python (equality on ports and on identity_privileged)."""
    accepted = []
    for raw in PREDICATES:
        if raw["field"].startswith("attributes."):
            continue  # attribute values compare as JSON text in hunts: tested below
        try:
            HuntFilter.model_validate(raw)
        except ValueError:
            continue
        accepted.append(raw)
    accepted += [
        {"field": "source_port", "op": "eq", "value": 22},
        {"field": "source_port", "op": "ne", "value": 22},
        {"field": "source_port", "op": "in", "value": [22, 443]},
        {"field": "source_port", "op": "not_in", "value": [22]},
        {"field": "identity_privileged", "op": "eq", "value": True},
        {"field": "identity_privileged", "op": "ne", "value": True},
        {"field": "identity_privileged", "op": "eq", "value": False},
    ]
    return accepted


def test_hunt_sql_selects_exactly_what_the_condition_accepts(
    db_session: Session,
    stored: list[DetectionEvent],  # noqa: F811
) -> None:
    filters = _hunt_filters()
    assert len(filters) > 60  # the comparison covers every operator, not a handful
    problems = []
    for raw in filters:
        hunt_filter = HuntFilter.model_validate(raw)
        python = {e.id for e in stored if hunt_filter.predicate().evaluate(e)}
        sql = {str(i) for i in db_session.scalars(select(Event.id).where(hunt_filter.to_sql()))}
        if python != sql:
            problems.append(f"{raw}: SQL {len(sql - python)} extra, {len(python - sql)} missing")
    assert problems == []


def test_unsupported_operators_are_refused_not_approximated() -> None:
    """The condition language's SQL is only a superset for these: a hunt must refuse them."""
    for raw in (
        {"field": "username", "op": "matches", "value": "^r"},
        {"field": "source_ip", "op": "contains", "value": "113"},
        {"field": "source_ip", "op": "startswith", "value": "203"},
    ):
        with pytest.raises(ValueError):
            HuntFilter.model_validate(raw)


@pytest.mark.parametrize(
    ("op", "value", "expected"),
    [
        ("eq", "sudo", {"sudo", "SUDO"}),
        ("eq", "5", {"5"}),  # the string and the JSON number 5 both read "5"
        ("eq", "true", {"true"}),  # the string "true" and the JSON boolean
        ("contains", "SU", {"sudo", "SUDO"}),  # ASCII case only: the long s of "ſudo" is not "s"
        ("exists", False, {"", None}),
    ],
)
def test_attribute_values_compare_as_their_json_text(
    db_session: Session,
    stored: list[DetectionEvent],  # noqa: F811
    op: str,
    value: Any,
    expected: set[Any],
) -> None:
    hunt_filter = HuntFilter.model_validate(
        {"field": "attributes.group_name", "op": op, "value": value}
    )
    rows = db_session.execute(
        select(Event.attributes["group_name"].astext).where(hunt_filter.to_sql())
    ).scalars()
    # The JSON number 5 reads "5" (5.0 reads "5.0"), the boolean true reads "true".
    assert set(rows) == expected


@pytest.mark.parametrize(
    "value", ["' OR 1=1 --", "%", "_", "a%b", "\\", "'; DROP TABLE events; --"]
)
def test_injection_shaped_values_match_literally(
    db_session: Session,
    stored: list[DetectionEvent],  # noqa: F811
    value: str,
) -> None:
    for op in ("eq", "contains"):
        hunt_filter = HuntFilter.model_validate({"field": "username", "op": op, "value": value})
        python = {e.id for e in stored if hunt_filter.predicate().evaluate(e)}
        sql = {str(i) for i in db_session.scalars(select(Event.id).where(hunt_filter.to_sql()))}
        assert sql == python
    # "%" and "_" are wildcards in LIKE: literally, only "a%b" contains "%".
    if value == "%":
        rows = db_session.scalars(
            select(Event.username).where(
                HuntFilter.model_validate(
                    {"field": "username", "op": "contains", "value": value}
                ).to_sql()
            )
        )
        assert set(rows) == {"a%b"}


@pytest.mark.parametrize("field", ["command_line", "message"])
def test_substring_search_can_use_the_trigram_index(db_session: Session, field: str) -> None:
    """The index is on the folded expression the compiler writes; if they drift apart,
    PostgreSQL silently scans the whole table (this happened before migration 0008)."""
    hunt_filter = HuntFilter.model_validate({"field": field, "op": "contains", "value": "certutil"})
    statement = select(Event.id).where(hunt_filter.to_sql())
    db_session.execute(text("SET LOCAL enable_seqscan = off"))
    plan = "\n".join(
        db_session.scalars(
            text(f"EXPLAIN {statement.compile(compile_kwargs={'literal_binds': True})}")
        )
    )
    assert f"ix_events_{field}_folded_trgm" in plan, plan
