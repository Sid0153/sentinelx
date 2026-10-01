"""What a hunt query accepts and refuses, before any SQL exists (docs/threat-hunting.md)."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from app.hunting.query import MAX_FILTERS, HuntFilter, HuntQuery, TimeRange
from app.hunting.service import DEFINITION

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
RANGE = {"from": "2026-09-30T00:00:00Z", "to": "2026-10-01T00:00:00Z"}


def query(**overrides: Any) -> HuntQuery:
    return HuntQuery.model_validate({"time_range": RANGE, **overrides})


def refused(**overrides: Any) -> str:
    with pytest.raises(ValidationError) as caught:
        query(**overrides)
    return str(caught.value)


def test_a_simple_query_is_accepted() -> None:
    hunt = query(
        filters=[
            {"field": "source_ip", "op": "eq", "value": "203.0.113.45"},
            {"field": "event_outcome", "op": "eq", "value": "success"},
            {"field": "destination_port", "op": "in", "value": [22, 3389]},
            {"field": "identity_privileged", "op": "eq", "value": True},
            {"field": "attributes.group_name", "op": "contains", "value": "admin"},
        ],
        alert={"rule_ids": ["AUTH-002"], "statuses": ["NEW"]},
    )
    assert len(hunt.filters) == 5
    assert hunt.sort == "newest" and hunt.limit == 50


@pytest.mark.parametrize(
    ("time_range", "message"),
    [
        (None, "Field required"),
        ({}, "needs last, or both from and to"),
        ({"from": "2026-09-30T00:00:00Z"}, "needs last, or both from and to"),
        ({"from": "2026-10-01T00:00:00Z", "to": "2026-09-30T00:00:00Z"}, "from must be before"),
        ({"from": "2026-08-01T00:00:00Z", "to": "2026-09-30T00:00:00Z"}, "at most 31 days"),
        ({"from": "2026-09-30T00:00:00", "to": "2026-10-01T00:00:00"}, "time zone"),
        ({"last": "32d"}, "at most 31 days"),
        ({"last": "0h"}, "at most 31 days"),
        ({"last": "1 day"}, "look like 15m"),
        ({"last": "24h", "from": "2026-09-30T00:00:00Z"}, "either last or from/to"),
    ],
)
def test_the_time_range_is_required_and_bounded(time_range: Any, message: str) -> None:
    body: dict[str, Any] = {} if time_range is None else {"time_range": time_range}
    with pytest.raises(ValidationError, match=message):
        HuntQuery.model_validate(body)


def test_a_relative_range_ends_now() -> None:
    start, end = TimeRange.model_validate({"last": "24h"}).resolve(NOW)
    assert (start, end) == (NOW - timedelta(hours=24), NOW)
    start, end = TimeRange.model_validate({"last": "31d"}).resolve(NOW)
    assert end - start == timedelta(days=31)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ({"field": "password_hash", "op": "eq", "value": "x"}, "unknown field"),
        ({"field": "attributes.Bad-Key", "op": "eq", "value": "x"}, "unknown field"),
        ({"field": "username", "op": "matches", "value": "^r"}, "Input should be"),  # no regex
        ({"field": "username", "op": "gt", "value": 5}, "gt cannot be used on username"),
        ({"field": "source_ip", "op": "contains", "value": "113"}, "contains cannot be used"),
        ({"field": "source_ip", "op": "eq", "value": "not-an-ip"}, "is not an IP address"),
        ({"field": "source_ip", "op": "cidr", "value": "10.0.0.0/33"}, "does not appear"),
        ({"field": "destination_port", "op": "eq", "value": 70000}, "0 to 65535"),
        ({"field": "destination_port", "op": "eq", "value": "22"}, "0 to 65535"),
        ({"field": "identity_privileged", "op": "eq", "value": "yes"}, "true or false"),
        ({"field": "username", "op": "eq", "value": "x" * 513}, "at most 512"),
        ({"field": "username", "op": "in", "value": ["a"] * 101}, "at most 100 values"),
        ({"field": "username", "op": "in", "value": []}, "1 to 200 values"),
        ({"field": "username", "op": "eq", "value": None}, "text of at most"),
        ({"field": "username", "op": "eq", "value": "x", "extra": 1}, "Extra inputs"),
    ],
)
def test_fields_operators_and_values_are_allowlisted(raw: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        HuntFilter.model_validate(raw)


def test_limits_bound_the_cost() -> None:
    many = [{"field": "username", "op": "ne", "value": f"u{i}"} for i in range(MAX_FILTERS + 1)]
    assert "at most 20 items" in refused(filters=many)
    assert "less than or equal to 200" in refused(limit=201)
    assert "Input should be 'newest' or 'oldest'" in refused(sort="timestamp; DROP TABLE events")


def test_alert_filters_cannot_contradict_each_other() -> None:
    assert "cannot be combined" in refused(alert={"in_alert": False, "rule_ids": ["AUTH-001"]})
    assert "String should match pattern" in refused(alert={"rule_ids": ["AUTH-001' OR 1=1"]})
    assert query(alert={"in_alert": False}).alert.in_alert is False


def test_saved_definitions_are_one_of_two_shapes() -> None:
    hunt = DEFINITION.validate_python({"kind": "query", "query": {"time_range": {"last": "7d"}}})
    assert hunt.kind == "query"
    template = DEFINITION.validate_python(
        {"kind": "template", "template_id": "rare_process_on_host", "time_range": {"last": "7d"}}
    )
    assert template.kind == "template"
    with pytest.raises(ValidationError):
        DEFINITION.validate_python({"kind": "sql", "sql": "SELECT * FROM users"})
