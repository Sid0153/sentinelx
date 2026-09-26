"""The SQL prefilter against the Python evaluation, on stored events with awkward values.

The engine relies on one property: the rows the SQL prefilter selects include every event the
Python condition accepts (it may select more, never fewer). Where `_exact` says a condition is
exact, which is what `Not` relies on, both must agree row for row. Checked here for every
operator on text, IP, numeric, boolean and attribute fields, negated too, over values chosen
to break naive implementations: mixed case, non-ASCII letters whose case folding differs
between Python and PostgreSQL, LIKE wildcards, empty and missing values, JSON numbers and
booleans, IPv6.
"""

import itertools
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import TypeAdapter
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection import engine
from app.detection.conditions import All, Any_, Condition, Not, Predicate, _exact, fold
from app.detection.events import DetectionEvent
from app.events.schema import EventCategory, EventOutcome, NormalizedEvent, SourceType
from app.events.store import Enrichment
from app.models.event import Event, RawEvent
from tests.helpers import make_source, stored_event, stored_raw

pytestmark = pytest.mark.integration

T0 = datetime(2026, 9, 25, 10, 0, tzinfo=UTC)

USERNAMES = [
    "root", "ROOT", "Straße", "strasse", "ſvc", "svc", "İnci", "ınci", "a_b", "a%b", "ab",
    "back\\slash", "", None,
]  # fmt: skip
PROCESSES = ["PowerShell.exe", "powershell.exe", "cmd.exe", "ÄPP.exe", None]
COMMANDS = ["sudo -i", "SUDO -I", "Straße", "a%b_c", "", None]
IPS = ["203.0.113.45", "10.0.2.42", "2001:db8::1", "::ffff:10.0.2.42", None]
ATTRIBUTES: list[Any] = [
    "sudo",
    "SUDO",
    "",
    "5",
    5,
    5.0,
    1e-07,
    1e20,
    True,
    False,
    None,
    "true",
    "ſudo",
]
PORTS = [22, 443, 50412, None]
PRIVILEGED = [True, False, None]


def _event(index: int) -> tuple[NormalizedEvent, Enrichment]:
    def pick(values: list[Any]) -> Any:
        return values[index % len(values)]

    attribute = pick(ATTRIBUTES)
    normalized = NormalizedEvent(
        timestamp=T0 + timedelta(seconds=index),
        source_type=SourceType.LINUX_AUTH,
        event_category=EventCategory.AUTHENTICATION,
        event_action="logon",
        event_outcome=EventOutcome.FAILURE,
        host="web-01",
        username=USERNAMES[index % len(USERNAMES)] or None,
        source_ip=pick(IPS),
        source_port=pick(PORTS),
        process_name=pick(PROCESSES),
        command_line=pick(COMMANDS),
        attributes={} if index % 7 == 0 else {"group_name": attribute},
    )
    return normalized, Enrichment(identity_privileged=pick(PRIVILEGED))


@pytest.fixture
def stored(db_session: Session) -> list[DetectionEvent]:
    source = make_source(db_session)
    for index in range(len(USERNAMES) * len(ATTRIBUTES)):
        normalized, enrichment = _event(index)
        raw = stored_raw(db_session, source, f"record {index}")
        stored_event(db_session, raw, normalized, enrichment)
    rows = db_session.execute(
        select(Event, RawEvent.batch_id).join(RawEvent, RawEvent.id == Event.raw_event_id)
    ).all()
    return [engine._to_event(event, batch_id) for event, batch_id in rows]


def _predicates() -> list[dict[str, Any]]:
    text_values = ["root", "Root", "strasse", "straße", "svc", "inci", "a_b", "a%b", "\\", ""]
    found: list[dict[str, Any]] = []
    for field, op, value in itertools.product(
        ["username", "process_name", "command_line", "attributes.group_name"],
        ["eq", "ne", "contains", "startswith", "endswith"],
        text_values[:-1],
    ):
        found.append({"field": field, "op": op, "value": value})
    for field in ("username", "process_name", "command_line", "attributes.group_name"):
        found.append({"field": field, "op": "in", "value": ["ROOT", "Straße", "sudo", "5"]})
        found.append({"field": field, "op": "not_in", "value": ["root", "true"]})
        found.append({"field": field, "op": "eq", "value": "5"})
        found.append({"field": field, "op": "eq", "value": "true"})
        found.append({"field": field, "op": "eq", "value": "1e-07"})
        found.append({"field": field, "op": "contains", "value": "e+"})
        found.append({"field": field, "op": "matches", "value": "(?i)^s"})
        for present in (None, True, False):
            found.append({"field": field, "op": "exists", "value": present})
    ip_cases: list[tuple[str, Any]] = [
        ("eq", "2001:DB8::1"),
        ("ne", "203.0.113.45"),
        ("in", ["10.0.2.42", "2001:DB8:0:0::1"]),
        ("not_in", ["10.0.2.42"]),
        ("cidr", "10.0.0.0/8"),
        ("cidr", "2001:db8::/32"),
        ("cidr", "::ffff:0:0/96"),
        ("contains", "113"),
        ("exists", False),
    ]
    for ip_op, ip_value in ip_cases:
        found.append({"field": "source_ip", "op": ip_op, "value": ip_value})
    for port_op, port in [("gt", 443), ("gte", 443), ("lt", 443), ("lte", 22), ("eq", 22)]:
        found.append({"field": "source_port", "op": port_op, "value": port})
    found.append({"field": "source_port", "op": "exists", "value": False})
    found.append({"field": "identity_privileged", "op": "eq", "value": True})
    found.append({"field": "identity_privileged", "op": "exists", "value": True})
    return found


CONDITION: TypeAdapter[All | Any_ | Not | Predicate] = TypeAdapter(Condition)
PREDICATES = _predicates()


def _disagreements(db: Session, events: list[DetectionEvent], raw: dict[str, Any]) -> list[str]:
    condition = CONDITION.validate_python(raw)
    python = {e.id for e in events if condition.evaluate(e)}
    sql = {str(i) for i in db.scalars(select(Event.id).where(condition.to_sql()))}
    if not python <= sql:
        return [f"prefilter dropped {len(python - sql)} matches of {raw}"]
    if _exact(condition) and python != sql:
        return [f"{raw} is marked exact but SQL selects {len(sql - python)} more rows"]
    return []


def test_the_prefilter_contains_every_python_match(
    db_session: Session, stored: list[DetectionEvent]
) -> None:
    """One test (the fixture is costly), every failure listed at once."""
    conditions: list[dict[str, Any]] = []
    for raw in PREDICATES:
        conditions += [raw, {"not": raw}]
    for first, second in itertools.combinations(PREDICATES[::7], 2):
        conditions.append({"all": [first, {"not": second}]})
        conditions.append({"not": {"any": [first, second]}})
    problems = [p for raw in conditions for p in _disagreements(db_session, stored, raw)]
    assert problems == []
    assert len(conditions) > 500


def test_the_fixture_covers_the_awkward_values(stored: list[DetectionEvent]) -> None:
    usernames = {e.username for e in stored}
    assert {"straße", "ſvc", "a%b", None} <= usernames
    kinds = {type(e.attributes.get("group_name")) for e in stored}
    assert {str, int, float, bool, type(None)} <= kinds


@pytest.mark.parametrize(
    ("left", "right", "same"),
    [
        ("ROOT", "root", True),
        ("Straße", "strasse", False),
        ("ſvc", "svc", False),
        (True, "true", True),
    ],
)
def test_fold_only_lowers_ascii(left: Any, right: Any, same: bool) -> None:
    assert (fold(left) == fold(right)) is same
