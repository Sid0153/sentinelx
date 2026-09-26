"""The simulated scenarios parse cleanly and have the shape their names promise."""

from collections import Counter
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from app.demo.scenarios import SCENARIOS, benign_activity, brute_force, password_spray
from app.events.schema import NormalizedEvent, SourceType
from app.ingestion.parsers import ParseContext, ParseFailure, parse_record

START = datetime(2026, 9, 25, 9, 0, tzinfo=UTC)
CONTEXT = ParseContext(
    received_at=datetime(2026, 9, 25, 18, 0, tzinfo=UTC), timezone=ZoneInfo("UTC")
)


def events(
    lines: list[str], source_type: SourceType = SourceType.LINUX_AUTH
) -> list[NormalizedEvent]:
    outcomes = [parse_record(source_type, line.encode(), CONTEXT) for line in lines]
    assert not [o for o in outcomes if isinstance(o, ParseFailure)], "scenario lines must parse"
    return [o for o in outcomes if isinstance(o, NormalizedEvent)]


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_every_scenario_is_deterministic_and_parses(name: str) -> None:
    scenario = SCENARIOS[name]
    assert scenario.build(START) == scenario.build(START)
    assert events(scenario.build(START), scenario.source_type)


def test_brute_force_is_one_source_one_account_many_failures() -> None:
    parsed = events(brute_force(START, attempts=12))
    failures = [e for e in parsed if e.event_outcome == "failure"]
    assert len(failures) == 12
    assert {(e.source_ip, e.username, e.host) for e in failures} == {
        ("203.0.113.45", "root", "web-01")
    }
    assert not [e for e in parsed if e.event_outcome == "success"]


def test_brute_force_success_ends_with_an_accepted_logon() -> None:
    parsed = events(SCENARIOS["brute_force_success"].build(START))
    assert parsed[-1].event_outcome == "success"
    assert parsed[-1].source_ip == "203.0.113.45"


def test_password_spray_hits_many_accounts_from_one_source() -> None:
    failures = [e for e in events(password_spray(START)) if e.event_outcome == "failure"]
    assert len({e.username for e in failures}) == len(failures) >= 5
    assert {e.source_ip for e in failures} == {"198.51.100.23"}


def test_benign_activity_is_internal_with_at_most_one_failure_per_user() -> None:
    parsed = events(benign_activity(START, days=2))
    failures = Counter(e.username for e in parsed if e.event_outcome == "failure")
    assert failures and max(failures.values()) <= 2  # one typo per day
    assert {e.source_ip for e in parsed if e.source_ip} <= {
        "10.0.2.41",
        "10.0.2.42",
        "10.0.2.57",
        "10.0.3.12",
    }


def test_outside_addresses_are_documentation_ranges() -> None:
    outside = {e.source_ip for e in events(brute_force(START) + password_spray(START))}
    assert all(ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")) for ip in outside if ip)


def test_generate_applies_the_chosen_options() -> None:
    from app.demo.scenarios import generate

    lines = generate(
        "brute_force",
        START,
        host="DB-01",
        user="svc-backup",
        source_ip="198.51.100.77",
        count=7,
        interval=10,
    )
    failures = [e for e in events(lines) if e.event_outcome == "failure"]
    assert len(failures) == 7
    assert {(e.host, e.username, e.source_ip) for e in failures} == {
        ("db-01", "svc-backup", "198.51.100.77")
    }
    assert failures[-1].timestamp - failures[0].timestamp == timedelta(seconds=60)


def test_spray_count_can_exceed_the_built_in_account_list() -> None:
    from app.demo.scenarios import generate

    failures = [
        e
        for e in events(generate("password_spray", START, count=20))
        if e.event_outcome == "failure"
    ]
    assert len({e.username for e in failures}) == 20


@pytest.mark.parametrize(
    ("name", "options", "message"),
    [
        ("teleport", {}, "unknown scenario"),
        ("benign", {"user": "root"}, "does not use --user"),
        ("password_spray", {"user": "root"}, "does not use --user"),
        ("brute_force", {"host": "not a host"}, "hostname"),
        ("brute_force", {"source_ip": "999.1.1.1"}, "does not appear to be an IPv4 or IPv6"),
        ("brute_force", {"user": "two words"}, "single word"),
        ("brute_force", {"count": 0}, "--count"),
        ("brute_force", {"count": 5001}, "--count"),
        ("brute_force", {"interval": 0}, "--interval"),
    ],
)
def test_generate_refuses_what_a_scenario_cannot_use(
    name: str, options: dict[str, object], message: str
) -> None:
    from app.demo.scenarios import generate

    with pytest.raises(ValueError, match=message):
        generate(name, START, **options)  # type: ignore[arg-type]


def test_generate_needs_a_zone_aware_start() -> None:
    from app.demo.scenarios import generate

    with pytest.raises(ValueError, match="time zone"):
        generate("benign", datetime(2026, 9, 25, 9, 0))
