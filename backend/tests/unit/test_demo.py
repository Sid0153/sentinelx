"""The simulated scenarios parse cleanly and have the shape their names promise."""

import itertools
from collections import Counter
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from app.demo.environment import ASSETS, ATTACKS, DAYS_OF_HISTORY, default_anchor, story
from app.demo.scenarios import (
    SCENARIOS,
    WORKSTATIONS,
    backup_job,
    benign_activity,
    brute_force,
    normal_authentication,
    password_spray,
    web_traffic,
)
from app.events.schema import NormalizedEvent, SourceType
from app.incidents.settings import DEFAULTS
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


# ---------- the newer scenarios and the demo environment (Phase 16) ----------


def test_normal_authentication_is_the_team_at_their_own_workstations() -> None:
    parsed = events(normal_authentication(START, days=2), SourceType.WINDOWS_SECURITY)
    assert {e.event_outcome for e in parsed} == {"success"}
    for event in parsed:
        workstation, address = WORKSTATIONS[event.username or ""]
        if event.host == "fs-01":  # network logons come from the user's own workstation
            assert event.source_ip == address
        else:
            assert event.host == workstation
    assert Counter(e.event_action for e in parsed) == {"logon": 12, "logoff": 6}


def test_backup_job_uses_two_ports_only() -> None:
    parsed = events(backup_job(START, nights=2), SourceType.GENERIC_JSON)
    assert len(parsed) == 48
    assert {e.destination_port for e in parsed} == {22, 5432}
    assert {(e.source_ip, e.destination_ip) for e in parsed} == {("10.0.1.50", "10.0.1.20")}


def test_every_workstation_in_the_scenarios_is_in_the_inventory() -> None:
    inventory = {a.hostname.split(".")[0]: set(a.ip_addresses) for a in ASSETS}
    for workstation, address in WORKSTATIONS.values():
        assert address in inventory[workstation]


ANCHOR = datetime(2026, 9, 25, 18, 0, tzinfo=UTC)


def test_the_attacks_are_apart_on_their_own_hosts_and_addresses() -> None:
    """So each incident in the demo comes from one scenario: further apart than the
    correlation window, and no host or outside address shared between two attacks."""
    attacks = story(ANCHOR)[-len(ATTACKS) :]
    assert len(attacks) == len(ATTACKS) == 9
    window = timedelta(minutes=DEFAULTS["correlation_window_minutes"])
    spans = []
    hosts: list[str] = []
    sources: list[str] = []
    for step in attacks:
        source_type = SCENARIOS[step.scenario].source_type
        parsed = events(step.lines(), source_type)
        spans.append((min(e.timestamp for e in parsed), max(e.timestamp for e in parsed)))
        hosts += {e.host for e in parsed if e.host}
        sources += {
            e.source_ip for e in parsed if e.source_ip and not e.source_ip.startswith("10.")
        }
    assert len(hosts) == len(set(hosts)) and len(sources) == len(set(sources))
    for (_, end), (start, _) in itertools.pairwise(spans):
        assert start - end > window


def test_the_story_ends_before_the_anchor_and_covers_the_working_days() -> None:
    steps = story(ANCHOR)
    times = [
        e.timestamp
        for step in steps
        for e in events(step.lines(), SCENARIOS[step.scenario].source_type)
    ]
    assert max(times) < ANCHOR
    assert min(times).date() == (ANCHOR - timedelta(days=DAYS_OF_HISTORY)).date()
    assert all(step.expected_rules == () for step in steps[: -len(ATTACKS)])  # ordinary


def test_the_story_needs_a_zone_aware_anchor() -> None:
    with pytest.raises(ValueError, match="time zone"):
        story(datetime(2026, 9, 25, 18, 0))  # noqa: DTZ001


def test_the_default_anchor_is_the_start_of_the_hour() -> None:
    moment = datetime(2026, 9, 25, 17, 42, 13, 5, tzinfo=ZoneInfo("Europe/Paris"))
    assert default_anchor(moment) == datetime(2026, 9, 25, 15, 0, tzinfo=UTC)


def test_web_traffic_is_sessions_of_ordinary_requests() -> None:
    lines = web_traffic(START, days=2)
    assert lines == web_traffic(START, days=2) and lines != web_traffic(START + timedelta(days=1))
    parsed = events(lines, SourceType.HTTP_ACCESS)
    statuses = Counter(e.attributes["http_status"] for e in parsed)
    assert statuses[404] == 4  # two scanner requests a night, nothing else fails
    assert set(statuses) == {200, 302, 404}
    times = [e.timestamp for e in parsed]
    assert times == sorted(times) and len(parsed) > 400
    attackers = {"198.51.100.23", "198.51.100.77", "192.0.2.150", "203.0.113.45"}
    assert not attackers & {e.source_ip for e in parsed}
