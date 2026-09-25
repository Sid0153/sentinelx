"""The normalized event's canonical form (docs/event-model.md)."""

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from app.events.schema import (
    ACTIONS,
    MAX_ATTRIBUTES,
    MAX_COMMAND_LINE,
    EventCategory,
    NormalizedEvent,
    SourceType,
)

WHEN = datetime(2026, 9, 25, 10, 31, 2, tzinfo=UTC)


def event(**overrides: Any) -> NormalizedEvent:
    values: dict[str, Any] = {
        "timestamp": WHEN,
        "source_type": SourceType.LINUX_AUTH,
        "event_category": "authentication",
        "event_action": "logon",
        "event_outcome": "failure",
    }
    values.update(overrides)
    return NormalizedEvent(**values)


def test_a_typical_ssh_failure_is_valid() -> None:
    parsed = event(
        host="web-01",
        username="root",
        source_ip="203.0.113.45",
        source_port=50412,
        service="sshd",
        protocol="ssh",
        message="Failed password for root from 203.0.113.45 port 50412 ssh2",
    )
    assert parsed.event_outcome == "failure"
    assert parsed.source_ip == "203.0.113.45"


def test_timestamps_must_carry_a_zone_and_are_stored_in_utc() -> None:
    with pytest.raises(ValidationError, match="time zone"):
        event(timestamp=datetime(2026, 9, 25, 10, 31, 2))
    ist = timezone(timedelta(hours=5, minutes=30))
    converted = event(timestamp=datetime(2026, 9, 25, 16, 1, 2, tzinfo=ist))
    assert converted.timestamp == WHEN
    assert converted.timestamp.tzinfo == UTC


@pytest.mark.parametrize(
    ("given", "stored"),
    [("WEB-01", "web-01"), ("web-01.corp.example.", "web-01.corp.example"), (" db-01 ", "db-01")],
)
def test_hostnames_are_canonical(given: str, stored: str) -> None:
    assert event(host=given).host == stored


@pytest.mark.parametrize("bad", ["-web", "web_01", "a" * 64, "web 01", "web/01", "<script>"])
def test_invalid_hostnames_are_rejected(bad: str) -> None:
    with pytest.raises(ValidationError, match="hostname"):
        event(host=bad)


def test_ips_are_canonical_and_mapped_ipv6_becomes_ipv4() -> None:
    parsed = event(source_ip="::ffff:10.0.0.5", destination_ip="2001:DB8::1")
    assert parsed.source_ip == "10.0.0.5"
    assert parsed.destination_ip == "2001:db8::1"


@pytest.mark.parametrize("bad", ["999.1.1.1", "10.0.0", "not-an-ip", "10.0.0.1/24"])
def test_invalid_ips_are_rejected(bad: str) -> None:
    with pytest.raises(ValidationError):
        event(source_ip=bad)


def test_names_are_lowercased_and_blank_means_absent() -> None:
    parsed = event(username="  Alice ", user_domain="CORP", target_username="   ")
    assert (parsed.username, parsed.user_domain, parsed.target_username) == ("alice", "corp", None)


def test_nul_bytes_become_replacement_characters_instead_of_failing_to_store() -> None:
    parsed = event(command_line="cmd.exe\x00/c whoami", attributes={"note": "a\x00b"})
    assert parsed.command_line == "cmd.exe�/c whoami"
    assert parsed.attributes["note"] == "a�b"
    with pytest.raises(ValidationError, match="control characters"):
        event(username="root\x00")


def test_control_characters_in_names_are_rejected() -> None:
    # A newline in a username is the classic way to forge a second log line.
    with pytest.raises(ValidationError, match="control characters"):
        event(username="bob\nroot")


@pytest.mark.parametrize("category", list(EventCategory))
def test_every_category_accepts_its_own_actions(category: EventCategory) -> None:
    for action in ACTIONS[category]:
        assert event(event_category=category, event_action=action).event_action == action


def test_an_action_from_another_category_is_rejected() -> None:
    with pytest.raises(ValidationError, match="not valid for authentication"):
        event(event_category="authentication", event_action="process_started")


def test_unknown_categories_and_outcomes_are_rejected() -> None:
    with pytest.raises(ValidationError):
        event(event_category="malware")
    with pytest.raises(ValidationError):
        event(event_outcome="maybe")


@pytest.mark.parametrize("port", [-1, 65536])
def test_ports_must_be_in_range(port: int) -> None:
    with pytest.raises(ValidationError):
        event(source_port=port)


def test_sizes_are_bounded() -> None:
    event(command_line="x" * MAX_COMMAND_LINE)
    with pytest.raises(ValidationError):
        event(command_line="x" * (MAX_COMMAND_LINE + 1))
    with pytest.raises(ValidationError, match="at most"):
        event(attributes={f"k{i}": i for i in range(MAX_ATTRIBUTES + 1)})


@pytest.mark.parametrize(
    "attributes",
    [{"Bad-Key": 1}, {"1st": 1}, {"nested": {"a": 1}}, {"items": [1, 2]}, {"long": "x" * 1025}],
)
def test_attributes_are_flat_snake_case_scalars(attributes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        event(attributes=attributes)


def test_windows_attributes_are_kept() -> None:
    parsed = event(
        source_type="windows_security",
        attributes={"event_id": 4625, "logon_type": 3, "sub_status": "0xc000006a"},
    )
    assert parsed.attributes["event_id"] == 4625


def test_unknown_fields_are_rejected_and_events_are_immutable() -> None:
    with pytest.raises(ValidationError, match="extra"):
        event(severity="high")
    parsed = event()
    with pytest.raises(ValidationError):
        parsed.username = "someone-else"
