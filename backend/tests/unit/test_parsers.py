"""Parsers: every supported line shape, and every way input can be wrong or hostile.

All sample data is synthetic: documentation IP ranges (RFC 5737), fictional hosts and users.
"""

import json
import time
from datetime import UTC, datetime
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from app.events.schema import NormalizedEvent, SourceType
from app.ingestion.parsers import ParseContext, ParseFailure, Skipped, parse_record

RECEIVED = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)
UTC_CONTEXT = ParseContext(received_at=RECEIVED, timezone=ZoneInfo("UTC"), default_host="web-01")


def parse(source: SourceType, line: str | bytes, context: ParseContext = UTC_CONTEXT) -> Any:
    raw = line.encode() if isinstance(line, str) else line
    return parse_record(source, raw, context)


def event(
    source: SourceType, line: str | bytes, context: ParseContext = UTC_CONTEXT
) -> NormalizedEvent:
    result = parse(source, line, context)
    assert isinstance(result, NormalizedEvent), result
    return result


def failure(source: SourceType, line: str | bytes) -> str:
    result = parse(source, line)
    assert isinstance(result, ParseFailure), result
    return result.code


def skipped(source: SourceType, line: str | bytes) -> str:
    result = parse(source, line)
    assert isinstance(result, Skipped), result
    return result.code


LINUX = SourceType.LINUX_AUTH

# ---------- Linux auth.log ----------


def test_ssh_password_failure() -> None:
    e = event(
        LINUX,
        "Sep 25 10:31:02 web-01 sshd[4122]: Failed password for root from 203.0.113.45 "
        "port 50412 ssh2",
    )
    assert (e.event_category, e.event_action, e.event_outcome) == (
        "authentication",
        "logon",
        "failure",
    )
    assert (e.host, e.username, e.source_ip, e.source_port) == (
        "web-01",
        "root",
        "203.0.113.45",
        50412,
    )
    assert (e.service, e.protocol, e.session_id) == ("sshd", "ssh", "4122")
    assert e.attributes == {"auth_method": "password", "invalid_user": False}
    assert e.timestamp == datetime(2026, 9, 25, 10, 31, 2, tzinfo=UTC)


def test_ssh_failure_for_an_invalid_user_keeps_the_attempted_name() -> None:
    e = event(
        LINUX,
        "Sep 25 10:31:05 web-01 sshd[4130]: Failed password for invalid user oracle "
        "from 203.0.113.45 port 50433 ssh2",
    )
    assert e.username == "oracle"
    assert e.attributes["invalid_user"] is True


@pytest.mark.parametrize("method", ["publickey", "password", "keyboard-interactive/pam"])
def test_ssh_success(method: str) -> None:
    e = event(
        LINUX,
        f"Sep 25 10:31:15 web-01 sshd[4190]: Accepted {method} for deploy from 198.51.100.7 "
        "port 40022 ssh2: ED25519 SHA256:abc",
    )
    assert (e.event_outcome, e.username, e.attributes["auth_method"]) == (
        "success",
        "deploy",
        method,
    )


def test_ssh_session_closed_is_a_logoff() -> None:
    e = event(
        LINUX,
        "Sep 25 11:02:00 web-01 sshd[4190]: pam_unix(sshd:session): session closed for user deploy",
    )
    assert (e.event_action, e.username) == ("logoff", "deploy")


@pytest.mark.parametrize(
    "message",
    [
        "Invalid user oracle from 203.0.113.45 port 50433",
        "Connection closed by authenticating user root 203.0.113.45 port 50412 [preauth]",
        "Disconnected from invalid user oracle 203.0.113.45 port 50433 [preauth]",
        "pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)",
        "Received disconnect from 203.0.113.45 port 50412:11: Bye Bye [preauth]",
    ],
)
def test_ssh_informational_lines_are_skipped_not_failed(message: str) -> None:
    # The Failed/Accepted line carries the attempt; counting these too would double-count.
    assert skipped(LINUX, f"Sep 25 10:31:03 web-01 sshd[4122]: {message}") == "sshd_informational"


def test_rfc3339_timestamps_and_zones() -> None:
    e = event(
        LINUX,
        "2026-09-25T16:01:02.123456+05:30 web-01 sshd[4122]: Failed password for root "
        "from 203.0.113.45 port 50412 ssh2",
    )
    assert e.timestamp == datetime(2026, 9, 25, 10, 31, 2, 123456, tzinfo=UTC)


def test_rfc3164_uses_the_source_time_zone() -> None:
    kolkata = ParseContext(received_at=RECEIVED, timezone=ZoneInfo("Asia/Kolkata"))
    e = event(
        LINUX,
        "Sep 25 16:01:02 web-01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2",
        kolkata,
    )
    assert e.timestamp == datetime(2026, 9, 25, 10, 31, 2, tzinfo=UTC)


def test_december_line_received_in_january_belongs_to_last_year() -> None:
    january = ParseContext(
        received_at=datetime(2027, 1, 1, 0, 5, tzinfo=UTC), timezone=ZoneInfo("UTC")
    )
    e = event(
        LINUX,
        "Dec 31 23:59:58 web-01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2",
        january,
    )
    assert e.timestamp.year == 2026


def test_single_digit_days_are_space_padded() -> None:
    e = event(
        LINUX,
        "Sep  5 10:31:02 web-01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2",
    )
    assert e.timestamp.day == 5


def test_sudo_command() -> None:
    e = event(
        LINUX,
        "Sep 25 10:31:28 web-01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; "
        "COMMAND=/bin/bash",
    )
    assert (e.event_category, e.event_action, e.event_outcome) == ("privilege", "sudo", "success")
    assert (e.username, e.target_username, e.command_line) == ("deploy", "root", "/bin/bash")
    assert e.attributes == {"tty": "pts/0", "working_directory": "/home/deploy"}


@pytest.mark.parametrize(
    ("reason", "code", "extra"),
    [
        ("user NOT in sudoers", "not_in_sudoers", {}),
        ("3 incorrect password attempts", "incorrect_password", {"attempts": 3}),
    ],
)
def test_sudo_failures(reason: str, code: str, extra: dict[str, int]) -> None:
    e = event(
        LINUX,
        f"Sep 25 10:40:00 web-01 sudo:      bob : {reason} ; TTY=pts/1 ; PWD=/home/bob ; "
        "USER=root ; COMMAND=/usr/bin/id",
    )
    assert e.event_outcome == "failure"
    assert e.attributes["failure_reason"] == code
    assert e.attributes.items() >= extra.items()


def test_su() -> None:
    ok = event(LINUX, "Sep 25 10:41:00 web-01 su[5001]: (to root) alice on pts/0")
    failed = event(LINUX, "Sep 25 10:41:30 web-01 su[5002]: FAILED SU (to root) alice on pts/0")
    assert (ok.event_action, ok.event_outcome, ok.username, ok.target_username) == (
        "su",
        "success",
        "alice",
        "root",
    )
    assert failed.event_outcome == "failure"


def test_privileged_account_creation_sequence() -> None:
    created = event(
        LINUX,
        "Sep 25 10:31:34 web-01 useradd[5120]: new user: name=svc-backup2, UID=1002, GID=1002, "
        "home=/home/svc-backup2, shell=/bin/bash, from=/dev/pts/0",
    )
    added = event(LINUX, "Sep 25 10:31:36 web-01 usermod[5125]: add 'svc-backup2' to group 'sudo'")
    gpasswd = event(
        LINUX, "Sep 25 10:31:40 web-01 gpasswd[5130]: user svc-backup2 added by root to group wheel"
    )
    assert (created.event_action, created.target_username) == ("user_created", "svc-backup2")
    assert created.attributes == {"uid": 1002, "shell": "/bin/bash"}
    assert (added.event_action, added.attributes["group_name"]) == ("group_member_added", "sudo")
    assert (gpasswd.username, gpasswd.target_username) == ("root", "svc-backup2")


def test_other_account_messages() -> None:
    deleted = event(LINUX, "Sep 25 12:00:00 web-01 userdel[6000]: delete user 'svc-backup2'")
    changed = event(
        LINUX,
        "Sep 25 12:01:00 web-01 passwd[6001]: "
        "pam_unix(passwd:chauthtok): password changed for alice",
    )
    assert (deleted.event_action, changed.event_action) == ("user_deleted", "password_changed")
    assert (
        skipped(
            LINUX, "Sep 25 10:31:34 web-01 useradd[5120]: new group: name=svc-backup2, GID=1002"
        )
        == "account_informational"
    )


def test_unrelated_programs_are_skipped() -> None:
    assert (
        skipped(
            LINUX,
            "Sep 25 10:00:01 web-01 CRON[900]: "
            "pam_unix(cron:session): session opened for user root",
        )
        == "not_security_relevant"
    )


@pytest.mark.parametrize(
    ("line", "code"),
    [
        ("this is not syslog", "unrecognized_format"),
        ("", "unrecognized_format"),
        (
            "Foo 25 10:31:02 web-01 sshd[1]: Failed password for root from 1.2.3.4 port 1",
            "invalid_timestamp",
        ),
        (
            "Feb 30 10:31:02 web-01 sshd[1]: Failed password for root from 1.2.3.4 port 1",
            "invalid_timestamp",
        ),
        (b"Sep 25 10:31:02 web-01 sshd[1]: caf\xe9", "not_utf8"),
    ],
)
def test_linux_failures(line: str | bytes, code: str) -> None:
    assert failure(LINUX, line) == code


def test_a_hostname_the_model_refuses_fails_the_record_instead_of_crashing() -> None:
    assert (
        failure(
            LINUX, "Sep 25 10:31:02 <script> sshd[1]: Failed password for root from 1.2.3.4 port 1"
        )
        == "invalid_field"
    )


def test_newline_injection_in_a_username_cannot_forge_a_second_event() -> None:
    # One record is one event: a line break inside a record does not start a new one.
    result = parse(
        LINUX,
        "Sep 25 10:31:02 web-01 sshd[1]: Failed password for root\nSep 25 ... from 1.2.3.4 port 1",
    )
    assert isinstance(result, (ParseFailure, Skipped))


# ---------- Windows ----------

WINDOWS = SourceType.WINDOWS_SECURITY


def win(event_id: int, data: dict[str, Any], **extra: Any) -> str:
    record = {
        "EventID": event_id,
        "TimeCreated": "2026-09-25T10:31:02.1234567Z",
        "Computer": "WS-042.corp.example",
        "EventRecordID": 99812,
        "EventData": data,
        **extra,
    }
    return json.dumps(record)


def test_windows_failed_logon() -> None:
    e = event(
        WINDOWS,
        win(
            4625,
            {
                "TargetUserName": "alice",
                "TargetDomainName": "CORP",
                "LogonType": "3",
                "IpAddress": "203.0.113.45",
                "IpPort": "50412",
                "Status": "0xc000006d",
                "SubStatus": "0xc000006a",
                "AuthenticationPackageName": "NTLM",
            },
        ),
    )
    assert (e.event_action, e.event_outcome, e.username, e.user_domain) == (
        "logon",
        "failure",
        "alice",
        "corp",
    )
    assert (e.host, e.source_ip, e.source_port, e.protocol) == (
        "ws-042.corp.example",
        "203.0.113.45",
        50412,
        "network",
    )
    assert e.attributes["event_id"] == 4625
    assert e.attributes["record_id"] == 99812
    assert e.attributes["sub_status"] == "0xc000006a"
    assert e.timestamp == datetime(2026, 9, 25, 10, 31, 2, 123456, tzinfo=UTC)


def test_windows_rdp_logon_and_placeholders() -> None:
    e = event(
        WINDOWS,
        win(4624, {"TargetUserName": "alice", "LogonType": 10, "IpAddress": "-", "IpPort": "-"}),
    )
    assert (e.event_outcome, e.protocol, e.source_ip, e.source_port) == (
        "success",
        "rdp",
        None,
        None,
    )
    assert e.attributes["logon_type_name"] == "remote_interactive"


def test_powershell_5_date_format() -> None:
    e = event(WINDOWS, win(4624, {"TargetUserName": "alice"}, TimeCreated="/Date(1790332262000)/"))
    assert e.timestamp == datetime.fromtimestamp(1790332262, UTC)


def test_windows_machine_accounts_are_marked() -> None:
    e = event(WINDOWS, win(4624, {"TargetUserName": "WS-042$", "LogonType": 3}))
    assert e.username == "ws-042$"
    assert e.attributes["account_kind"] == "machine"


def test_windows_process_creation() -> None:
    e = event(
        WINDOWS,
        win(
            4688,
            {
                "SubjectUserName": "alice",
                "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ParentProcessName": "C:\\Windows\\explorer.exe",
                "CommandLine": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
                "NewProcessId": "0x1a2b",
            },
        ),
    )
    assert (e.event_category, e.process_name, e.parent_process_name) == (
        "process",
        "powershell.exe",
        "explorer.exe",
    )
    assert e.command_line is not None and "-EncodedCommand" in e.command_line
    assert e.attributes["process_path"].endswith("powershell.exe")


def test_windows_account_creation_and_group_add_share_the_sid() -> None:
    created = event(
        WINDOWS,
        win(
            4720,
            {
                "SubjectUserName": "alice",
                "TargetUserName": "helpdesk2",
                "TargetSid": "S-1-5-21-1-2-3-1105",
            },
        ),
    )
    added = event(
        WINDOWS,
        win(
            4732,
            {
                "SubjectUserName": "alice",
                "MemberName": "-",
                "MemberSid": "S-1-5-21-1-2-3-1105",
                "TargetUserName": "Administrators",
            },
        ),
    )
    assert (created.username, created.target_username) == ("alice", "helpdesk2")
    assert added.target_username is None  # local accounts: only the SID is logged
    assert created.attributes["target_sid"] == added.attributes["target_sid"]
    assert added.attributes["group_name"] == "Administrators"


def test_windows_special_privileges() -> None:
    e = event(WINDOWS, win(4672, {"SubjectUserName": "alice", "PrivilegeList": "SeDebugPrivilege"}))
    assert (e.event_category, e.event_action) == ("privilege", "special_privileges_assigned")


def test_netbios_hostnames_with_underscores() -> None:
    assert (
        event(WINDOWS, win(4624, {"TargetUserName": "alice"}, Computer="WS_042")).host == "ws_042"
    )


def test_unsupported_event_ids_are_skipped() -> None:
    assert skipped(WINDOWS, win(4798, {})) == "unsupported_event_id"


@pytest.mark.parametrize(
    ("line", "code"),
    [
        ("not json", "invalid_json"),
        ("[1, 2]", "not_a_json_object"),
        (json.dumps({"TimeCreated": "2026-09-25T10:00:00Z"}), "missing_event_id"),
        (
            json.dumps({"EventID": 4624, "TimeCreated": "yesterday", "EventData": {}}),
            "invalid_timestamp",
        ),
        (
            json.dumps({"EventID": 4624, "TimeCreated": "2026-09-25T10:00:00", "EventData": {}}),
            "invalid_timestamp",
        ),
        (
            json.dumps({"EventID": 4624, "TimeCreated": "2026-09-25T10:00:00Z", "EventData": "x"}),
            "invalid_event_data",
        ),
        ("[" * 100_000 + "]" * 100_000, "invalid_json"),
    ],
    ids=["text", "array", "no-id", "bad-time", "naive-time", "bad-data", "deep-nesting"],
)
def test_windows_failures(line: str, code: str) -> None:
    assert failure(WINDOWS, line) == code


# ---------- HTTP access log ----------

HTTP = SourceType.HTTP_ACCESS


def test_combined_log_line() -> None:
    e = event(
        HTTP,
        '203.0.113.9 - admin [25/Sep/2026:10:31:02 +0000] "GET /wp-login.php?redirect=1 HTTP/1.1" '
        '401 512 "-" "Mozilla/5.0 (compatible; scanner)"',
    )
    assert (e.event_category, e.event_action, e.event_outcome) == ("web", "http_request", "failure")
    assert (e.host, e.source_ip, e.username) == ("web-01", "203.0.113.9", "admin")
    assert e.attributes["url_path"] == "/wp-login.php"
    assert e.attributes["url_query"] == "redirect=1"
    assert e.attributes["http_status"] == 401
    assert e.attributes["user_agent"] == "Mozilla/5.0 (compatible; scanner)"


def test_success_and_missing_size() -> None:
    e = event(HTTP, '10.0.2.42 - - [25/Sep/2026:10:31:02 +0200] "HEAD / HTTP/1.1" 200 - "-" "-"')
    assert e.event_outcome == "success"
    assert "response_bytes" not in e.attributes
    assert e.timestamp == datetime(2026, 9, 25, 8, 31, 2, tzinfo=UTC)


def test_garbage_request_lines_are_kept_as_events() -> None:
    e = event(
        HTTP,
        '203.0.113.77 - - [25/Sep/2026:10:31:02 +0000] "\\x16\\x03\\x01\\x02\\x00" 400 157 "-" "-"',
    )
    assert e.attributes["request_line"].startswith("\\x16")
    assert "http_method" not in e.attributes


def test_access_line_without_referrer_and_agent() -> None:
    e = event(HTTP, '203.0.113.9 - - [25/Sep/2026:10:31:02 +0000] "GET / HTTP/1.0" 200 10')
    assert e.attributes["http_version"] == "HTTP/1.0"


@pytest.mark.parametrize(
    ("line", "code"),
    [
        ("GET / HTTP/1.1", "unrecognized_format"),
        ('203.0.113.9 - - [not a date] "GET / HTTP/1.1" 200 1 "-" "-"', "invalid_timestamp"),
    ],
)
def test_http_failures(line: str, code: str) -> None:
    assert failure(HTTP, line) == code


# ---------- application JSON ----------

APP = SourceType.APP_JSON


def test_app_login_failure() -> None:
    e = event(
        APP,
        json.dumps(
            {
                "ts": "2026-09-25T10:31:02Z",
                "event": "login_failure",
                "user": "Alice@corp.example",
                "ip": "203.0.113.9",
                "app": "billing",
                "detail": "bad password",
            }
        ),
    )
    assert (e.event_action, e.event_outcome, e.username, e.user_domain) == (
        "logon",
        "failure",
        "alice",
        "corp.example",
    )
    assert (e.service, e.host) == (
        "billing",
        "web-01",
    )  # no host in the record: the source's default
    assert e.attributes == {"app_event": "login_failure", "detail": "bad password"}


def test_app_user_created_has_actor_and_target() -> None:
    e = event(
        APP,
        json.dumps(
            {
                "ts": "2026-09-25T10:31:02Z",
                "event": "user_created",
                "user": "admin",
                "target_user": "newbie",
            }
        ),
    )
    assert (e.event_category, e.username, e.target_username) == ("iam", "admin", "newbie")


@pytest.mark.parametrize(
    ("record", "code"),
    [
        ({"ts": "2026-09-25T10:31:02Z"}, "missing_event_type"),
        ({"ts": "2026-09-25T10:31:02Z", "event": "teleported"}, "unknown_event_type"),
        ({"event": "logout"}, "invalid_timestamp"),
        ({"ts": 12345, "event": "logout"}, "invalid_timestamp"),
    ],
)
def test_app_failures(record: dict[str, Any], code: str) -> None:
    assert failure(APP, json.dumps(record)) == code


# ---------- generic JSON ----------

GENERIC = SourceType.GENERIC_JSON


def test_generic_network_event() -> None:
    e = event(
        GENERIC,
        json.dumps(
            {
                "timestamp": "2026-09-25T10:31:02Z",
                "event_category": "network",
                "event_action": "connection",
                "event_outcome": "success",
                "host": "ws-042",
                "source_ip": "10.0.2.42",
                "destination_ip": "10.0.1.20",
                "destination_port": 445,
                "protocol": "tcp",
                "event_id": "sender-123",
            }
        ),
    )
    assert (e.source_type, e.destination_port) == ("generic_json", 445)


def test_generic_json_cannot_choose_its_source_type() -> None:
    e = event(
        GENERIC,
        json.dumps(
            {
                "timestamp": "2026-09-25T10:31:02Z",
                "event_category": "application",
                "event_action": "app_event",
                "source_type": "windows_security",
            }
        ),
    )
    assert e.source_type == "generic_json"
    assert e.host == "web-01"


@pytest.mark.parametrize(
    "record",
    [
        {"timestamp": "2026-09-25T10:31:02Z", "event_category": "network", "event_action": "logon"},
        {
            "timestamp": "2026-09-25T10:31:02",
            "event_category": "network",
            "event_action": "connection",
        },
        {
            "timestamp": "2026-09-25T10:31:02Z",
            "event_category": "network",
            "event_action": "connection",
            "severity": "high",
        },
        {
            "timestamp": "2026-09-25T10:31:02Z",
            "event_category": "network",
            "event_action": "connection",
            "destination_port": 99999,
        },
    ],
    ids=["wrong-action", "naive-time", "unknown-field", "bad-port"],
)
def test_generic_json_failures(record: dict[str, Any]) -> None:
    assert failure(GENERIC, json.dumps(record)) == "invalid_event"


# ---------- hostile input ----------


@pytest.mark.parametrize("source", list(SourceType))
def test_random_bytes_never_crash_any_parser(source: SourceType) -> None:
    import random

    rng = random.Random(1234)  # noqa: S311  (seeded fuzz input for tests, not cryptography)
    for _ in range(300):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200)))
        result = parse(source, blob)
        assert isinstance(result, (NormalizedEvent, Skipped, ParseFailure))


@pytest.mark.parametrize(
    ("source", "line"),
    [
        (LINUX, "Sep 25 10:31:02 web-01 sshd[1]: Failed password for " + "a" * 60_000),
        (LINUX, "Sep 25 10:31:02 web-01 sudo: " + "x : " * 15_000),
        (HTTP, '203.0.113.9 - - [25/Sep/2026:10:31:02 +0000] "' + "\\" * 60_000),
        (HTTP, "203.0.113.9 " * 5_000),
    ],
    ids=["ssh-long-user", "sudo-separators", "http-backslashes", "http-repeated"],
)
def test_adversarial_lines_are_handled_in_linear_time(source: SourceType, line: str) -> None:
    started = time.perf_counter()
    parse(source, line)
    assert time.perf_counter() - started < 0.5  # catastrophic backtracking would take minutes


def test_markup_in_fields_is_kept_as_inert_text() -> None:
    e = event(
        LINUX,
        # sshd user names cannot contain spaces, so the payload is written without them.
        "Sep 25 10:31:02 web-01 sshd[1]: "
        "Failed password for <img/src=x/onerror=alert(1)> from 203.0.113.45 port 1 ssh2",
    )
    assert e.username == "<img/src=x/onerror=alert(1)>"  # stored as text; the UI renders text only


def test_a_parser_bug_fails_the_record_and_logs_only_the_exception_type(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from app.ingestion import parsers

    def broken(raw: bytes, context: ParseContext) -> NormalizedEvent:
        raise KeyError("secret-looking record content")

    monkeypatch.setitem(parsers.PARSERS, LINUX, broken)
    with caplog.at_level("ERROR", logger="app.ingestion.parsers"):
        result = parse(LINUX, "anything")
    assert isinstance(result, ParseFailure) and result.code == "parser_error"
    (entry,) = caplog.records
    assert entry.fields == {"source_type": "linux_auth", "error": "KeyError"}  # type: ignore[attr-defined]
    assert "secret-looking" not in caplog.text
