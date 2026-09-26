"""Simulated log scenarios (ADR-0006): raw log records sent through the normal pipeline.

Each scenario produces records in the format of one source type (auth.log lines, Windows
event JSON, generic JSON connection events) and can only be ingested into a source of that
type. Phase 16 builds the full demo environment (multi-stage story, reset).

Everything here is synthetic and deterministic (same arguments, same lines):
- outside addresses come from the documentation ranges (RFC 5737: 192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24), inside ones from 10.0.0.0/8;
- hosts and users belong to a fictional environment (corp.example);
- nothing here touches a real system. Ingesting it marks every record as simulated.

Syslog lines use RFC 3339 timestamps (with the offset), so no year inference is involved.
"""

import base64
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from app.events.schema import SourceType, canonical_hostname, canonical_ip

INTERNAL_WORKSTATIONS = ["10.0.2.41", "10.0.2.42", "10.0.2.57", "10.0.3.12"]
TEAM = ["alice", "bob", "deploy", "carol"]
_DOC_NETS = ["203.0.113", "198.51.100", "192.0.2"]
COMMON_ACCOUNTS = ["root", "admin", "oracle", "postgres", "test", "ubuntu", "git", "ftpuser"]


def _line(moment: datetime, host: str, program: str, message: str) -> str:
    """One syslog line with an RFC 3339 timestamp: `<time> <host> <program>: <message>`."""
    return f"{moment.isoformat(timespec='microseconds')} {host} {program}: {message}"


@dataclass(frozen=True)
class Scenario:
    """A named scenario. `options` maps the generator options it supports (the demo
    parameters of the brief: host, user, source IP, count, time spread) to the keyword
    arguments of `build`. Options a scenario does not support are refused, not ignored."""

    name: str
    description: str
    build: Callable[..., list[str]]
    options: dict[str, str] = field(default_factory=dict)
    count_meaning: str = ""
    source_type: SourceType = SourceType.LINUX_AUTH
    expected_rules: tuple[str, ...] = ()  # what it must trigger (tested); () means nothing


def brute_force(
    start: datetime,
    *,
    host: str = "web-01",
    username: str = "root",
    source_ip: str = "203.0.113.45",
    attempts: int = 12,
    interval_seconds: int = 3,
    succeed: bool = False,
) -> list[str]:
    """Repeated password failures for one account from one outside source, as sshd logs
    them (including the preauth noise). With succeed=True, the last attempt works."""
    lines: list[str] = []
    moment = start
    pid = 4122
    for attempt in range(attempts):
        port = 50412 + attempt * 7
        sshd = f"sshd[{pid}]"
        lines.append(
            _line(
                moment,
                host,
                sshd,
                f"Failed password for {username} from {source_ip} port {port} ssh2",
            )
        )
        lines.append(
            _line(
                moment + timedelta(milliseconds=400),
                host,
                sshd,
                f"Connection closed by authenticating user {username} {source_ip} "
                f"port {port} [preauth]",
            )
        )
        moment += timedelta(seconds=interval_seconds)
        pid += 1
    if succeed:
        sshd = f"sshd[{pid}]"
        lines.append(
            _line(
                moment,
                host,
                sshd,
                f"Accepted password for {username} from {source_ip} port 50999 ssh2",
            )
        )
        lines.append(
            _line(
                moment + timedelta(milliseconds=50),
                host,
                sshd,
                f"pam_unix(sshd:session): session opened for user {username}(uid=0) by (uid=0)",
            )
        )
    return lines


def brute_force_success(
    start: datetime,
    *,
    host: str = "web-01",
    username: str = "root",
    source_ip: str = "203.0.113.45",
    attempts: int = 12,
    interval_seconds: int = 3,
) -> list[str]:
    """Brute force whose last attempt works: the pattern AUTH-002 looks for."""
    return brute_force(
        start,
        host=host,
        username=username,
        source_ip=source_ip,
        attempts=attempts,
        interval_seconds=interval_seconds,
        succeed=True,
    )


def spray_accounts(count: int) -> list[str]:
    """Common account names first, then numbered ones, so any count is possible."""
    names = COMMON_ACCOUNTS[:count]
    return names + [f"user{i:02d}" for i in range(1, count - len(names) + 1)]


def password_spray(
    start: datetime,
    *,
    host: str = "web-01",
    source_ip: str = "198.51.100.23",
    account_count: int = len(COMMON_ACCOUNTS),
    interval_seconds: int = 5,
) -> list[str]:
    """One outside source trying one password against many accounts (few tries each)."""
    lines = []
    for index, account in enumerate(spray_accounts(account_count)):
        moment = start + timedelta(seconds=index * interval_seconds)
        port = 41000 + index
        sshd = f"sshd[{5200 + index}]"
        lines.append(
            _line(moment, host, sshd, f"Invalid user {account} from {source_ip} port {port}")
        )
        lines.append(
            _line(
                moment + timedelta(milliseconds=300),
                host,
                sshd,
                f"Failed password for invalid user {account} from {source_ip} port {port} ssh2",
            )
        )
    return lines


def distributed_brute_force(
    start: datetime,
    *,
    host: str = "web-01",
    username: str = "deploy",
    source_count: int = 6,
    interval_seconds: int = 20,
) -> list[str]:
    """Password guesses against one existing account, spread over many outside sources with
    three attempts each: every source stays under AUTH-001's per-source threshold, and each
    tries one account only (not AUTH-003)."""
    # Only documentation addresses (RFC 5737): three /24 ranges, 762 hosts.
    pool = [f"{net}.{host}" for net in _DOC_NETS for host in range(1, 255)]
    if source_count > len(pool):
        raise ValueError(f"--count must be at most {len(pool)} for this scenario")
    lines = []
    for index, source_ip in enumerate(pool[:source_count]):
        for attempt in range(3):
            moment = start + timedelta(seconds=index * interval_seconds + attempt * 4)
            port = 43000 + index * 3 + attempt
            lines.append(
                _line(
                    moment,
                    host,
                    f"sshd[{6100 + index}]",
                    f"Failed password for {username} from {source_ip} port {port} ssh2",
                )
            )
    return lines


def benign_activity(start: datetime, *, host: str = "web-01", days: int = 1) -> list[str]:
    """Ordinary working-day activity that should trigger nothing: key-based logons from
    internal workstations, one mistyped password followed by a success, routine sudo."""
    lines = []
    for day in range(days):
        morning = start + timedelta(days=day)
        for index, user in enumerate(TEAM):
            moment = morning + timedelta(minutes=5 + index * 11)
            ip = INTERNAL_WORKSTATIONS[index % len(INTERNAL_WORKSTATIONS)]
            pid = 7000 + day * 100 + index
            sshd = f"sshd[{pid}]"
            if user == "bob":  # one typo, then the right password 20 seconds later
                lines.append(
                    _line(moment, host, sshd, f"Failed password for bob from {ip} port 52001 ssh2")
                )
                moment += timedelta(seconds=20)
                lines.append(
                    _line(
                        moment, host, sshd, f"Accepted password for bob from {ip} port 52002 ssh2"
                    )
                )
            else:
                lines.append(
                    _line(
                        moment,
                        host,
                        sshd,
                        f"Accepted publickey for {user} from {ip} port {52000 + index} ssh2: "
                        f"ED25519 SHA256:demo{index}",
                    )
                )
            if user == "deploy":
                lines.append(
                    _line(
                        moment + timedelta(minutes=2),
                        host,
                        "sudo",
                        "  deploy : TTY=pts/1 ; PWD=/srv/app ; USER=root ; "
                        "COMMAND=/usr/bin/systemctl restart app",
                    )
                )
            lines.append(
                _line(
                    moment + timedelta(hours=7),
                    host,
                    sshd,
                    f"pam_unix(sshd:session): session closed for user {user}",
                )
            )
    return lines


def privilege_escalation(
    start: datetime, *, host: str = "web-01", username: str = "deploy"
) -> list[str]:
    """A user logs on and opens a root shell with sudo; another user without sudo rights
    tries sudo. Both are PRIV-001 indicators."""
    return [
        _line(
            start,
            host,
            "sshd[6100]",
            f"Accepted publickey for {username} from 10.0.2.57 port 53100 ssh2: "
            "ED25519 SHA256:demo-escalation",
        ),
        _line(
            start + timedelta(seconds=40),
            host,
            "sudo",
            f"  {username} : TTY=pts/2 ; PWD=/home/{username} ; USER=root ; COMMAND=/bin/bash",
        ),
        _line(
            start + timedelta(minutes=3),
            host,
            "sudo",
            "      carol : user NOT in sudoers ; TTY=pts/3 ; PWD=/home/carol ; USER=root ; "
            "COMMAND=/usr/bin/cat /etc/shadow",
        ),
    ]


def privileged_account_creation(
    start: datetime, *, host: str = "web-01", account: str = "svc-backup2"
) -> list[str]:
    """A local account is created and added to the sudo group two seconds later."""
    return [
        _line(start, host, "useradd[5120]", f"new group: name={account}, GID=1002"),
        _line(
            start + timedelta(milliseconds=20),
            host,
            "useradd[5120]",
            f"new user: name={account}, UID=1002, GID=1002, home=/home/{account}, "
            "shell=/bin/bash, from=/dev/pts/2",
        ),
        _line(
            start + timedelta(seconds=2), host, "usermod[5125]", f"add '{account}' to group 'sudo'"
        ),
        _line(
            start + timedelta(seconds=2, milliseconds=5),
            host,
            "usermod[5125]",
            f"add '{account}' to shadow group 'sudo'",
        ),
    ]


def multi_stage_attack(
    start: datetime,
    *,
    host: str = "web-01",
    username: str = "deploy",
    source_ip: str = "203.0.113.45",
    account: str = "svc-backup2",
) -> list[str]:
    """The brief's correlation example as log records, one stage after the other on one host:
    a brute force against an existing account from an outside address that ends in a
    successful logon, a root shell through sudo half a minute later, and a new local account
    added to the sudo group a minute after that. Four rules fire (AUTH-001, AUTH-002,
    PRIV-001, ACCT-001); correlation should make them one incident."""
    attack = brute_force_success(start, host=host, username=username, source_ip=source_ip)
    success_at = start + timedelta(seconds=12 * 3)
    shell = [
        _line(
            success_at + timedelta(seconds=30),
            host,
            "sudo",
            f"  {username} : TTY=pts/0 ; PWD=/home/{username} ; USER=root ; COMMAND=/bin/bash",
        )
    ]
    persistence = privileged_account_creation(
        success_at + timedelta(minutes=1, seconds=30), host=host, account=account
    )
    return attack + shell + persistence


def _windows_event(
    moment: datetime, host: str, record_id: int, event_id: int, data: dict[str, str]
) -> str:
    return json.dumps(
        {
            "EventID": event_id,
            "TimeCreated": moment.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "Computer": host,
            "EventRecordID": record_id,
            "EventData": data,
        }
    )


def suspicious_process(
    start: datetime, *, host: str = "ws-042.corp.example", username: str = "alice"
) -> list[str]:
    """Windows process creation (event 4688): an ordinary program, then PowerShell started
    with an encoded command. The encoded text only prints a message: it is demo data, and
    nothing ever executes it."""
    encoded = base64.b64encode(
        "Write-Output 'SentinelX demo: simulated encoded command'".encode("utf-16-le")
    ).decode()
    windows = "C:\\Windows\\System32\\"
    return [
        _windows_event(
            start,
            host,
            88001,
            4688,
            {
                "SubjectUserName": username,
                "SubjectDomainName": "CORP",
                "NewProcessName": windows + "notepad.exe",
                "ParentProcessName": "C:\\Windows\\explorer.exe",
                "CommandLine": f"notepad.exe C:\\Users\\{username}\\notes.txt",
            },
        ),
        _windows_event(
            start + timedelta(minutes=2),
            host,
            88002,
            4688,
            {
                "SubjectUserName": username,
                "SubjectDomainName": "CORP",
                "NewProcessName": windows + "WindowsPowerShell\\v1.0\\powershell.exe",
                "ParentProcessName": windows + "cmd.exe",
                "CommandLine": f"powershell.exe -NoProfile -WindowStyle Hidden -enc {encoded}",
            },
        ),
    ]


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521]
COMMON_PORTS += [3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]


def network_scan(
    start: datetime,
    *,
    host: str = "ws-042",
    source_ip: str = "10.0.2.42",
    port_count: int = 25,
    interval_seconds: int = 1,
) -> list[str]:
    """One internal workstation connecting to many ports of a server within seconds
    (generic JSON network events, as a flow or firewall log would give them)."""
    ports = COMMON_PORTS + list(range(10000, 10000 + max(0, port_count - len(COMMON_PORTS))))
    lines = []
    for index, port in enumerate(ports[:port_count]):
        moment = start + timedelta(seconds=index * interval_seconds)
        lines.append(
            json.dumps(
                {
                    "timestamp": moment.astimezone(UTC).isoformat(),
                    "event_category": "network",
                    "event_action": "connection",
                    "event_outcome": "success" if port in (22, 80, 443) else "failure",
                    "host": host,
                    "source_ip": source_ip,
                    "source_port": 49152 + index,
                    "destination_ip": "10.0.1.20",
                    "destination_port": port,
                    "protocol": "tcp",
                }
            )
        )
    return lines


_BRUTE_FORCE_OPTIONS = {
    "host": "host",
    "user": "username",
    "source_ip": "source_ip",
    "count": "attempts",
    "interval": "interval_seconds",
}

SCENARIOS: dict[str, Scenario] = {
    "brute_force": Scenario(
        "brute_force",
        "Repeated SSH password failures from one outside source",
        brute_force,
        _BRUTE_FORCE_OPTIONS,
        "failed attempts",
        expected_rules=("AUTH-001",),
    ),
    "brute_force_success": Scenario(
        "brute_force_success",
        "Repeated SSH failures, then a successful logon from the same source",
        brute_force_success,
        _BRUTE_FORCE_OPTIONS,
        "failed attempts before the success",
        expected_rules=("AUTH-001", "AUTH-002"),
    ),
    "password_spray": Scenario(
        "password_spray",
        "One outside source trying many accounts",
        password_spray,
        {
            "host": "host",
            "source_ip": "source_ip",
            "count": "account_count",
            "interval": "interval_seconds",
        },
        "accounts tried",
        expected_rules=("AUTH-003",),
    ),
    "distributed_brute_force": Scenario(
        "distributed_brute_force",
        "One real account attacked from many outside sources, a few attempts each",
        distributed_brute_force,
        {
            "host": "host",
            "user": "username",
            "count": "source_count",
            "interval": "interval_seconds",
        },
        "attacking sources",
        expected_rules=("AUTH-005",),
    ),
    "multi_stage_attack": Scenario(
        "multi_stage_attack",
        "Brute force, successful logon, root shell, new privileged account: one incident",
        multi_stage_attack,
        {"host": "host", "user": "username", "source_ip": "source_ip"},
        expected_rules=("AUTH-001", "AUTH-002", "PRIV-001", "ACCT-001"),
    ),
    "benign": Scenario(
        "benign",
        "Ordinary activity that should trigger no detection",
        benign_activity,
        {"host": "host", "count": "days"},
        "working days of activity",
    ),
    "privilege_escalation": Scenario(
        "privilege_escalation",
        "A root shell through sudo, and a sudo attempt by a user without sudo rights",
        privilege_escalation,
        {"host": "host", "user": "username"},
        expected_rules=("PRIV-001",),
    ),
    "privileged_account_creation": Scenario(
        "privileged_account_creation",
        "A new local account added to the sudo group right after it is created",
        privileged_account_creation,
        {"host": "host", "user": "account"},
        expected_rules=("ACCT-001",),
    ),
    "suspicious_process": Scenario(
        "suspicious_process",
        "Windows: PowerShell started with an encoded command (event 4688)",
        suspicious_process,
        {"host": "host", "user": "username"},
        source_type=SourceType.WINDOWS_SECURITY,
        expected_rules=("PROC-001",),
    ),
    "network_scan": Scenario(
        "network_scan",
        "An internal host connecting to many ports of one server (generic JSON)",
        network_scan,
        {
            "host": "host",
            "source_ip": "source_ip",
            "count": "port_count",
            "interval": "interval_seconds",
        },
        "ports tried",
        source_type=SourceType.GENERIC_JSON,
        expected_rules=("NET-001",),
    ),
}

MAX_COUNT = 5000  # one ingest batch
MAX_INTERVAL_SECONDS = 3600


def generate(
    name: str,
    start: datetime,
    *,
    host: str | None = None,
    user: str | None = None,
    source_ip: str | None = None,
    count: int | None = None,
    interval: int | None = None,
) -> list[str]:
    """Lines for one scenario with the options the caller chose (None: scenario default).

    Raises ValueError with a message fit for the operator: unknown scenario, an option the
    scenario does not use, or an invalid value. Values are validated here, not trusted,
    because they end up inside log lines that the parsers must accept.
    """
    scenario = SCENARIOS.get(name)
    if scenario is None:
        raise ValueError(f"unknown scenario; choose from {', '.join(SCENARIOS)}")
    if start.tzinfo is None:
        raise ValueError("the start time must include a time zone")
    given: dict[str, object] = {
        option: value
        for option, value in {
            "host": host,
            "user": user,
            "source_ip": source_ip,
            "count": count,
            "interval": interval,
        }.items()
        if value is not None
    }
    unsupported = sorted(set(given) - set(scenario.options))
    if unsupported:
        names = ", ".join(f"--{option.replace('_', '-')}" for option in unsupported)
        raise ValueError(f"scenario {name} does not use {names}")
    if host is not None:
        host = canonical_hostname(host)
        given["host"] = host
    if user is not None and (not user or len(user) > 64 or not user.isprintable() or " " in user):
        raise ValueError("--user must be a single word of at most 64 printable characters")
    if source_ip is not None:
        given["source_ip"] = canonical_ip(source_ip)
    if count is not None and not 1 <= count <= MAX_COUNT:
        raise ValueError(f"--count must be between 1 and {MAX_COUNT}")
    if interval is not None and not 1 <= interval <= MAX_INTERVAL_SECONDS:
        raise ValueError(f"--interval must be between 1 and {MAX_INTERVAL_SECONDS} seconds")
    return scenario.build(start, **{scenario.options[k]: v for k, v in given.items()})
