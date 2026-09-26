"""Simulated log scenarios (ADR-0006): raw auth.log lines sent through the normal pipeline.

This is the thin slice Phase 5 needs as realistic input; Phase 16 builds the full demo
environment. Everything here is synthetic and deterministic (same arguments, same lines):
- outside addresses come from the documentation ranges (RFC 5737: 192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24), inside ones from 10.0.0.0/8;
- hosts and users belong to a fictional environment (corp.example);
- nothing here touches a real system. Ingesting it marks every record as simulated.

Lines use RFC 3339 timestamps (with the offset), so no year inference is involved.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.events.schema import canonical_hostname, canonical_ip

INTERNAL_WORKSTATIONS = ["10.0.2.41", "10.0.2.42", "10.0.2.57", "10.0.3.12"]
TEAM = ["alice", "bob", "deploy", "carol"]
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
    ),
    "brute_force_success": Scenario(
        "brute_force_success",
        "Repeated SSH failures, then a successful logon from the same source",
        brute_force_success,
        _BRUTE_FORCE_OPTIONS,
        "failed attempts before the success",
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
    ),
    "benign": Scenario(
        "benign",
        "Ordinary activity that should trigger no detection",
        benign_activity,
        {"host": "host", "count": "days"},
        "working days of activity",
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
