"""The demo environment (Phase 16): a fictional company, its inventory, and a story of
SIMULATED activity placed relative to one moment (the anchor).

Pure: no database, no clock. The same anchor always gives the same records, so a
demonstration can be repeated exactly (and loading it twice stores nothing new: every record
is a duplicate). `app.demo.loader` writes it to the database through the normal pipeline.

The story is three working days of ordinary activity (which must trigger nothing) and, in
the 25 hours before the anchor, one example of each attack scenario. The attacks are three
hours apart, further than the correlation window (2 hours by default), each on its own host
and from its own address, so every incident in the demo comes from one scenario (tested in
tests/unit/test_demo.py). What each step must trigger is listed with it and checked by
tests/integration/test_demo_environment.py.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, time, timedelta

from app.demo.scenarios import SCENARIOS, generate
from app.events.schema import SourceType

DAYS_OF_HISTORY = 3

# Log sources the demo ingests into, one per format (created when missing).
SOURCES: dict[SourceType, str] = {
    SourceType.LINUX_AUTH: "demo-linux-auth",
    SourceType.WINDOWS_SECURITY: "demo-windows-security",
    SourceType.GENERIC_JSON: "demo-network-flows",
    SourceType.HTTP_ACCESS: "demo-web-01-access",
}
# An access log does not name its server: the source says which host it comes from.
SOURCE_HOSTS = {SourceType.HTTP_ACCESS: "web-01"}


@dataclass(frozen=True)
class DemoAsset:
    hostname: str
    ip_addresses: tuple[str, ...]
    asset_type: str
    environment: str
    criticality: str
    owner: str
    description: str
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class DemoIdentity:
    username: str
    display_name: str
    department: str
    title: str
    privilege_level: str
    tags: tuple[str, ...] = ()


ASSETS = (
    DemoAsset("web-01", ("10.0.1.10",), "server", "production", "critical", "Web team",
              "Public web front end (SSH open to the internet for the vendor)", ("linux",)),
    DemoAsset("db-01", ("10.0.1.20",), "server", "production", "critical", "Data team",
              "Customer database (PostgreSQL)", ("linux", "pii")),
    DemoAsset("app-01", ("10.0.1.30",), "server", "production", "high", "Web team",
              "Application server", ("linux",)),
    DemoAsset("jump-01", ("10.0.1.5",), "server", "production", "high", "IT operations",
              "SSH bastion host", ("linux",)),
    DemoAsset("fs-01", ("10.0.1.40",), "server", "production", "high", "IT operations",
              "File server (Windows shares, SSH for administration)", ("windows",)),
    DemoAsset("backup-01", ("10.0.1.50",), "server", "production", "high", "IT operations",
              "Backup server; connects to db-01 every night", ("linux",)),
    DemoAsset("mon-01", ("10.0.1.60",), "server", "production", "medium", "IT operations",
              "Monitoring server", ("linux",)),
    DemoAsset("build-01", ("10.0.2.57",), "server", "development", "medium", "Web team",
              "CI runner; deploys to production with the deploy account", ("linux",)),
    DemoAsset("ws-042.corp.example", ("10.0.2.42",), "workstation", "production", "medium",
              "alice", "Alice's workstation", ("windows",)),
    DemoAsset("ws-017.corp.example", ("10.0.3.12",), "workstation", "production", "medium",
              "bob", "Bob's workstation", ("windows",)),
    DemoAsset("ws-031.corp.example", ("10.0.2.41",), "workstation", "production", "medium",
              "carol", "Carol's workstation", ("windows",)),
)  # fmt: skip

IDENTITIES = (
    DemoIdentity("alice", "Alice Martin", "Engineering", "Software engineer", "standard"),
    DemoIdentity("bob", "Bob Okafor", "Engineering", "Site reliability engineer", "standard"),
    DemoIdentity("carol", "Carol Nguyen", "Data", "Database administrator", "privileged"),
    DemoIdentity("deploy", "Deployment account", "Engineering", "CI deployment", "service"),
    DemoIdentity("root", "Superuser", "IT operations", "Local superuser", "privileged"),
    DemoIdentity("postgres", "PostgreSQL service", "Data", "Database service", "service"),
)


@dataclass(frozen=True)
class Step:
    """One scenario in the story: what is sent, into which source, and what it must do."""

    title: str
    scenario: str
    at: datetime
    options: dict[str, object] = field(default_factory=dict)
    expected_rules: tuple[str, ...] = ()
    why: str = ""  # when the environment changes what the scenario alone would trigger

    @property
    def source_type(self) -> SourceType:
        return SCENARIOS[self.scenario].source_type

    @property
    def source_name(self) -> str:
        return SOURCES[self.source_type]

    def lines(self) -> list[str]:
        return generate(self.scenario, self.at, **self.options)  # type: ignore[arg-type]


def default_anchor(now: datetime) -> datetime:
    """The start of the current hour: loading again within the hour gives the same records."""
    return now.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def _day(anchor: datetime, days_before: int, at: time) -> datetime:
    day = anchor.astimezone(UTC).date() - timedelta(days=days_before)
    return datetime.combine(day, at, UTC)


@dataclass(frozen=True)
class Attack:
    """An attack step: how long before the anchor it starts, and the scenario's options.
    `expected_rules` is None when the step triggers what the scenario alone does."""

    before: timedelta
    title: str
    scenario: str
    options: dict[str, object]
    expected_rules: tuple[str, ...] | None = None
    why: str = ""

    def step(self, anchor: datetime) -> Step:
        expected = self.expected_rules
        if expected is None:
            expected = SCENARIOS[self.scenario].expected_rules
        return Step(
            self.title, self.scenario, anchor - self.before, self.options, expected, self.why
        )


# Oldest first. Each on its own host, from its own address, further apart than the window.
ATTACKS = (
    Attack(timedelta(hours=25), "Password spraying against the application server",
           "password_spray", {"host": "app-01", "source_ip": "198.51.100.23"}),
    Attack(timedelta(hours=22), "Brute force against the bastion's admin account",
           "brute_force", {"host": "jump-01", "user": "admin", "source_ip": "198.51.100.77"}),
    Attack(timedelta(hours=19), "Distributed brute force against bob on the database server",
           "distributed_brute_force", {"host": "db-01", "user": "bob"}),
    Attack(timedelta(hours=16), "Success after failures: carol's account on the file server",
           "brute_force_success",
           {"host": "fs-01", "user": "carol", "source_ip": "192.0.2.150"},
           ("AUTH-001", "AUTH-002", "AUTH-004"),
           "carol has logged on from the office every day, so a logon from an outside network "
           "is also new for her account (AUTH-004 needs that history to judge)"),
    Attack(timedelta(hours=13), "Root shell through sudo on the CI runner",
           "privilege_escalation", {"host": "build-01", "user": "deploy"}),
    Attack(timedelta(hours=10),
           "New local account added to sudo on the monitoring server",
           "privileged_account_creation", {"host": "mon-01", "user": "svc-monitor2"}),
    Attack(timedelta(hours=7), "Encoded PowerShell on alice's workstation",
           "suspicious_process", {"host": "ws-042.corp.example", "user": "alice"}),
    Attack(timedelta(hours=4), "Bob's workstation probing the database server's ports",
           "network_scan", {"host": "ws-017", "source_ip": "10.0.3.12"}),
    Attack(timedelta(minutes=90), "Multi-stage attack on the web server",
           "multi_stage_attack",
           {"host": "web-01", "user": "deploy", "source_ip": "203.0.113.45"}),
)  # fmt: skip


def story(anchor: datetime) -> list[Step]:
    """Every step, in the order it is loaded: the ordinary activity first (detection then has
    the history it needs, as it would in a real deployment), then the attacks."""
    if anchor.tzinfo is None:
        raise ValueError("the anchor must include a time zone")
    first_morning = _day(anchor, DAYS_OF_HISTORY, time(8, 0))
    first_night = _day(anchor, DAYS_OF_HISTORY, time(1, 30))
    first_midnight = _day(anchor, DAYS_OF_HISTORY, time(0, 0))
    days = {"count": DAYS_OF_HISTORY}
    steps = [
        Step("Working days on the web server (SSH, routine sudo, one mistyped password)",
             "benign", first_morning, {"host": "web-01", **days}),
        Step("Working days on Windows (workstation and file server logons)",
             "normal_authentication", first_morning, dict(days)),
        Step("Nightly backups of the database server", "backup_job", first_night, dict(days)),
        Step("Visitors on the public web site, health checks, scanner noise", "web_traffic",
             first_midnight, dict(days)),
    ]  # fmt: skip
    steps += [attack.step(anchor) for attack in ATTACKS]
    return steps
