"""A deterministic synthetic workload for the benchmark: ordinary activity at volume, with the
demo attack scenarios mixed in at a fixed rate.

Everything is synthetic (fictional hosts and users, RFC 5737 outside addresses, 10.0.0.0/8
inside) and seeded: the same arguments always give the same records, so two runs measure the
same work. Records are produced in time order, slice by slice, as a shipper would send them.

Ordinary activity is shaped not to trigger rules by accident (each user logs on from their
own internal network; mistyped passwords are rare), so alerts come from the injected attacks,
as in a real environment. `tests/unit/test_benchmark_workload.py` checks both properties.
"""

import random
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.demo import scenarios
from app.events.schema import SourceType

LINUX = SourceType.LINUX_AUTH
WINDOWS = SourceType.WINDOWS_SECURITY

# Attack scenarios injected in turn, one every `attack_every` records.
ATTACKS = [
    "brute_force",
    "brute_force_success",
    "password_spray",
    "distributed_brute_force",
    "privilege_escalation",
    "privileged_account_creation",
    "multi_stage_attack",
    "suspicious_process",
]
ROUTINE_SUDO = [
    "/usr/bin/systemctl restart app",
    "/usr/bin/journalctl -u app --since today",
    "/usr/bin/apt-get update",
    "/usr/bin/tail -n 100 /var/log/syslog",
]
BENIGN_PROCESSES = [
    ("C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\notepad.exe", "notepad.exe report.txt"),
    (
        "C:\\Windows\\explorer.exe",
        "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
        "firefox.exe https://intranet.corp.example/",
    ),
    (
        "C:\\Windows\\System32\\services.exe",
        "C:\\Windows\\System32\\svchost.exe",
        "svchost.exe -k netsvcs",
    ),
    ("C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c dir"),
]


@dataclass(frozen=True)
class World:
    linux_hosts: list[str]
    windows_hosts: list[str]
    users: list[str]
    home_ip: dict[str, list[str]]  # each user's workstation addresses (one /24 per user)


def make_world(
    rng: random.Random, linux_hosts: int = 300, windows_hosts: int = 150, users: int = 120
) -> World:
    names = [f"user{i:03d}" for i in range(users)]
    home = {}
    for index, user in enumerate(names):
        network = f"10.{2 + index // 250}.{index % 250}"
        home[user] = [f"{network}.{rng.randint(10, 250)}" for _ in range(2)]
    return World(
        linux_hosts=[f"srv-{i:03d}" for i in range(linux_hosts)],
        windows_hosts=[f"ws-{i:03d}.corp.example" for i in range(windows_hosts)],
        users=names,
        home_ip=home,
    )


@dataclass(frozen=True)
class Batch:
    source_type: SourceType
    records: list[str]
    attacks: list[str]  # scenario names injected into this batch


class Workload:
    """`batches()` yields batches in time order across [start, end): per slice one Linux and
    one Windows batch, together `batch_size` ordinary records plus any injected attack."""

    def __init__(
        self,
        *,
        seed: int,
        records: int,
        batch_size: int,
        start: datetime,
        end: datetime,
        attack_every: int = 10_000,
        windows_share: float = 0.2,
    ) -> None:
        self.rng = random.Random(seed)  # noqa: S311  (synthetic test data, not cryptography)
        self.world = make_world(self.rng)
        self.records = records
        self.batch_size = batch_size
        self.start, self.end = start, end
        self.attack_every = attack_every
        self.windows_share = windows_share
        self.record_id = 1_000_000

    def batches(self) -> Iterator[Batch]:
        slices = max(1, self.records // self.batch_size)
        span = (self.end - self.start) / slices
        produced = 0
        attacks = 0
        for index in range(slices):
            slice_start = self.start + span * index
            windows_count = int(self.batch_size * self.windows_share)
            linux = [self._linux(slice_start, span) for _ in range(self.batch_size - windows_count)]
            windows = [self._windows(slice_start, span) for _ in range(windows_count)]
            injected: dict[SourceType, list[str]] = {LINUX: [], WINDOWS: []}
            produced += self.batch_size
            while produced >= (attacks + 1) * self.attack_every:
                name = ATTACKS[attacks % len(ATTACKS)]
                lines, source = self._attack(name, slice_start + span / 2, attacks)
                (linux if source == LINUX else windows).extend(lines)
                injected[source].append(name)
                attacks += 1
            # Each batch in time order, as one shipper flush.
            linux.sort()
            yield Batch(LINUX, linux, injected[LINUX])
            if windows:
                yield Batch(WINDOWS, windows, injected[WINDOWS])

    def _moment(self, slice_start: datetime, span: timedelta) -> datetime:
        return slice_start + span * self.rng.random()

    def _linux(self, slice_start: datetime, span: timedelta) -> str:
        rng, world = self.rng, self.world
        moment = self._moment(slice_start, span)
        host = rng.choice(world.linux_hosts)
        user = rng.choice(world.users)
        ip = rng.choice(world.home_ip[user])
        pid = rng.randint(1000, 60000)
        port = rng.randint(40000, 65000)
        roll = rng.random()
        if roll < 0.45:
            message = (
                f"Accepted publickey for {user} from {ip} port {port} ssh2: ED25519 SHA256:k{pid}"
            )
            return scenarios._line(moment, host, f"sshd[{pid}]", message)
        if roll < 0.75:
            message = f"pam_unix(sshd:session): session closed for user {user}"
            return scenarios._line(moment, host, f"sshd[{pid}]", message)
        if roll < 0.88:
            tty, command = rng.randint(0, 9), rng.choice(ROUTINE_SUDO)
            message = f"  {user} : TTY=pts/{tty} ; PWD=/home/{user} ; USER=root ; COMMAND={command}"
            return scenarios._line(moment, host, "sudo", message)
        if roll < 0.90:  # a rare typo: one failure from the user's own workstation
            message = f"Failed password for {user} from {ip} port {port} ssh2"
            return scenarios._line(moment, host, f"sshd[{pid}]", message)
        message = "pam_unix(cron:session): session opened for user root"  # skipped: not security
        return scenarios._line(moment, host, f"CRON[{pid}]", message)

    def _windows(self, slice_start: datetime, span: timedelta) -> str:
        rng, world = self.rng, self.world
        moment = self._moment(slice_start, span)
        host = rng.choice(world.windows_hosts)
        user = rng.choice(world.users)
        self.record_id += 1
        roll = rng.random()
        if roll < 0.5:
            data = {
                "TargetUserName": user,
                "TargetDomainName": "CORP",
                "LogonType": rng.choice(["2", "3", "3", "3", "10"]),
                "IpAddress": rng.choice(world.home_ip[user]),
                "IpPort": str(rng.randint(40000, 65000)),
                "AuthenticationPackageName": "Kerberos",
            }
            return scenarios._windows_event(moment, host, self.record_id, 4624, data)
        if roll < 0.7:
            data = {"TargetUserName": user, "TargetDomainName": "CORP", "LogonType": "3"}
            return scenarios._windows_event(moment, host, self.record_id, 4634, data)
        parent, process, command = rng.choice(BENIGN_PROCESSES)
        data = {
            "SubjectUserName": user,
            "SubjectDomainName": "CORP",
            "NewProcessName": process,
            "ParentProcessName": parent,
            "CommandLine": command,
        }
        return scenarios._windows_event(moment, host, self.record_id, 4688, data)

    def _attack(self, name: str, moment: datetime, index: int) -> tuple[list[str], SourceType]:
        """A demo scenario on a host of this world, from its own outside address."""
        outside = f"{scenarios._DOC_NETS[index % 3]}.{10 + index % 240}"
        if name == "suspicious_process":
            host = self.world.windows_hosts[index % len(self.world.windows_hosts)]
            return scenarios.suspicious_process(
                moment, host=host, username=f"user{index % 120:03d}"
            ), WINDOWS
        host = self.world.linux_hosts[index % len(self.world.linux_hosts)]
        options: dict[str, str] = {"host": host}
        if name in ("brute_force", "brute_force_success", "multi_stage_attack"):
            options["source_ip"] = outside
        if name == "privilege_escalation":
            options["username"] = f"user{index % 120:03d}"
        if name == "privileged_account_creation":
            options["account"] = f"svc-bench{index:04d}"
        lines = getattr(scenarios, name)(moment, **options)
        return list(lines), LINUX
