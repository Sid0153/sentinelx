"""How strongly an alert belongs with an incident, or with another alert (pure).

docs/correlation.md has the table; ADR-0009 and ADR-0012 the reasoning. In short:

| Shared with the incident                                        | Strength | Links? |
|-----------------------------------------------------------------|----------|--------|
| host and user (actor or target)                                  | STRONG   | yes    |
| host and source address                                          | STRONG   | yes    |
| an external source address (any hosts)                           | MEDIUM   | yes    |
| host where it shows access, then a new kind of finding (sequence)  | MEDIUM   | yes    |
| host only, user only, or an internal source only                 | WEAK     | no     |

The sequence row: the incident already shows **access** on that host (a finding mapped to
Initial Access or Privilege Escalation, such as a successful logon or a root shell), and the
alert starts at or after that access, within the sequence window, as a **new kind of finding**
(an ATT&CK technique the incident does not have). Sharing only a host is weak evidence; what
follows a foothold on that host is not (ADR-0012). Tactics are too coarse to tell findings
apart (T1078 alone spans four), so kinds of finding are techniques.

Both the alert and the incident must also fall within the correlation window of each other.
Every link comes with the entities it shares and one sentence saying why, so an analyst can
check it by hand.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from app.core.client_ip import Network
from app.events.schema import IpScope
from app.ingestion.enrich import ip_scope
from app.models.incident import LinkStrength

AUTO_LINK = (LinkStrength.STRONG, LinkStrength.MEDIUM)
# Tactics that mean someone got in or got higher privileges on a host.
ACCESS_TACTICS = frozenset({"Initial Access", "Privilege Escalation"})


@dataclass(frozen=True)
class Subject:
    """An alert, or an incident as the union of its alerts."""

    hosts: frozenset[str]
    users: frozenset[str]  # actors and target accounts
    sources: frozenset[str]
    tactics: frozenset[str]
    techniques: frozenset[str]
    first: datetime
    last: datetime
    # Hosts where it shows access, each with when that access began.
    access: tuple[tuple[str, datetime], ...] = ()

    def access_since(self, host: str) -> datetime | None:
        times = [at for h, at in self.access if h == host]
        return min(times) if times else None


@dataclass(frozen=True)
class Link:
    strength: LinkStrength
    shared: list[str]  # e.g. ["host web-01", "user deploy"]
    reason: str


def within(a: Subject, b: Subject, window: timedelta) -> bool:
    """The two time spans are at most `window` apart (inclusive)."""
    return a.first <= b.last + window and a.last >= b.first - window


def _gap(a: Subject, b: Subject) -> timedelta:
    """How far apart the spans are (zero when they overlap)."""
    return max(a.first - b.last, b.first - a.last, timedelta(0))


def _when(a: Subject, b: Subject) -> str:
    gap = _gap(a, b)
    if gap == timedelta(0):
        return "during the same period"
    seconds = int(gap.total_seconds())
    text = f"{seconds} s" if seconds < 120 else f"{seconds // 60} min"
    return f"{text} apart"


def link(
    alert: Subject,
    target: Subject,
    *,
    internal: tuple[Network, ...],
    correlation_window: timedelta,
    sequence_window: timedelta,
) -> Link | None:
    """The strongest reason `alert` belongs with `target`, or None when nothing is shared or
    they are too far apart in time."""
    if not within(alert, target, correlation_window):
        return None
    hosts = sorted(alert.hosts & target.hosts)
    users = sorted(alert.users & target.users)
    sources = sorted(alert.sources & target.sources)
    external = [s for s in sources if ip_scope(s, internal) == IpScope.EXTERNAL]
    labels = (
        [f"host {h}" for h in hosts]
        + [f"user {u}" for u in users]
        + [f"source {s}" for s in sources]
    )
    when = _when(alert, target)

    if hosts and users:
        return Link(LinkStrength.STRONG, labels, f"Same host and user ({_list(labels)}), {when}.")
    if hosts and sources:
        return Link(LinkStrength.STRONG, labels, f"Same host and source ({_list(labels)}), {when}.")
    if external:
        return Link(
            LinkStrength.MEDIUM,
            labels,
            f"Same outside source {', '.join(external)} (one campaign across hosts), {when}.",
        )
    new = sorted(alert.techniques - target.techniques)
    if new and within(alert, target, sequence_window):
        for host in hosts:
            since = target.access_since(host)
            if since is not None and alert.first >= since:
                return Link(
                    LinkStrength.MEDIUM,
                    labels,
                    f"On {host}, after the access the incident shows there (since "
                    f"{since:%Y-%m-%d %H:%M:%S} UTC): a new kind of finding ({', '.join(new)}), "
                    f"{when}.",
                )
    if labels:
        return Link(
            LinkStrength.WEAK, labels, f"Only {_list(labels)} in common, {when}: not linked."
        )
    return None


def _list(labels: list[str]) -> str:
    return labels[0] if len(labels) == 1 else ", ".join(labels[:-1]) + " and " + labels[-1]
