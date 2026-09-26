"""Correlation's pure parts: every row of the link-strength table, the window edges, the
incident workflow over every status pair, and incident risk."""

import itertools
from datetime import UTC, datetime, timedelta

import pytest

from app.core.client_ip import parse_networks
from app.correlation.scoring import Subject, link, within
from app.incidents import workflow
from app.models.incident import IncidentDisposition, IncidentStatus, LinkStrength
from app.risk.priority import incident_risk

T0 = datetime(2026, 9, 26, 10, 0, tzinfo=UTC)
INTERNAL = parse_networks("10.0.0.0/8, 192.168.0.0/16")
WINDOW = timedelta(hours=2)
SEQUENCE = timedelta(minutes=30)


def subject(
    hosts: tuple[str, ...] = (),
    users: tuple[str, ...] = (),
    sources: tuple[str, ...] = (),
    tactics: tuple[str, ...] = ("Credential Access",),
    techniques: tuple[str, ...] = ("T1110.001",),
    start: timedelta = timedelta(0),
    length: timedelta = timedelta(minutes=1),
    access: tuple[tuple[str, datetime], ...] = (),
) -> Subject:
    return Subject(
        frozenset(hosts),
        frozenset(users),
        frozenset(sources),
        frozenset(tactics),
        frozenset(techniques),
        T0 + start,
        T0 + start + length,
        access,
    )


# The incident shows access on web-01 from T0 (a successful logon).
INCIDENT = subject(
    ("web-01",), ("deploy",), ("203.0.113.45",), ("Credential Access",), access=(("web-01", T0),)
)


def strength(alert: Subject, target: Subject = INCIDENT) -> LinkStrength | None:
    found = link(
        alert, target, internal=INTERNAL, correlation_window=WINDOW, sequence_window=SEQUENCE
    )
    return found.strength if found else None


@pytest.mark.parametrize(
    ("alert", "expected"),
    [
        (subject(("web-01",), ("deploy",)), LinkStrength.STRONG),  # host + user
        (subject(("web-01",), sources=("203.0.113.45",)), LinkStrength.STRONG),  # host + source
        (subject(("db-02",), sources=("203.0.113.45",)), LinkStrength.MEDIUM),  # outside source
        (  # same host, a new stage, soon after
            subject(("web-01",), techniques=("T1136.001",), start=timedelta(minutes=10)),
            LinkStrength.MEDIUM,
        ),
        (subject(("web-01",)), LinkStrength.WEAK),  # host only, same stage
        (subject(("db-02",), ("deploy",)), LinkStrength.WEAK),  # user only
        (subject(("db-02",), sources=("10.0.2.42",)), None),  # nothing shared
        (subject(), None),
    ],
    ids=[
        "host+user",
        "host+source",
        "external-source",
        "host+new-stage",
        "host-only",
        "user-only",
        "nothing",
        "empty",
    ],
)
def test_link_strength_table(alert: Subject, expected: LinkStrength | None) -> None:
    assert strength(alert) == expected


def test_a_shared_internal_source_alone_is_weak() -> None:
    """Shared NAT and jump hosts make internal addresses poor evidence on their own."""
    incident = subject(("web-01",), sources=("10.0.2.42",))
    assert strength(subject(("db-02",), sources=("10.0.2.42",)), incident) == LinkStrength.WEAK


def test_the_target_account_counts_as_a_user() -> None:
    incident = subject(("web-01",), ("deploy", "svc-backup2"))
    assert strength(subject(("web-01",), ("svc-backup2",)), incident) == LinkStrength.STRONG


@pytest.mark.parametrize(
    ("gap", "linked"),
    [(timedelta(hours=2), True), (timedelta(hours=2, seconds=1), False)],
    ids=["exactly-2h", "2h-and-1s"],
)
def test_correlation_window_edge(gap: timedelta, linked: bool) -> None:
    """The alert starts `gap` after the incident's last activity (the window is inclusive)."""
    alert = subject(("web-01",), ("deploy",), start=timedelta(minutes=1) + gap)
    assert (strength(alert) == LinkStrength.STRONG) is linked
    assert within(alert, INCIDENT, WINDOW) is linked


def test_an_alert_before_the_incident_counts_the_same_way() -> None:
    before = subject(("web-01",), ("deploy",), start=-timedelta(hours=2, minutes=1))
    assert strength(before) == LinkStrength.STRONG
    too_early = subject(("web-01",), ("deploy",), start=-timedelta(hours=2, minutes=1, seconds=1))
    assert strength(too_early) is None


@pytest.mark.parametrize(
    ("gap", "expected"),
    [
        (timedelta(minutes=30), LinkStrength.MEDIUM),
        (timedelta(minutes=30, seconds=1), LinkStrength.WEAK),
    ],
)
def test_sequence_window_edge(gap: timedelta, expected: LinkStrength) -> None:
    alert = subject(("web-01",), techniques=("T1136.001",), start=timedelta(minutes=1) + gap)
    assert strength(alert) == expected


def test_a_new_finding_needs_access_on_that_host_first() -> None:
    """Sharing only a host links nothing unless the incident already shows a foothold there,
    and the finding comes at or after it."""
    no_access = subject(("web-01",), ("deploy",))
    finding = subject(("web-01",), techniques=("T1136.001",), start=timedelta(minutes=5))
    assert strength(finding, no_access) == LinkStrength.WEAK
    other_host = subject(("web-01",), ("deploy",), access=(("db-02", T0),))
    assert strength(finding, other_host) == LinkStrength.WEAK
    before = subject(("web-01",), techniques=("T1136.001",), start=-timedelta(minutes=5))
    assert strength(before) == LinkStrength.WEAK
    at_access = subject(("web-01",), techniques=("T1136.001",), start=timedelta(0))
    assert strength(at_access) == LinkStrength.MEDIUM


def test_a_known_stage_on_the_same_host_is_not_enough() -> None:
    """Two brute forces from different sources on one host are not one story."""
    alert = subject(("web-01",), sources=("198.51.100.9",), start=timedelta(minutes=5))
    assert strength(alert) == LinkStrength.WEAK


def test_every_link_says_why() -> None:
    found = link(
        subject(("web-01",), ("deploy",), start=timedelta(seconds=90)),
        INCIDENT,
        internal=INTERNAL,
        correlation_window=WINDOW,
        sequence_window=SEQUENCE,
    )
    assert found is not None
    assert found.shared == ["host web-01", "user deploy"]
    assert found.reason == "Same host and user (host web-01 and user deploy), 30 s apart."
    stage = link(
        subject(("web-01",), techniques=("T1136.001",), start=timedelta(minutes=5)),
        INCIDENT,
        internal=INTERNAL,
        correlation_window=WINDOW,
        sequence_window=SEQUENCE,
    )
    assert stage is not None and stage.reason.startswith("On web-01, after the access")
    assert "a new kind of finding (T1136.001), 4 min apart" in stage.reason


# ---------- incident workflow ----------

S = IncidentStatus
ALLOWED = {
    (S.OPEN, S.TRIAGED),
    (S.OPEN, S.RESOLVED),
    (S.TRIAGED, S.INVESTIGATING),
    (S.TRIAGED, S.RESOLVED),
    (S.INVESTIGATING, S.CONTAINED),
    (S.INVESTIGATING, S.RESOLVED),
    (S.CONTAINED, S.INVESTIGATING),
    (S.CONTAINED, S.RESOLVED),
    (S.RESOLVED, S.CLOSED),
    (S.RESOLVED, S.INVESTIGATING),
}


@pytest.mark.parametrize(("current", "target"), list(itertools.product(S, S)))
def test_every_incident_status_pair(current: IncidentStatus, target: IncidentStatus) -> None:
    resolving = target == S.RESOLVED
    disposition = IncidentDisposition.CONFIRMED_MALICIOUS if resolving else None
    resolution = "Contained and cleaned up" if resolving else None
    if (current, target) in ALLOWED:
        workflow.check(current, target, disposition, resolution, "because")
        assert target in workflow.allowed(current)
    else:
        with pytest.raises(workflow.TransitionError):
            workflow.check(current, target, disposition, resolution, "because")


def test_resolving_needs_a_disposition_and_a_resolution() -> None:
    with pytest.raises(workflow.MissingInput):
        workflow.check(S.OPEN, S.RESOLVED, None, "done", None)
    with pytest.raises(workflow.MissingInput):
        workflow.check(S.OPEN, S.RESOLVED, IncidentDisposition.FALSE_POSITIVE, "", None)
    with pytest.raises(workflow.MissingInput):
        workflow.check(S.OPEN, S.TRIAGED, IncidentDisposition.FALSE_POSITIVE, None, None)


def test_reopening_needs_a_reason_and_closed_is_final() -> None:
    with pytest.raises(workflow.MissingInput, match="reason"):
        workflow.check(S.RESOLVED, S.INVESTIGATING, None, None, None)
    assert workflow.allowed(S.CLOSED) == []
    assert not workflow.accepts_alerts(S.RESOLVED) and not workflow.accepts_alerts(S.CLOSED)
    assert workflow.accepts_alerts(S.CONTAINED)


# ---------- incident risk ----------


def risk(**changes: object) -> tuple[int, list[tuple[str, int]]]:
    values: dict[str, object] = {
        "top_alert_score": 58,
        "top_alert_title": "Successful authentication after repeated failures",
        "top_alert_has_privileged": False,
        "stages": ["AUTH-002"],
        "host_count": 1,
        "privileged_identity": None,
    }
    values.update(changes)
    result = incident_risk(**values)  # type: ignore[arg-type]
    return result.score, [(f.name, f.points) for f in result.factors]


def test_one_stage_on_one_host_is_the_top_alert() -> None:
    assert risk() == (58, [("highest alert", 58)])


def test_each_extra_stage_adds_five_up_to_fifteen() -> None:
    assert risk(stages=["AUTH-001", "AUTH-002"])[0] == 63
    stages = ["AUTH-001", "AUTH-002", "PRIV-001:root_shell", "ACCT-001", "PROC-001"]
    assert risk(stages=stages)[0] == 58 + 15


def test_breadth_hosts_and_a_privileged_account_not_already_counted() -> None:
    assert risk(host_count=2)[0] == 63
    assert risk(privileged_identity="root")[0] == 63
    assert risk(privileged_identity="root", top_alert_has_privileged=True)[0] == 58


def test_incident_risk_is_capped() -> None:
    stages = ["a", "b", "c", "d"]
    assert risk(top_alert_score=95, stages=stages, host_count=3, privileged_identity="x")[0] == 100
