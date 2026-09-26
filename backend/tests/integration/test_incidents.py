"""Correlation and incidents against a real PostgreSQL: the brief's chain becomes one incident
(also across batches), unrelated alerts do not, the windows are respected, analyst decisions
(resolve, unlink) are respected by the engine, and the investigation record is append-only."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.demo.scenarios import generate
from app.detection.library import Library
from app.detection.service import run_manual
from app.incidents import queries, service
from app.incidents.settings import SettingsUpdate, update
from app.ingestion.service import IngestRequest, ingest
from app.models.alert import Alert
from app.models.event import BatchChannel, IngestionBatch, LogSource
from app.models.incident import (
    EvidenceAction,
    EvidenceTag,
    Incident,
    IncidentAlert,
    IncidentDisposition,
    IncidentStatus,
)
from app.models.user import Role, User
from tests.helpers import audit_entries, make_source, make_user

pytestmark = pytest.mark.integration

START = (datetime.now(UTC) - timedelta(hours=6)).replace(microsecond=0)


def send(db: Session, lines: list[str], source: LogSource | None = None) -> IngestionBatch:
    source = source or make_source(db)
    request = IngestRequest(
        source, [line.encode() for line in lines], BatchChannel.DEMO, None, True
    )
    return ingest(db, request, get_settings())


def incidents(db: Session) -> list[Incident]:
    return list(db.scalars(select(Incident).order_by(Incident.number)))


def members(db: Session, incident: Incident) -> dict[str, IncidentAlert]:
    return {
        alert.rule_id: link
        for link, alert in db.execute(
            select(IncidentAlert, Alert)
            .join(Alert, Alert.id == IncidentAlert.alert_id)
            .where(IncidentAlert.incident_id == incident.id)
        )
    }


def failures_then_success(start: datetime, source_ip: str, user: str = "deploy") -> list[str]:
    return generate("brute_force_success", start, user=user, source_ip=source_ip, host="web-01")


@pytest.fixture
def analyst(db_session: Session) -> User:
    return make_user(db_session, Role.ANALYST, email="analyst@example.com")


def resolve(db: Session, incident: Incident, analyst: User) -> None:
    service.transition(
        db,
        incident.id,
        IncidentStatus.RESOLVED,
        IncidentDisposition.CONFIRMED_MALICIOUS,
        "Account locked, host rebuilt",
        None,
        analyst,
    )


# ---------- the chain ----------


def test_the_brief_chain_becomes_one_incident(db_session: Session, seeded_rules: Library) -> None:
    batch = send(db_session, generate("multi_stage_attack", START))
    assert (batch.incidents_created, batch.incidents_updated) == (1, 0)
    (incident,) = incidents(db_session)
    links = members(db_session, incident)
    assert set(links) == {"AUTH-001", "AUTH-002", "PRIV-001", "ACCT-001"}
    # Each link says why. AUTH-001 is processed first (earliest activity) and opens the
    # incident together with its partner AUTH-002.
    assert links["AUTH-001"].link_strength == "ORIGIN"
    assert links["AUTH-002"].link_strength == "STRONG"
    assert links["PRIV-001"].link_strength == "STRONG"  # host web-01 and user deploy
    assert links["ACCT-001"].link_strength == "MEDIUM"  # same host, a new stage
    assert "a new kind of finding (T1098.007, T1136.001)" in links["ACCT-001"].reason
    assert incident.hosts == ["web-01"] and incident.source_ips == ["203.0.113.45"]
    assert incident.usernames == ["deploy", "root", "svc-backup2"]  # root: the sudo target
    assert set(incident.tactics) >= {"Credential Access", "Privilege Escalation", "Persistence"}
    assert incident.severity == "high" and incident.alert_count == 4 and incident.simulated
    assert incident.title == "Multi-stage activity on web-01 (deploy from 203.0.113.45)"
    assert incident.created_reason.startswith("Multi-stage activity:")
    # Risk: the highest alert plus the chain bonus, and the sum is what is shown.
    assert incident.risk_breakdown[0]["factor"] == "highest alert"
    assert any(f["factor"] == "attack stages" for f in incident.risk_breakdown)
    assert incident.risk_score == sum(f["points"] for f in incident.risk_breakdown)


def test_the_chain_across_four_batches_is_still_one_incident(
    db_session: Session, seeded_rules: Library
) -> None:
    lines = generate("multi_stage_attack", START)
    source = make_source(db_session)
    success = next(i for i, line in enumerate(lines) if "Accepted" in line)
    shell = next(i for i, line in enumerate(lines) if "COMMAND=/bin/bash" in line)
    account = next(i for i, line in enumerate(lines) if "useradd" in line)
    parts = [lines[:success], lines[success:shell], lines[shell:account], lines[account:]]
    reports = [send(db_session, part, source) for part in parts]
    (incident,) = incidents(db_session)
    assert set(members(db_session, incident)) == {"AUTH-001", "AUTH-002", "PRIV-001", "ACCT-001"}
    # The failures alone are a medium alert: no incident until the success arrives.
    assert [(r.incidents_created, r.incidents_updated) for r in reports] == [
        (0, 0),
        (1, 0),
        (0, 1),
        (0, 1),
    ]


def test_the_timeline_is_rebuilt_from_stored_rows_in_order(
    db_session: Session, seeded_rules: Library
) -> None:
    send(db_session, generate("multi_stage_attack", START))
    (incident,) = incidents(db_session)
    entries, cursor = queries.timeline(db_session, incident.id, 500, None)
    assert cursor is None
    times = [e["at"] for e in entries]
    assert times == sorted(times)
    events = [e["event"] for e in entries if e["kind"] == "event"]
    assert events[0]["outcome"] == "failure" and "Failed password" in events[0]["raw_text"]
    actions = [(e["action"], e["outcome"]) for e in events]
    assert ("logon", "success") in actions
    success = actions.index(("logon", "success"))
    assert all(outcome == "failure" for _, outcome in actions[:success])
    assert events[-1]["action"] == "group_member_added"
    assert {e["alert"]["rule_id"] for e in entries if e["kind"] == "alert"} == {
        "AUTH-001",
        "AUTH-002",
        "PRIV-001",
        "ACCT-001",
    }
    kinds = {e["activity"]["kind"] for e in entries if e["kind"] == "activity"}
    assert kinds == {"CREATED", "LINK"}
    # Paged with the keyset, the same entries come back in the same order.
    paged, cursor = [], None
    while True:
        page, cursor = queries.timeline(db_session, incident.id, 7, cursor)
        paged += page
        if cursor is None:
            break
    assert [e["id"] for e in paged] == [e["id"] for e in entries]


# ---------- what does not become an incident ----------


def test_a_lone_medium_alert_stays_standalone(db_session: Session, seeded_rules: Library) -> None:
    batch = send(db_session, generate("brute_force", START))
    assert batch.alerts_created == 1 and batch.incidents_created == 0
    assert incidents(db_session) == []


def test_unrelated_brute_forces_are_not_merged(db_session: Session, seeded_rules: Library) -> None:
    send(db_session, generate("brute_force", START, host="web-01", source_ip="203.0.113.45"))
    send(db_session, generate("brute_force", START, host="db-02", source_ip="198.51.100.77"))
    assert incidents(db_session) == []


def test_one_outside_source_against_two_hosts_is_one_incident(
    db_session: Session, seeded_rules: Library
) -> None:
    send(db_session, generate("brute_force", START, host="web-01"))
    send(db_session, generate("brute_force", START + timedelta(minutes=10), host="db-02"))
    (incident,) = incidents(db_session)
    strengths = db_session.scalars(
        select(IncidentAlert.link_strength).where(IncidentAlert.incident_id == incident.id)
    ).all()
    assert sorted(strengths) == ["MEDIUM", "ORIGIN"]
    assert incident.hosts == ["db-02", "web-01"]
    assert any(f["factor"] == "hosts" for f in incident.risk_breakdown)


# ---------- analyst decisions ----------


def test_a_resolved_incident_is_not_extended_new_activity_links_back(
    db_session: Session, seeded_rules: Library, analyst: User
) -> None:
    send(db_session, failures_then_success(START, "203.0.113.45"))
    (first,) = incidents(db_session)
    resolve(db_session, first, analyst)
    send(db_session, failures_then_success(START + timedelta(minutes=30), "203.0.113.46"))
    old, new = incidents(db_session)
    assert old.status == IncidentStatus.RESOLVED and old.alert_count == 2
    assert new.status == IncidentStatus.OPEN and new.related_incident_id == old.id


def test_an_unlinked_alert_is_not_linked_back(
    db_session: Session, seeded_rules: Library, analyst: User
) -> None:
    source = make_source(db_session)
    send(db_session, failures_then_success(START, "203.0.113.45"), source)
    (incident,) = incidents(db_session)
    auth_001 = next(
        a for a in queries.links(db_session, incident.id) if a[1].rule_id == "AUTH-001"
    )[1]
    service.unlink_alert(db_session, incident.id, auth_001.id, "separate scanner noise", analyst)
    # The same brute force continues: its alert is extended and correlated again.
    later = generate("brute_force", START + timedelta(minutes=3), user="deploy", host="web-01")
    send(db_session, later, source)
    assert "AUTH-001" not in members(db_session, incident)
    assert (entry := audit_entries(db_session, "INCIDENT_ALERT_UNLINKED")[0]).details["reason"]
    assert entry.details["alert_id"] == str(auth_001.id)


@pytest.mark.parametrize(
    ("gap", "linked"), [(timedelta(hours=2), True), (timedelta(hours=2, seconds=1), False)]
)
def test_the_correlation_window_edge_on_stored_alerts(
    db_session: Session, seeded_rules: Library, gap: timedelta, linked: bool
) -> None:
    send(db_session, failures_then_success(START, "203.0.113.45"))
    (first,) = incidents(db_session)
    # A second, different AUTH-002 (another source) for the same host and user, starting
    # `gap` after the incident's last activity.
    later = failures_then_success(first.last_activity_at + gap, "203.0.113.46")
    send(db_session, later)
    assert (len(incidents(db_session)) == 1) is linked


def test_an_admin_can_narrow_the_window(
    db_session: Session, seeded_rules: Library, analyst: User
) -> None:
    admin = make_user(db_session, Role.ADMIN, email="settings-admin@example.com")
    update(
        db_session, SettingsUpdate(correlation_window_minutes=15, sequence_window_minutes=5), admin
    )
    send(db_session, failures_then_success(START, "203.0.113.45"))
    (first,) = incidents(db_session)
    send(
        db_session,
        failures_then_success(first.last_activity_at + timedelta(minutes=16), "203.0.113.46"),
    )
    assert len(incidents(db_session)) == 2
    (entry,) = audit_entries(db_session, "SETTINGS_CHANGED")
    assert entry.details["changes"]["correlation_window_minutes"] == {"from": 120, "to": 15}


def test_notes_evidence_and_activity_are_append_only(
    db_session: Session, seeded_rules: Library, analyst: User
) -> None:
    send(db_session, generate("multi_stage_attack", START))
    (incident,) = incidents(db_session)
    service.add_note(db_session, incident.id, "Source is a known VPS provider.", analyst)
    event_id = db_session.scalar(text("SELECT event_id FROM alert_events LIMIT 1"))
    service.change_evidence(
        db_session,
        incident.id,
        event_id=event_id,
        alert_id=None,
        action=EvidenceAction.PIN,
        tag=EvidenceTag.INITIAL_ACCESS,
        comment="first failure",
        actor=analyst,
    )
    for table in ("incident_notes", "incident_evidence", "incident_activity"):
        for statement in (f"UPDATE {table} SET created_at = now()", f"DELETE FROM {table}"):
            with pytest.raises(DBAPIError, match="append-only"), db_session.begin_nested():
                db_session.execute(text(statement))


def test_a_closed_incident_takes_no_more_changes(
    db_session: Session, seeded_rules: Library, analyst: User
) -> None:
    send(db_session, generate("multi_stage_attack", START))
    (incident,) = incidents(db_session)
    resolve(db_session, incident, analyst)
    service.transition(db_session, incident.id, IncidentStatus.CLOSED, None, None, None, analyst)
    assert incident.disposition == "confirmed_malicious" and incident.closed_at is not None
    for action in (
        lambda: service.add_note(db_session, incident.id, "late note", analyst),
        lambda: service.rename(db_session, incident.id, "Renamed", analyst),
        lambda: service.transition(
            db_session, incident.id, IncidentStatus.INVESTIGATING, None, None, "again", analyst
        ),
    ):
        with pytest.raises(Exception, match="final|closed"):
            action()


def details(db: Session, **where: Any) -> list[Incident]:
    statement = select(Incident)
    for key, value in where.items():
        statement = statement.where(getattr(Incident, key) == value)
    return list(db.scalars(statement))


# ---------- the sweep, the backfill, and what counts as access ----------


def test_a_standalone_alert_joins_once_the_incident_grows_to_cover_it(
    db_session: Session, seeded_rules: Library
) -> None:
    """A brute force on db-02 is a lone medium alert. Later the incident on web-01 grows to
    db-02 and the account root (the same outside source tries db-02 as root): the waiting alert
    joins without any new activity of its own."""
    send(db_session, generate("brute_force", START, host="db-02", source_ip="203.0.113.60"))
    send(db_session, failures_then_success(START + timedelta(minutes=5), "203.0.113.45"))
    (incident,) = incidents(db_session)
    assert "db-02" not in incident.hosts
    later = START + timedelta(minutes=10)
    send(db_session, generate("brute_force", later, host="db-02", source_ip="203.0.113.45"))
    rows = db_session.execute(
        select(IncidentAlert, Alert)
        .join(Alert, Alert.id == IncidentAlert.alert_id)
        .where(IncidentAlert.incident_id == incident.id)
    ).all()
    sources = {
        str(alert.source_ip): link.link_strength for link, alert in rows if alert.host == "db-02"
    }
    assert sources == {"203.0.113.45": "MEDIUM", "203.0.113.60": "STRONG"}  # the sweep: host + user


def test_a_manual_run_correlates_alerts_that_never_were(
    db_session: Session, seeded_rules: Library, analyst: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Alerts from before correlation existed (simulated by switching it off) are picked up by
    a manual detection run over their range, once."""
    from app.correlation import service as correlation

    real = correlation.correlate
    monkeypatch.setattr(correlation, "correlate", lambda db, ids, now: correlation.Result())
    send(db_session, generate("multi_stage_attack", START))
    assert incidents(db_session) == []
    monkeypatch.setattr(correlation, "correlate", real)
    window = (START - timedelta(hours=1), START + timedelta(hours=1))
    run = run_manual(db_session, *window, analyst)
    assert run.incidents_created == 1
    (incident,) = incidents(db_session)
    assert set(members(db_session, incident)) == {"AUTH-001", "AUTH-002", "PRIV-001", "ACCT-001"}
    again = run_manual(db_session, *window, analyst)
    assert (again.incidents_created, again.incidents_updated) == (0, 0)


def test_a_refused_sudo_is_not_a_foothold(db_session: Session, seeded_rules: Library) -> None:
    """A brute force against carol and her refused sudo on web-02 make one incident. A new
    account created there minutes later shares only the host with it. The refusal maps to a
    privilege-escalation technique but gave nobody access, so the incident shows no foothold on
    web-02 and the account creation opens an incident of its own instead of joining."""
    source = make_source(db_session)
    send(db_session, generate("brute_force", START, host="web-02", user="carol"), source)
    refused = (
        f"{(START + timedelta(minutes=1)).isoformat()} web-02 sudo:    carol : user NOT in "
        "sudoers ; TTY=pts/3 ; PWD=/home/carol ; USER=root ; COMMAND=/usr/bin/id"
    )
    send(db_session, [refused], source)
    (attempts,) = incidents(db_session)
    assert set(members(db_session, attempts)) == {"AUTH-001", "PRIV-001"}
    later = START + timedelta(minutes=3)
    send(db_session, generate("privileged_account_creation", later, host="web-02"), source)
    first, second = incidents(db_session)
    assert set(members(db_session, first)) == {"AUTH-001", "PRIV-001"}
    assert set(members(db_session, second)) == {"ACCT-001"}


def test_a_campaign_is_judged_on_all_its_sources_not_the_ten_shown(
    db_session: Session, seeded_rules: Library
) -> None:
    """Twenty outside sources try two accounts on web-01. For one account the first ten sources
    come first, for the other the last ten: each alert's display list (its ten most frequent
    values) shares no source with the other's, yet all twenty are shared. Correlation reads
    the evidence, so this is one campaign, one incident (found live: a spray split into seven)."""
    sources = [f"203.0.113.{150 + i}" for i in range(20)]
    lines = []
    for account, order in (("appuser", sources), ("backup", sources[10:] + sources[:10])):
        for i, source in enumerate(order):
            moment = (START + timedelta(seconds=i * 3)).isoformat()
            lines.append(
                f"{moment} web-01 sshd[{7000 + i}]: Failed password for {account} "
                f"from {source} port {40000 + i} ssh2"
            )
    send(db_session, lines)
    alerts = db_session.scalars(select(Alert).where(Alert.rule_id == "AUTH-005")).all()
    assert len(alerts) == 2
    shown = [set(a.entities["source_ip"]) for a in alerts]
    assert len(shown[0]) == len(shown[1]) == 10 and not shown[0] & shown[1]
    (incident,) = incidents(db_session)
    assert set(members(db_session, incident)) == {"AUTH-005"}
    assert incident.alert_count == 2 and len(incident.source_ips) == 20
