"""The demo environment (Phase 16) loaded into PostgreSQL through the real pipeline: every
step triggers exactly the rules it lists, the incidents are the documented ones, loading
again changes nothing, and everything stored is SIMULATED."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import cli
from app.audit.events import AuditAction
from app.core.config import get_settings
from app.demo.environment import ASSETS, IDENTITIES, SOURCES, story
from app.demo.loader import LoadReport, load, status
from app.detection.library import Library
from app.models.alert import Alert
from app.models.audit_log import AuditLog
from app.models.context import Asset, Identity
from app.models.event import Event, LogSource, RawEvent
from app.models.incident import Incident, IncidentAlert

ANCHOR = datetime(2026, 9, 25, 18, 0, tzinfo=UTC)


@pytest.fixture
def loaded(db_session: Session, seeded_rules: Library) -> LoadReport:
    return load(db_session, ANCHOR, get_settings())


def test_every_step_triggers_exactly_its_rules(loaded: LoadReport) -> None:
    triggered = {r.step.title: r.rules for r in loaded.steps}
    expected = {r.step.title: set(r.step.expected_rules) for r in loaded.steps}
    assert triggered == expected
    for result in loaded.steps:
        batch = result.batch
        assert batch.failed_count == 0 and batch.parsed_count > 0, result.step.title
        assert batch.duplicate_count == 0 and batch.simulated


def test_the_inventory_and_sources_are_created(db_session: Session, loaded: LoadReport) -> None:
    assert loaded.assets_created == len(ASSETS)
    assert loaded.identities_created == len(IDENTITIES)
    assert sorted(loaded.sources_created) == sorted(SOURCES.values())
    assert db_session.scalar(select(func.count()).select_from(Asset)) == len(ASSETS)
    assert db_session.scalar(select(func.count()).select_from(Identity)) == len(IDENTITIES)
    # Enrichment saw the inventory: every event on a known host is linked to its asset.
    unlinked = db_session.scalars(
        select(Event.host).where(Event.asset_id.is_(None), Event.host.is_not(None)).distinct()
    ).all()
    assert unlinked == []


# docs/demo.md lists these. The other alerts (spraying, the bastion brute force, the
# distributed brute force, the port scan) are single medium findings: they stay alerts.
EXPECTED_INCIDENTS = [
    ("fs-01", ["AUTH-001", "AUTH-002", "AUTH-004"]),
    ("build-01", ["PRIV-001", "PRIV-001"]),  # deploy's root shell; carol not in sudoers
    ("mon-01", ["ACCT-001"]),
    ("ws-042.corp.example", ["PROC-001"]),
    ("web-01", ["ACCT-001", "AUTH-001", "AUTH-002", "PRIV-001"]),
]


def test_the_incidents_are_the_documented_ones(db_session: Session, loaded: LoadReport) -> None:
    incidents = db_session.scalars(select(Incident).order_by(Incident.first_activity_at)).all()
    found = []
    for incident in incidents:
        rules = db_session.scalars(
            select(Alert.rule_id)
            .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
            .where(IncidentAlert.incident_id == incident.id)
        ).all()
        assert len(incident.hosts) == 1, incident.hosts  # one scenario on one host each
        assert incident.simulated
        found.append((incident.hosts[0], sorted(rules)))
    assert found == EXPECTED_INCIDENTS
    assert loaded.incidents_created == len(EXPECTED_INCIDENTS)
    # One alert per rule a step triggers, plus the second PRIV-001 (two users on build-01).
    alerts = db_session.scalars(select(Alert.rule_id)).all()
    expected = [rule for result in loaded.steps for rule in result.step.expected_rules]
    assert sorted(alerts) == sorted([*expected, "PRIV-001"])
    assert loaded.alerts_created == len(alerts)


def test_everything_stored_is_simulated(db_session: Session, loaded: LoadReport) -> None:
    assert db_session.scalar(select(func.count()).where(RawEvent.simulated.is_(False))) == 0
    assert db_session.scalar(select(func.count()).where(Event.simulated.is_(False))) == 0
    current = status(db_session)
    assert current.demo_only and current.simulated_records == loaded.records


def test_nothing_happens_after_the_anchor(loaded: LoadReport, db_session: Session) -> None:
    latest = db_session.scalar(select(func.max(Event.timestamp)))
    assert latest is not None and latest < ANCHOR
    earliest = db_session.scalar(select(func.min(Event.timestamp)))
    assert earliest is not None and earliest >= ANCHOR - timedelta(days=4)


def test_loading_again_stores_nothing_new(db_session: Session, loaded: LoadReport) -> None:
    alerts = db_session.scalar(select(func.count()).select_from(Alert))
    again = load(db_session, ANCHOR, get_settings())
    assert again.assets_created == again.identities_created == 0
    assert again.sources_created == []
    assert again.duplicates == again.records == loaded.records
    assert again.alerts_created == again.incidents_created == 0
    assert db_session.scalar(select(func.count()).select_from(Alert)) == alerts


def test_each_load_is_audited(db_session: Session, loaded: LoadReport) -> None:
    (entry,) = db_session.scalars(
        select(AuditLog).where(AuditLog.action == AuditAction.DEMO_LOADED)
    ).all()
    assert entry.details["records"] == loaded.records
    assert entry.details["alerts_created"] == loaded.alerts_created


def test_a_reset_records_the_replaced_audit_log(db_session: Session, seeded_rules: Library) -> None:
    load(db_session, ANCHOR, get_settings(), previous_audit_head=(41, "ab" * 32))
    (entry,) = db_session.scalars(
        select(AuditLog).where(AuditLog.action == AuditAction.DEMO_RESET)
    ).all()
    assert entry.details["previous_audit_head_seq"] == 41
    assert entry.details["previous_audit_head_hash"] == "ab" * 32


def test_a_source_of_the_wrong_type_is_refused(db_session: Session, seeded_rules: Library) -> None:
    db_session.add(LogSource(name=SOURCES[next(iter(SOURCES))], source_type="generic_json"))
    db_session.flush()
    with pytest.raises(ValueError, match="exists with type generic_json"):
        load(db_session, ANCHOR, get_settings())


def test_the_story_is_the_same_for_the_same_anchor() -> None:
    first = [(s.title, s.lines()) for s in story(ANCHOR)]
    assert first == [(s.title, s.lines()) for s in story(ANCHOR)]
    later = story(ANCHOR + timedelta(days=1))
    assert all(a.lines() != b.lines() for a, b in zip(story(ANCHOR), later, strict=True))


# ---------- CLI ----------


def test_cli_loads_the_demo_and_reports_each_step(
    cli_sessions: Session, seeded_rules: Library, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["demo-load", "--start", ANCHOR.isoformat()]) == 0
    out = capsys.readouterr().out
    assert "Demo environment (SIMULATED), anchored at 2026-09-25T18:00:00+00:00" in out
    assert "Multi-stage attack on the web server" in out
    assert "ACCT-001, AUTH-001, AUTH-002, PRIV-001" in out
    assert cli.main(["demo-status"]) == 0
    assert "0 real records" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["demo-load", "--start", "yesterday"], "--start must be an ISO 8601 time"),
        (["demo-load", "--start", "2026-09-25T18:00:00"], "must include a zone"),
        (["demo-load", "--start", "2999-01-01T00:00:00Z"], "must not be in the future"),
    ],
)
def test_cli_refuses_a_bad_start(
    cli_sessions: Session, argv: list[str], message: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(argv) == 1
    assert message in capsys.readouterr().err


def test_cli_refuses_a_bad_previous_head(
    cli_sessions: Session, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["demo-load", "--previous-audit-head", "12:short"]) == 2
    assert "SEQ:HASH" in capsys.readouterr().err


def test_demo_status_fails_when_real_records_exist(
    cli_sessions: Session, capsys: pytest.CaptureFixture[str]
) -> None:
    from tests.helpers import make_source

    source = make_source(cli_sessions)
    from app.ingestion.service import IngestRequest, ingest
    from app.models.event import BatchChannel

    ingest(
        cli_sessions,
        IngestRequest(source, [b"not a log line"], BatchChannel.API, None, detect=False),
        get_settings(),
    )
    assert cli.main(["demo-status"]) == 3
    out = capsys.readouterr().out
    assert "1 real records" in out and "not a demo environment" in out


@pytest.mark.parametrize(
    "anchor",
    [
        datetime(2026, 9, 26, 0, 0, tzinfo=UTC),  # midnight: the story crosses day boundaries
        datetime(2026, 10, 2, 12, 0, tzinfo=UTC),
        datetime(2026, 12, 31, 23, 0, tzinfo=UTC),  # the end of a year
    ],
)
def test_the_alerts_and_incidents_do_not_depend_on_the_anchor(
    db_session: Session, seeded_rules: Library, anchor: datetime
) -> None:
    report = load(db_session, anchor, get_settings())
    assert {r.step.title: r.rules for r in report.steps} == {
        r.step.title: set(r.step.expected_rules) for r in report.steps
    }
    assert (report.alerts_created, report.incidents_created) == (15, 5)
