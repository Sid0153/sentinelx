"""Alerts from detections against a real PostgreSQL: creation, deduplication, idempotence,
recurrence after closing, priority from the current inventory, the evidence cap, the
one-open-alert-per-key guarantee, and failure handling."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.alerts import service
from app.context import service as context
from app.core.config import get_settings
from app.demo.scenarios import generate
from app.detection.library import Library
from app.detection.service import run_manual
from app.ingestion.service import IngestRequest, ingest
from app.models.alert import Alert, AlertEvent, AlertStatus, Disposition
from app.models.context import Asset, Identity
from app.models.detection import DetectionRun
from app.models.event import BatchChannel, BatchStatus, IngestionBatch, LogSource
from app.models.user import Role, User
from app.schemas.context import AssetCreate, AssetUpdate, IdentityCreate, IdentityUpdate
from tests.helpers import audit_entries, make_asset, make_source, make_user

pytestmark = pytest.mark.integration

START = (datetime.now(UTC) - timedelta(hours=2)).replace(microsecond=0)
FAILED = "Failed password for root from 203.0.113.45 port {port} ssh2"


def send(
    db: Session,
    lines: list[str],
    source: LogSource | None = None,
    *,
    source_type: str = "linux_auth",
    simulated: bool = True,
) -> IngestionBatch:
    source = source or make_source(db, source_type)
    channel = BatchChannel.DEMO if simulated else BatchChannel.API
    request = IngestRequest(source, [line.encode() for line in lines], channel, None, simulated)
    return ingest(db, request, get_settings())


def failures(count: int, start: datetime, every: int = 3) -> list[str]:
    return [
        f"{(start + timedelta(seconds=i * every)).isoformat()} web-01 sshd[{4000 + i}]: "
        + FAILED.format(port=50000 + i)
        for i in range(count)
    ]


def alerts(db: Session, **where: Any) -> list[Alert]:
    statement = select(Alert).order_by(Alert.created_at)
    for name, value in where.items():
        statement = statement.where(getattr(Alert, name) == value)
    return list(db.scalars(statement))


def linked(db: Session, alert: Alert) -> int:
    return db.scalar(select(func.count()).where(AlertEvent.alert_id == alert.id)) or 0


@pytest.fixture
def analyst(db_session: Session) -> User:
    return make_user(db_session, Role.ANALYST, email="analyst@example.com")


def close(db: Session, alert: Alert, analyst: User) -> None:
    now = datetime.now(UTC)
    service.transition(db, alert.id, AlertStatus.TRIAGED, None, None, analyst, now)
    service.transition(
        db, alert.id, AlertStatus.RESOLVED, Disposition.CONFIRMED_MALICIOUS, None, analyst, now
    )


# ---------- creation ----------


def test_a_detection_becomes_an_alert_with_its_evidence(
    db_session: Session, seeded_rules: Library
) -> None:
    batch = send(db_session, generate("brute_force", START, count=12))
    assert (batch.detection_count, batch.alerts_created, batch.alerts_updated) == (1, 1, 0)
    (alert,) = alerts(db_session)
    assert alert.rule_id == "AUTH-001" and alert.status == AlertStatus.NEW
    assert alert.title == "Repeated SSH authentication failures (203.0.113.45, web-01, root)"
    assert (alert.host, alert.username, str(alert.source_ip)) == ("web-01", "root", "203.0.113.45")
    assert alert.event_count == linked(db_session, alert) == 12
    assert not alert.evidence_truncated and alert.simulated
    assert alert.explanation.startswith('12 failed SSH logons for "root" on web-01')
    assert alert.mitre[0]["technique"] == "T1110.001"
    assert alert.mitre[0]["tactics"] == ["Credential Access"]
    assert alert.first_event_at < alert.last_event_at
    # Nothing in the inventory: severity medium 25 + confidence medium 8 + unknown asset 5
    # + evidence 12 ≥ 2 × 5 → 5 = 43.
    assert [(f["factor"], f["points"]) for f in alert.priority_breakdown] == [
        ("severity", 25),
        ("confidence", 8),
        ("asset", 5),
        ("evidence", 5),
    ]
    assert (alert.priority_score, alert.priority_band) == (43, "medium")
    run = db_session.scalar(select(DetectionRun).where(DetectionRun.batch_id == batch.id))
    assert run is not None and run.alerts_created == 1
    assert run.detections[0]["alert_id"] == str(alert.id)
    assert run.detections[0]["alert"] == "created"


def test_priority_uses_the_current_inventory(db_session: Session, seeded_rules: Library) -> None:
    make_asset(db_session, "web-01", criticality="critical")
    db_session.add(Identity(username="root", privilege_level="privileged"))
    db_session.flush()
    send(db_session, generate("brute_force", START, count=12))
    (alert,) = alerts(db_session)
    assert alert.asset_id is not None and alert.identity_id is not None
    assert {f["factor"]: f["value"] for f in alert.priority_breakdown} == {
        "severity": "medium",
        "confidence": "medium",
        "asset": "web-01 critical",
        "identity": "root privileged",
        "evidence": "12 (≥ 2× threshold 5)",
    }
    assert (alert.priority_score, alert.priority_band) == (63, "high")


def test_findings_that_are_different_activity_become_different_alerts(
    db_session: Session, seeded_rules: Library
) -> None:
    send(db_session, generate("privilege_escalation", START))
    found = alerts(db_session, rule_id="PRIV-001")
    assert sorted((a.indicator, a.username) for a in found) == [
        ("not_in_sudoers", "carol"),
        ("root_shell", "deploy"),
    ]


def test_alerts_from_real_data_are_not_marked_simulated(
    db_session: Session, seeded_rules: Library
) -> None:
    send(db_session, failures(6, START), simulated=False)
    (alert,) = alerts(db_session)
    assert not alert.simulated


# ---------- deduplication and idempotence ----------


def test_continuing_activity_extends_the_open_alert(
    db_session: Session, seeded_rules: Library
) -> None:
    source = make_source(db_session)
    send(db_session, failures(6, START), source)
    second = send(db_session, failures(6, START + timedelta(minutes=1)), source)
    assert (second.alerts_created, second.alerts_updated) == (0, 1)
    (alert,) = alerts(db_session)
    assert alert.event_count == linked(db_session, alert) == 12
    assert alert.detection_count == 2 and len(alert.history) == 2
    assert alert.history[1]["new_evidence"] == 6
    assert alert.last_event_at == START + timedelta(minutes=1, seconds=15)
    assert alert.explanation.startswith("12 failed SSH logons")  # the latest detection


def test_rerunning_detection_changes_nothing(
    db_session: Session, seeded_rules: Library, analyst: User
) -> None:
    for name in ("brute_force_success", "password_spray", "privileged_account_creation"):
        send(db_session, generate(name, START))
    before = [(a.id, a.event_count, a.detection_count, a.updated_at) for a in alerts(db_session)]
    run = run_manual(db_session, START - timedelta(hours=1), START + timedelta(hours=1), analyst)
    assert run.detection_count == 4 and (run.alerts_created, run.alerts_updated) == (0, 0)
    assert {d["alert"] for d in run.detections} == {"unchanged"}
    after = [(a.id, a.event_count, a.detection_count, a.updated_at) for a in alerts(db_session)]
    assert after == before


def test_a_closed_alert_is_neither_reopened_nor_recreated_by_a_rerun(
    db_session: Session, seeded_rules: Library, analyst: User
) -> None:
    send(db_session, generate("brute_force", START))
    (alert,) = alerts(db_session)
    close(db_session, alert, analyst)
    run = run_manual(db_session, START - timedelta(hours=1), START + timedelta(hours=1), analyst)
    assert (run.alerts_created, run.alerts_updated) == (0, 0)
    assert [a.status for a in alerts(db_session)] == [AlertStatus.RESOLVED]


def test_new_activity_after_closing_opens_a_new_alert_linked_to_the_old_one(
    db_session: Session, seeded_rules: Library, analyst: User
) -> None:
    source = make_source(db_session)
    send(db_session, failures(6, START), source)
    (old,) = alerts(db_session)
    close(db_session, old, analyst)
    send(db_session, failures(6, START + timedelta(minutes=2)), source)
    old_now, new = alerts(db_session)
    assert old_now.id == old.id and old_now.status == AlertStatus.RESOLVED
    assert new.status == AlertStatus.NEW and new.previous_alert_id == old.id
    # The new alert holds the new events only; the old ones stay with the closed alert.
    assert new.event_count == 6 and new.first_event_at == START + timedelta(minutes=2)


def test_only_one_open_alert_per_key_is_a_database_guarantee(
    db_session: Session, seeded_rules: Library
) -> None:
    send(db_session, generate("brute_force", START))
    (alert,) = alerts(db_session)
    columns = {c.name: getattr(alert, c.key) for c in Alert.__table__.columns if c.name != "id"}
    with (
        pytest.raises(IntegrityError, match="uq_alerts_dedup_key_active"),
        db_session.begin_nested(),
    ):
        db_session.add(Alert(**columns))
        db_session.flush()
    # Once the first is closed, another open alert with the key is allowed.
    db_session.execute(
        update(Alert)
        .where(Alert.id == alert.id)
        .values(status="FALSE_POSITIVE", status_note="test")
    )
    db_session.add(Alert(**columns))
    db_session.flush()


def test_evidence_beyond_the_cap_is_counted_as_missing(
    db_session: Session, seeded_rules: Library, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service, "MAX_EVIDENCE_PER_ALERT", 5)
    send(db_session, generate("brute_force", START, count=12))
    (alert,) = alerts(db_session)
    assert alert.event_count == linked(db_session, alert) == 5
    assert alert.evidence_truncated


# ---------- failures ----------


def test_if_alerting_fails_the_run_fails_and_the_records_stay(
    db_session: Session, seeded_rules: Library, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("simulated alerting bug")

    monkeypatch.setattr(service, "apply", broken)
    batch = send(db_session, generate("brute_force", START))
    assert batch.status == BatchStatus.DETECTION_FAILED
    assert batch.parsed_count == 12
    assert alerts(db_session) == [] and db_session.scalar(select(DetectionRun)) is None


# ---------- priority follows the inventory ----------


def score(db: Session) -> tuple[int, list[tuple[str, str, int]]]:
    (alert,) = alerts(db)
    db.refresh(alert)
    return alert.priority_score, [
        (f["factor"], f["value"], f["points"]) for f in alert.priority_breakdown
    ]


def new_asset(db: Session, admin: User, hostname: str, criticality: str) -> Asset:
    return context.create_asset(
        db,
        AssetCreate.model_validate(
            {
                "hostname": hostname,
                "asset_type": "server",
                "environment": "production",
                "criticality": criticality,
            }
        ),
        admin,
    )


@pytest.fixture
def admin(db_session: Session) -> User:
    return make_user(db_session, Role.ADMIN, email="inventory-admin@example.com")


def test_raising_an_assets_criticality_reprioritizes_its_open_alerts(
    db_session: Session, seeded_rules: Library, admin: User
) -> None:
    asset = new_asset(db_session, admin, "web-01", "medium")
    send(db_session, generate("brute_force", START))
    assert score(db_session)[0] == 43  # 25 + 8 + asset medium 5 + evidence 5
    context.update_asset(
        db_session, asset.id, AssetUpdate.model_validate({"criticality": "critical"}), admin
    )
    points, breakdown = score(db_session)
    assert points == 53 and ("asset", "web-01 critical", 15) in breakdown
    (entry,) = audit_entries(db_session, "ASSET_UPDATED")
    assert entry.details["open_alerts_reprioritized"] == 1


def test_an_asset_added_after_the_events_still_counts(
    db_session: Session, seeded_rules: Library, admin: User
) -> None:
    """Events never change, so their (empty) enrichment stays; the alert looks the host up
    in the current inventory instead."""
    send(db_session, generate("brute_force", START))
    assert ("asset", "not in inventory", 5) in score(db_session)[1]
    asset = new_asset(db_session, admin, "web-01.corp.example", "critical")  # short name match
    points, breakdown = score(db_session)
    assert points == 53 and ("asset", "web-01.corp.example critical", 15) in breakdown
    (alert,) = alerts(db_session)
    assert alert.asset_id == asset.id


def test_an_identity_becoming_privileged_raises_the_priority(
    db_session: Session, seeded_rules: Library, admin: User
) -> None:
    identity = context.create_identity(
        db_session,
        IdentityCreate.model_validate({"username": "root", "privilege_level": "standard"}),
        admin,
    )
    send(db_session, generate("brute_force", START))
    before = score(db_session)[0]
    context.update_identity(
        db_session,
        identity.id,
        IdentityUpdate.model_validate({"privilege_level": "privileged"}),
        admin,
    )
    points, breakdown = score(db_session)
    assert points == before + 10 and ("identity", "root privileged", 10) in breakdown


def test_closed_alerts_and_unrelated_changes_are_left_alone(
    db_session: Session, seeded_rules: Library, admin: User, analyst: User
) -> None:
    asset = new_asset(db_session, admin, "web-01", "low")
    send(db_session, generate("brute_force", START))
    new_asset(db_session, admin, "db-07", "critical")  # another host
    assert audit_entries(db_session, "ASSET_CREATED")[1].details["open_alerts_reprioritized"] == 0
    (alert,) = alerts(db_session)
    close(db_session, alert, analyst)
    before = score(db_session)
    context.update_asset(
        db_session, asset.id, AssetUpdate.model_validate({"criticality": "critical"}), admin
    )
    assert score(db_session) == before  # scored as it was when it was handled
    (entry,) = audit_entries(db_session, "ASSET_UPDATED")
    assert entry.details["open_alerts_reprioritized"] == 0


def test_a_change_that_does_not_affect_priority_does_not_recompute(
    db_session: Session, seeded_rules: Library, admin: User
) -> None:
    asset = new_asset(db_session, admin, "web-01", "high")
    send(db_session, generate("brute_force", START))
    context.update_asset(
        db_session, asset.id, AssetUpdate.model_validate({"owner": "platform team"}), admin
    )
    (entry,) = audit_entries(db_session, "ASSET_UPDATED")
    assert entry.details["open_alerts_reprioritized"] == 0
