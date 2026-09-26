"""The detection engine against a real PostgreSQL: rule storage (seeding, library updates,
admin tuning, versions), runs after ingest batches and manual runs, error isolation, and the
SQL prefilter agreeing with the Python evaluation."""

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app import cli
from app.core.config import get_settings
from app.core.errors import AppError
from app.demo.scenarios import SCENARIOS, generate
from app.detection import engine
from app.detection.evaluate import evaluate
from app.detection.library import Library, fingerprint
from app.detection.service import run_manual
from app.detection.storage import RuleChanges, effective, enabled_rules, seed, update_rule
from app.ingestion.service import IngestRequest, ingest
from app.models.detection import (
    DetectionRule,
    DetectionRuleTechnique,
    DetectionRuleVersion,
    DetectionRun,
    MitreTechnique,
    RunStatus,
    RunTrigger,
)
from app.models.event import (
    BatchChannel,
    BatchStatus,
    Event,
    IngestionBatch,
    LogSource,
    RawEvent,
)
from app.models.user import Role, User
from tests.helpers import audit_entries, make_source, make_user

pytestmark = pytest.mark.integration

START = (datetime.now(UTC) - timedelta(hours=2)).replace(microsecond=0)


def send(
    db: Session,
    lines: list[str],
    source_type: str = "linux_auth",
    *,
    detect: bool = True,
    source: LogSource | None = None,
) -> IngestionBatch:
    source = source or make_source(db, source_type)
    request = IngestRequest(
        source, [line.encode() for line in lines], BatchChannel.DEMO, None, True, detect
    )
    return ingest(db, request, get_settings())


def batch_run(db: Session, batch: IngestionBatch) -> DetectionRun:
    detection_run = db.scalar(select(DetectionRun).where(DetectionRun.batch_id == batch.id))
    assert detection_run is not None
    return detection_run


def rule_ids(detection_run: DetectionRun) -> set[str]:
    return {d["rule_id"] for d in detection_run.detections}


def signature(detection_run: DetectionRun) -> list[tuple[Any, ...]]:
    """What a detection is, independent of when it was computed."""
    return sorted(
        (d["rule_id"], sorted(d["group"].items()), tuple(d["evidence_event_ids"]))
        for d in detection_run.detections
    )


@pytest.fixture
def admin(db_session: Session) -> User:
    return make_user(db_session, Role.ADMIN, email="rules-admin@example.com")


def changed(library: Library, rule_id: str, **fields: Any) -> Library:
    """A copy of the library where one rule's definition changed (the shipped one is cached)."""
    rule = library.rules[rule_id].model_copy(update=fields)
    return dataclasses.replace(
        library,
        rules={**library.rules, rule_id: rule},
        hashes={**library.hashes, rule_id: fingerprint(rule)},
    )


# ---------- storage: seeding ----------


def test_seeding_loads_every_rule_once(db_session: Session, seeded_rules: Library) -> None:
    rows = list(db_session.scalars(select(DetectionRule)))
    assert {r.rule_id for r in rows} == set(seeded_rules.rules)
    assert all(r.version == 1 and r.in_library and r.overrides == {} for r in rows)
    assert len(audit_entries(db_session, "RULE_ADDED")) == len(seeded_rules.rules)
    versions = list(db_session.scalars(select(DetectionRuleVersion)))
    assert len(versions) == len(seeded_rules.rules)
    # Techniques: the reference list, and every mapping in the rules (per indicator too).
    assert db_session.get(MitreTechnique, "T1110.001") is not None
    proc = db_session.scalars(
        select(DetectionRuleTechnique).where(DetectionRuleTechnique.rule_id == "PROC-001")
    ).all()
    assert {m.indicator for m in proc} >= {"encoded_powershell", "download_pipe_shell"}

    # Idempotent: seeding the same library again changes nothing.
    assert seed(db_session, seeded_rules) == []
    assert len(list(db_session.scalars(select(DetectionRuleVersion)))) == len(versions)


def test_a_library_change_creates_a_version_and_keeps_valid_tuning(
    db_session: Session, seeded_rules: Library, admin: User
) -> None:
    update_rule(db_session, "AUTH-001", RuleChanges(threshold=8, reason="noisy jump host"), admin)
    library = changed(seeded_rules, "AUTH-001", description="A clearer description.")
    assert seed(db_session, library) == ["AUTH-001: library update to version 3"]
    row = db_session.get(DetectionRule, "AUTH-001")
    assert row is not None and row.version == 3
    assert effective(row).threshold == 8  # the admin's value survives
    assert effective(row).description == "A clearer description."
    (entry,) = audit_entries(db_session, "RULE_LIBRARY_UPDATED")
    assert entry.details == {"version": 3, "dropped_overrides": []}


def test_tuning_that_no_longer_fits_the_library_is_dropped_and_audited(
    db_session: Session, seeded_rules: Library, admin: User
) -> None:
    update_rule(db_session, "AUTH-001", RuleChanges(threshold=15, reason="noisy jump host"), admin)
    rule = seeded_rules.rules["AUTH-001"]
    assert rule.tunable.threshold is not None
    tighter = rule.tunable.model_copy(
        update={"threshold": rule.tunable.threshold.model_copy(update={"max": 10})}
    )
    library = changed(seeded_rules, "AUTH-001", tunable=tighter)
    seed(db_session, library)
    row = db_session.get(DetectionRule, "AUTH-001")
    assert row is not None and row.overrides == {}
    assert effective(row).threshold == rule.threshold
    (entry,) = audit_entries(db_session, "RULE_LIBRARY_UPDATED")
    assert entry.details["dropped_overrides"] == ["threshold"]


def test_a_rule_removed_from_the_library_is_retired_not_deleted(
    db_session: Session, seeded_rules: Library, admin: User
) -> None:
    rules = {k: v for k, v in seeded_rules.rules.items() if k != "NET-001"}
    library = dataclasses.replace(seeded_rules, rules=rules)
    assert seed(db_session, library) == ["NET-001: retired (no longer in the library)"]
    row = db_session.get(DetectionRule, "NET-001")
    assert row is not None and not row.in_library and not row.enabled
    assert len(audit_entries(db_session, "RULE_RETIRED")) == 1
    assert "NET-001" not in {rule.id for rule, _ in enabled_rules(db_session)}
    with pytest.raises(AppError) as error:
        update_rule(db_session, "NET-001", RuleChanges(enabled=True, reason="bring it back"), admin)
    assert error.value.status_code == 409
    # Shipping it again brings it back (enabled as the library says), with a new version.
    seed(db_session, seeded_rules)
    assert row.in_library and row.enabled and row.version == 2


# ---------- storage: admin tuning ----------


def test_tuning_creates_a_version_and_an_audit_entry(
    db_session: Session, seeded_rules: Library, admin: User
) -> None:
    row = update_rule(
        db_session,
        "AUTH-001",
        RuleChanges.model_validate(
            {
                "threshold": 8,
                "time_window": "10m",
                "severity": "high",
                "reason": "tuning after review",
            }
        ),
        admin,
    )
    assert row.version == 2
    rule = effective(row)
    assert (rule.threshold, rule.time_window, rule.severity) == (8, timedelta(minutes=10), "high")
    (entry,) = audit_entries(db_session, "RULE_UPDATED")
    assert entry.actor_id == admin.id and entry.entity_id == "AUTH-001"
    assert entry.details["reason"] == "tuning after review"
    assert entry.details["changes"]["threshold"] == {"from": 5, "to": 8}
    version = db_session.scalar(
        select(DetectionRuleVersion).where(
            DetectionRuleVersion.rule_id == "AUTH-001", DetectionRuleVersion.version == 2
        )
    )
    assert version is not None and version.source == "admin" and version.changed_by == admin.id
    assert version.definition["threshold"] == 8

    # Sending the current values again is not a change: no version, no audit entry.
    update_rule(db_session, "AUTH-001", RuleChanges(threshold=8, reason="same again"), admin)
    assert row.version == 2 and len(audit_entries(db_session, "RULE_UPDATED")) == 1


@pytest.mark.parametrize(
    ("rule_id", "changes", "message"),
    [
        ("PRIV-001", {"threshold": 3}, "threshold is not tunable for PRIV-001"),
        ("AUTH-001", {"threshold": 1001}, "threshold must be between"),
        ("AUTH-001", {"time_window": "30d"}, "time_window is outside the bounds"),
        ("AUTH-001", {}, "Send at least one field"),
        ("NOPE-001", {"enabled": False}, "Detection rule not found"),
    ],
)
def test_tuning_is_limited_to_what_the_rule_allows(
    db_session: Session,
    seeded_rules: Library,
    admin: User,
    rule_id: str,
    changes: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(AppError) as error:
        update_rule(db_session, rule_id, RuleChanges(**changes, reason="trying it"), admin)
    assert message in error.value.message
    assert audit_entries(db_session, "RULE_UPDATED") == []


def test_disabling_a_rule_stops_it_running(
    db_session: Session, seeded_rules: Library, admin: User
) -> None:
    update_rule(db_session, "AUTH-001", RuleChanges(enabled=False, reason="maintenance"), admin)
    batch = send(db_session, generate("brute_force", START))
    assert "AUTH-001" not in batch_run(db_session, batch).rule_results
    assert batch.detection_count == 0


def test_rule_versions_are_append_only(db_session: Session, seeded_rules: Library) -> None:
    for statement in (
        "UPDATE detection_rule_versions SET change_reason = 'rewritten'",
        "DELETE FROM detection_rule_versions",
        "TRUNCATE detection_rule_versions CASCADE",
    ):
        with pytest.raises(DBAPIError, match="append-only"), db_session.begin_nested():
            db_session.execute(text(statement))


# ---------- runs after ingest batches ----------


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_each_scenario_triggers_exactly_its_rules(
    db_session: Session, seeded_rules: Library, name: str
) -> None:
    scenario = SCENARIOS[name]
    batch = send(db_session, generate(name, START), scenario.source_type)
    detection_run = batch_run(db_session, batch)
    assert batch.status == BatchStatus.PROCESSED
    assert detection_run.trigger == RunTrigger.BATCH
    assert detection_run.status == RunStatus.COMPLETED
    assert rule_ids(detection_run) == set(scenario.expected_rules)
    assert batch.detection_count == detection_run.detection_count
    assert set(detection_run.rule_results) == set(seeded_rules.rules)
    for detection in detection_run.detections:
        assert detection["explanation"] and "$" not in detection["explanation"]
        assert detection["batch_ids"] == [str(batch.id)]


def test_a_detection_points_at_stored_evidence(db_session: Session, seeded_rules: Library) -> None:
    batch = send(db_session, generate("brute_force", START, count=12))
    (detection,) = batch_run(db_session, batch).detections
    assert detection["rule_id"] == "AUTH-001" and detection["event_count"] == 12
    evidence = db_session.scalars(
        select(Event).where(Event.id.in_(detection["evidence_event_ids"]))
    ).all()
    assert len(evidence) == 12
    assert {e.event_outcome for e in evidence} == {"failure"}
    assert detection["group"] == {"source_ip": "203.0.113.45", "host": "web-01", "username": "root"}
    assert detection["mitre"][0]["technique"] == "T1110.001"
    row = db_session.get(DetectionRule, "AUTH-001")
    assert row is not None and row.match_count == 1 and row.last_match_at is not None


def test_activity_split_across_batches_is_still_correlated(
    db_session: Session, seeded_rules: Library
) -> None:
    """Failures in one batch, the successful logon in the next: the sequence rule sees both,
    because each run re-reads the window from the database (no in-memory state)."""
    lines = generate("brute_force_success", START, count=6)
    success = next(i for i, line in enumerate(lines) if "Accepted" in line)
    first = send(db_session, lines[:success])
    assert "AUTH-002" not in rule_ids(batch_run(db_session, first))
    second = send(db_session, lines[success:])
    (sequence,) = [
        d for d in batch_run(db_session, second).detections if d["rule_id"] == "AUTH-002"
    ]
    assert set(sequence["batch_ids"]) == {str(first.id), str(second.id)}


def test_a_batch_run_keeps_only_detections_involving_its_events(
    db_session: Session, seeded_rules: Library
) -> None:
    attack = send(db_session, generate("brute_force", START))
    assert attack.detection_count == 1
    # Unrelated activity in the same time range: the brute force is in its window, but it was
    # already reported with the first batch.
    later = send(db_session, generate("privilege_escalation", START + timedelta(seconds=5)))
    assert rule_ids(batch_run(db_session, later)) == {"PRIV-001"}


def test_a_batch_without_new_events_is_processed_without_a_run(
    db_session: Session, seeded_rules: Library
) -> None:
    lines = generate("brute_force", START)
    source = make_source(db_session)
    send(db_session, lines, source=source)
    repeat = send(db_session, lines, source=source)  # all duplicates of what is stored
    assert repeat.duplicate_count == len(lines) and repeat.first_event_at is None
    assert db_session.scalar(select(DetectionRun).where(DetectionRun.batch_id == repeat.id)) is None
    assert repeat.status == BatchStatus.PROCESSED and repeat.detection_count == 0


def test_manual_runs_repeat_the_same_result(
    db_session: Session, seeded_rules: Library, admin: User
) -> None:
    for name in ("brute_force_success", "password_spray", "privileged_account_creation"):
        send(db_session, generate(name, START))
    end = START + timedelta(hours=1)
    first = run_manual(db_session, START - timedelta(hours=1), end, admin)
    second = run_manual(db_session, START - timedelta(hours=1), end, admin)
    assert first.trigger == RunTrigger.MANUAL and first.requested_by == admin.id
    assert rule_ids(first) == {"AUTH-001", "AUTH-002", "AUTH-003", "ACCT-001"}
    assert signature(first) == signature(second)
    (entry, _) = audit_entries(db_session, "DETECTION_RUN_REQUESTED")
    assert entry.actor_id == admin.id and set(entry.details) == {"from", "to"}


@pytest.mark.parametrize(
    ("start", "end", "message"),
    [
        (START, START, "'from' must be before 'to'"),
        (START, START - timedelta(minutes=1), "'from' must be before 'to'"),
        (START, START + timedelta(days=32), "at most 31 days"),
        (START.replace(tzinfo=None), START + timedelta(hours=1), "time zone"),
    ],
)
def test_manual_run_ranges_are_checked(
    db_session: Session,
    seeded_rules: Library,
    admin: User,
    start: datetime,
    end: datetime,
    message: str,
) -> None:
    with pytest.raises(AppError) as error:
        run_manual(db_session, start, end, admin)
    assert error.value.status_code == 400 and message in error.value.message
    assert audit_entries(db_session, "DETECTION_RUN_REQUESTED") == []
    assert db_session.scalar(select(DetectionRun)) is None


# ---------- failures ----------


def test_a_rule_with_too_many_candidates_is_reported_not_truncated(
    db_session: Session, seeded_rules: Library, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(engine, "MAX_CANDIDATES", 5)
    batch = send(db_session, generate("brute_force", START, count=12))
    detection_run = batch_run(db_session, batch)
    assert detection_run.rule_results["AUTH-001"]["error"] == "too_many_candidates"
    assert detection_run.rule_results["PRIV-001"]["error"] is None  # the others still ran
    assert detection_run.status == RunStatus.COMPLETED_WITH_ERRORS
    assert batch.status == BatchStatus.PROCESSED_WITH_ERRORS
    row = db_session.get(DetectionRule, "AUTH-001")
    assert row is not None and row.error_count == 1 and row.match_count == 0


def test_a_failing_rule_does_not_stop_the_others(
    db_session: Session, seeded_rules: Library, monkeypatch: pytest.MonkeyPatch
) -> None:

    def broken_for_auth_001(rule: Any, events: Any, history: Any = None) -> Any:
        if rule.id == "AUTH-001":
            raise RuntimeError("simulated bug")
        return evaluate(rule, events, history)

    monkeypatch.setattr("app.detection.engine.evaluate", broken_for_auth_001)
    batch = send(db_session, generate("brute_force_success", START))
    detection_run = batch_run(db_session, batch)
    assert detection_run.rule_results["AUTH-001"]["error"] == "evaluation_error"
    assert rule_ids(detection_run) == {"AUTH-002"}
    assert batch.status == BatchStatus.PROCESSED_WITH_ERRORS


def test_a_failed_run_keeps_the_records_and_marks_the_batch(
    db_session: Session, seeded_rules: Library, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_run(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("simulated database outage")

    monkeypatch.setattr(engine, "run", failing_run)
    batch = send(db_session, generate("brute_force", START))
    assert batch.status == BatchStatus.DETECTION_FAILED
    stored = db_session.scalars(select(RawEvent).where(RawEvent.batch_id == batch.id)).all()
    assert len(stored) == batch.received_count
    assert db_session.scalar(select(DetectionRun)) is None


# ---------- AUTH-004 needs history from the database ----------


def accepted(moment: datetime, ip: str, user: str = "alice") -> str:
    return (
        f"{moment.isoformat()} web-01 sshd[4122]: "
        f"Accepted publickey for {user} from {ip} port 52000 ssh2"
    )


def test_logon_from_a_new_network_uses_stored_history(
    db_session: Session, seeded_rules: Library
) -> None:
    history = [accepted(START - timedelta(days=d), "10.0.2.41") for d in range(1, 7)]
    send(db_session, history, detect=False)

    familiar = send(db_session, [accepted(START, "10.0.2.99")])
    assert batch_run(db_session, familiar).detections == []

    unusual = send(db_session, [accepted(START + timedelta(minutes=5), "203.0.113.200")])
    (detection,) = batch_run(db_session, unusual).detections
    assert detection["rule_id"] == "AUTH-004"
    assert detection["facts"]["value"] == "203.0.113.0/24"
    assert detection["facts"]["history_count"] == 7  # six days plus the familiar logon


def test_accounts_without_stored_history_are_not_judged(
    db_session: Session, seeded_rules: Library
) -> None:
    batch = send(db_session, [accepted(START, "203.0.113.200", user="newcomer")])
    assert batch_run(db_session, batch).detections == []


# ---------- the SQL prefilter never drops what the rule would match ----------


def test_the_sql_prefilter_contains_every_python_match(
    db_session: Session, seeded_rules: Library
) -> None:
    for name, scenario in SCENARIOS.items():
        send(db_session, generate(name, START), scenario.source_type, detect=False)
    rows = db_session.execute(
        select(Event, RawEvent.batch_id).join(RawEvent, RawEvent.id == Event.raw_event_id)
    ).all()
    events = [engine._to_event(event, batch_id) for event, batch_id in rows]
    assert len(events) > 50

    for rule in seeded_rules.rules.values():
        conditions = (
            [step.match for step in rule.steps or []] if rule.kind == "sequence" else [rule.match]
        )
        python = {
            e.id
            for e in events
            if any(c is None or c.evaluate(e) for c in conditions)
            and (not rule.indicators or any(i.match.evaluate(e) for i in rule.indicators))
        }
        sql = {
            str(event_id)
            for event_id in db_session.scalars(select(Event.id).where(engine._prefilter(rule)))
        }
        assert python, f"{rule.id}: the scenarios should exercise every rule"
        assert python <= sql, f"{rule.id}: the prefilter dropped {python - sql}"


@pytest.mark.parametrize("rule_id", ["AUTH-001", "AUTH-003", "PRIV-001", "NET-001"])
def test_the_prefilter_compares_indexed_columns_directly(
    db_session: Session, seeded_rules: Library, rule_id: str
) -> None:
    """Wrapping an indexed column in translate() would hide it from its index. The prefilter
    must compare event_category and event_action directly: the query shape that
    test_schema.py proves fits ix_events_category_action_ts. (Which index the planner picks
    on an empty table says nothing, so the shape is checked, not the plan.)"""
    rule = seeded_rules.rules[rule_id]
    sql = str(
        select(Event.id)
        .where(engine._prefilter(rule))
        .compile(dialect=db_session.get_bind().dialect, compile_kwargs={"literal_binds": True})
    )
    assert "events.event_category = '" in sql, sql
    assert "events.event_action = '" in sql or "events.event_action IN (" in sql, sql
    assert "translate(events.event_" not in sql, sql


def test_batches_a_crash_left_without_detection_are_flagged(
    db_session: Session, cli_sessions: Session, capsys: pytest.CaptureFixture[str]
) -> None:
    source = make_source(db_session)
    old, recent, done = (
        IngestionBatch(
            source_id=source.id,
            channel=BatchChannel.API,
            status=status,
            received_count=0,
            created_at=datetime.now(UTC) - age,
        )
        for status, age in (
            (BatchStatus.STORED, timedelta(hours=1)),  # the crash
            (BatchStatus.STORED, timedelta(seconds=10)),  # possibly still being processed
            (BatchStatus.PROCESSED, timedelta(hours=1)),
        )
    )
    db_session.add_all([old, recent, done])
    db_session.commit()
    assert cli.main(["reconcile-batches"]) == 0
    assert "1 batches" in capsys.readouterr().out
    for batch in (old, recent, done):
        db_session.refresh(batch)
    assert (old.status, recent.status, done.status) == (
        BatchStatus.DETECTION_FAILED,
        BatchStatus.STORED,
        BatchStatus.PROCESSED,
    )
