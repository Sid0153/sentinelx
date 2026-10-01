"""The audit log's hash chain (Phase 13): new entries are linked by a database trigger, a
changed or removed entry is detected, log anchors catch a rewritten tail, and concurrent
writers still form one valid chain."""

import logging

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app import cli
from app.audit.chain import GENESIS, verify
from app.audit.events import AuditAction
from app.audit.service import record
from app.models.audit_log import AuditLog
from app.models.user import Role
from tests.concurrency import Factory, Worker, wait_until_blocked
from tests.helpers import bearer, make_user

pytestmark = pytest.mark.integration


def add_entries(db: Session, count: int) -> list[AuditLog]:
    entries = [
        record(db, AuditAction.SETTINGS_CHANGED, details={"n": i, "note": 'a|b,c"d'})
        for i in range(count)
    ]
    db.flush()  # several entries in one flush: the trigger links them in order
    return entries


def as_owner(db: Session, statement: str) -> None:
    """What only the database owner can do: change rows with the append-only trigger off."""
    db.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_no_update_delete"))
    db.execute(text(statement))
    db.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_no_update_delete"))


def test_new_entries_form_a_chain(db_session: Session) -> None:
    before = verify(db_session)
    entries = add_entries(db_session, 3)
    report = verify(db_session)
    assert report.intact and report.chained == before.chained + 3
    assert [e.seq for e in entries] == sorted(e.seq for e in entries)
    assert entries[1].prev_hash == entries[0].entry_hash
    assert entries[2].prev_hash == entries[1].entry_hash
    assert report.head_seq == entries[-1].seq and report.head_hash == entries[-1].entry_hash
    if before.chained == 0:
        assert entries[0].prev_hash == GENESIS


def test_a_writer_cannot_choose_the_hashes(db_session: Session) -> None:
    entry = record(db_session, AuditAction.SETTINGS_CHANGED)
    entry.prev_hash = "f" * 64
    entry.entry_hash = "e" * 64
    db_session.flush()
    stored = db_session.scalar(select(AuditLog.entry_hash).where(AuditLog.id == entry.id))
    assert stored != "e" * 64 and len(stored or "") == 64
    assert verify(db_session).intact


def test_a_changed_entry_breaks_the_chain(db_session: Session) -> None:
    entries = add_entries(db_session, 3)
    as_owner(
        db_session,
        f"UPDATE audit_logs SET details = '{{\"n\": 99}}' WHERE seq = {entries[1].seq}",
    )
    report = verify(db_session)
    assert not report.intact and report.first_broken == entries[1].seq


def test_a_removed_entry_breaks_the_chain(db_session: Session) -> None:
    entries = add_entries(db_session, 3)
    as_owner(db_session, f"DELETE FROM audit_logs WHERE seq = {entries[1].seq}")
    report = verify(db_session)
    assert report.first_broken == entries[2].seq  # it no longer points at its predecessor


def test_log_anchors_catch_a_removed_tail(db_session: Session) -> None:
    """Removing the newest entries leaves an internally consistent chain; the hashes already
    written to the application log still disagree."""
    entries = add_entries(db_session, 3)
    anchors = [(e.seq, e.entry_hash or "") for e in entries]
    assert verify(db_session, anchors).intact
    as_owner(db_session, f"DELETE FROM audit_logs WHERE seq = {entries[2].seq}")
    report = verify(db_session, anchors)
    assert report.first_broken is None  # the chain alone cannot tell
    assert report.anchor_problems == [f"entry {entries[2].seq} is missing"]
    as_owner(
        db_session,
        f"UPDATE audit_logs SET entry_hash = repeat('a', 64) WHERE seq = {entries[1].seq}",
    )
    assert (
        f"entry {entries[1].seq} has a different hash than logged"
        in verify(db_session, anchors).anchor_problems
    )


def test_entries_from_before_the_chain_are_reported_not_hidden(db_session: Session) -> None:
    before = verify(db_session)
    db_session.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_chain"))
    db_session.execute(
        text(
            "INSERT INTO audit_logs (id, seq, occurred_at, action, result, details) "
            "VALUES (gen_random_uuid(), nextval('audit_logs_seq'), now(), 'OLD', 'SUCCESS', '{}')"
        )
    )
    db_session.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_chain"))
    report = verify(db_session)
    assert report.legacy == before.legacy + 1 and report.intact


def test_anchors_are_logged_after_commit_only(
    db_session: Session, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="sentinelx.audit")
    entry = record(db_session, AuditAction.SETTINGS_CHANGED, details={"secret_ish": "x"})
    db_session.commit()
    [line] = [r for r in caplog.records if r.getMessage() == "audit.chained"]
    assert line.fields == {"seq": entry.seq, "hash": entry.entry_hash}  # type: ignore[attr-defined]
    caplog.clear()
    record(db_session, AuditAction.SETTINGS_CHANGED)
    db_session.flush()
    db_session.rollback()
    assert not [r for r in caplog.records if r.getMessage() == "audit.chained"]


def test_concurrent_writers_form_one_chain(scratch: Factory) -> None:
    """Two transactions write audit entries at once: the second waits for the chain lock and
    links to the first, whichever drew its number first."""
    first = scratch()
    record(first, AuditAction.SETTINGS_CHANGED, details={"who": "first"})
    first.flush()  # holds the chain lock until it commits

    def second_writer() -> None:
        with scratch() as db:
            record(db, AuditAction.SETTINGS_CHANGED, details={"who": "second"})
            db.commit()

    worker = Worker(second_writer)
    worker.start()
    wait_until_blocked(scratch)
    first.commit()
    first.close()
    worker.finish()
    with scratch() as db:
        report = verify(db)
        assert report.intact and report.chained >= 2


def test_admins_can_check_the_chain_through_the_api(
    db_client: TestClient, db_session: Session
) -> None:
    admin = bearer(make_user(db_session, Role.ADMIN, email="chain-admin@example.com"))
    entries = add_entries(db_session, 2)
    data = db_client.get("/api/audit/integrity", headers=admin).json()
    assert data["intact"] is True and data["first_broken_seq"] is None
    assert data["head_seq"] >= entries[-1].seq and len(data["head_hash"]) == 64
    as_owner(
        db_session,
        f"UPDATE audit_logs SET action = 'FORGED' WHERE seq = {entries[0].seq}",
    )
    data = db_client.get("/api/audit/integrity", headers=admin).json()
    assert data["intact"] is False and data["first_broken_seq"] == entries[0].seq


def test_cli_reports_the_chain_and_checks_anchors(
    cli_sessions: Session, capsys: pytest.CaptureFixture[str]
) -> None:
    entries = add_entries(cli_sessions, 2)
    good = f"{entries[1].seq}:{entries[1].entry_hash}"
    assert cli.main(["verify-audit", "--anchor", good]) == 0
    assert "Audit log intact" in capsys.readouterr().out
    assert cli.main(["verify-audit", "--anchor", f"{entries[1].seq}:{'b' * 64}"]) == 1
    assert "ANCHOR MISMATCH" in capsys.readouterr().out
    assert cli.main(["verify-audit", "--anchor", "nonsense"]) == 2
