"""The event store against a real PostgreSQL: round trip, duplicates, and evidence rules."""

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from app.events.schema import (
    Criticality,
    EventCategory,
    EventOutcome,
    IpScope,
    NormalizedEvent,
    SourceType,
)
from app.events.store import Enrichment, add_event, add_raw_event, find_raw_event, fingerprint
from app.models.context import Asset
from app.models.event import Event, LogSource, RawEvent
from tests.helpers import make_asset, make_source

pytestmark = pytest.mark.integration

LINE = (
    "Sep 25 10:31:02 web-01 sshd[4122]: Failed password for root from 203.0.113.45 port 50412 ssh2"
)


def ssh_failure() -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=datetime(2026, 9, 25, 10, 31, 2, tzinfo=UTC),
        source_type=SourceType.LINUX_AUTH,
        event_category=EventCategory.AUTHENTICATION,
        event_action="logon",
        event_outcome=EventOutcome.FAILURE,
        host="web-01",
        username="root",
        source_ip="203.0.113.45",
        source_port=50412,
        service="sshd",
        protocol="ssh",
        attributes={"method": "password"},
    )


def rejected(db: Session, statement: str, params: dict[str, object] | None = None) -> str:
    savepoint = db.begin_nested()
    with pytest.raises((IntegrityError, DBAPIError)) as caught:
        db.execute(text(statement), params or {})
    savepoint.rollback()
    return str(caught.value)


def test_fingerprint_depends_on_source_and_exact_text() -> None:
    a, b = uuid.uuid4(), uuid.uuid4()
    assert fingerprint(a, LINE) == fingerprint(a, LINE)
    assert fingerprint(a, LINE) != fingerprint(b, LINE)
    assert fingerprint(a, LINE) != fingerprint(a, LINE + " ")


def test_raw_and_normalized_round_trip_with_enrichment(db_session: Session) -> None:
    source = make_source(db_session)
    asset = make_asset(db_session, "web-01", Criticality.CRITICAL)
    raw = add_raw_event(db_session, source.id, LINE)
    event = add_event(
        db_session,
        raw,
        ssh_failure(),
        Enrichment(
            source_ip_scope=IpScope.EXTERNAL,
            asset_id=asset.id,
            asset_criticality=Criticality.CRITICAL,
        ),
    )
    db_session.commit()
    db_session.expire_all()

    stored = db_session.get(Event, event.id)
    assert stored is not None
    assert stored.raw_event_id == raw.id
    assert str(stored.source_ip) == "203.0.113.45"
    assert stored.timestamp == datetime(2026, 9, 25, 10, 31, 2, tzinfo=UTC)
    assert stored.attributes == {"method": "password"}
    assert (stored.source_ip_scope, stored.asset_criticality) == ("external", "critical")
    assert stored.ingested_at is not None
    stored_raw = db_session.get(RawEvent, raw.id)
    assert stored_raw is not None and stored_raw.raw_data == LINE.encode()  # byte for byte


@pytest.mark.parametrize(
    "record",
    [
        b"\x00garbage with a NUL byte",
        b"caf\xe9: latin-1 bytes, invalid as UTF-8",
        "unicode ☃ snowman".encode(),
    ],
    ids=["nul", "invalid-utf8", "utf8"],
)
def test_any_bytes_are_preserved_exactly(db_session: Session, record: bytes) -> None:
    # Malformed input is evidence too: it must be stored, not crash ingestion.
    source = make_source(db_session)
    raw = add_raw_event(db_session, source.id, record, parse_error="unrecognized_format")
    db_session.commit()
    db_session.expire_all()
    stored = db_session.get(RawEvent, raw.id)
    assert stored is not None
    assert stored.raw_data == record
    assert isinstance(stored.display_text, str)  # always showable, never matched on


def test_the_same_record_from_the_same_source_is_stored_once(db_session: Session) -> None:
    source = make_source(db_session)
    first = add_raw_event(db_session, source.id, LINE)
    assert find_raw_event(db_session, source.id, LINE) == first
    savepoint = db_session.begin_nested()
    with pytest.raises(IntegrityError, match="uq_raw_events_fingerprint"):
        add_raw_event(db_session, source.id, LINE)
    savepoint.rollback()


def test_the_same_text_from_another_source_is_a_separate_record(db_session: Session) -> None:
    one, two = make_source(db_session), make_source(db_session)
    add_raw_event(db_session, one.id, LINE)
    add_raw_event(db_session, two.id, LINE)
    count = db_session.scalar(text("SELECT count(*) FROM raw_events"))
    assert count == 2


def test_failed_records_are_kept_but_cannot_have_an_event(db_session: Session) -> None:
    source = make_source(db_session)
    raw = add_raw_event(db_session, source.id, b"\x00garbage", parse_error="unrecognized_format")
    assert raw.parse_status == "FAILED"
    with pytest.raises(ValueError, match="only a parsed raw record"):
        add_event(db_session, raw, ssh_failure())


def test_simulated_flag_travels_from_raw_to_event(db_session: Session) -> None:
    source = make_source(db_session)
    raw = add_raw_event(db_session, source.id, LINE, simulated=True)
    assert add_event(db_session, raw, ssh_failure()).simulated is True


# ---------- evidence is append-only ----------


@pytest.mark.parametrize("table", ["raw_events", "events"])
def test_evidence_tables_reject_update_delete_and_truncate(db_session: Session, table: str) -> None:
    source = make_source(db_session)
    add_event(db_session, add_raw_event(db_session, source.id, LINE), ssh_failure())
    column = "parse_error" if table == "raw_events" else "username"
    for statement in (
        f"UPDATE {table} SET {column} = 'tampered'",
        f"DELETE FROM {table}",
        f"TRUNCATE {table} CASCADE",
    ):
        assert "append-only" in rejected(db_session, statement)
    assert db_session.scalar(select(Event.username)) == "root"


# ---------- constraints ----------

INSERT_RAW = (
    "INSERT INTO raw_events (id, source_id, received_at, raw_data, fingerprint, parse_status, "
    "parse_error) VALUES (gen_random_uuid(), :source, now(), 'x'::bytea, :fp, :status, :error)"
)


def test_parse_status_and_error_must_agree(db_session: Session) -> None:
    source = make_source(db_session)
    for status, error in (("FAILED", None), ("PARSED", "unrecognized_format"), ("MAYBE", None)):
        message = rejected(
            db_session,
            INSERT_RAW,
            {"source": source.id, "fp": uuid.uuid4().hex, "status": status, "error": error},
        )
        assert "ck_raw_events_" in message


def test_raw_record_size_is_bounded(db_session: Session) -> None:
    source = make_source(db_session)
    message = rejected(
        db_session,
        "INSERT INTO raw_events (id, source_id, received_at, raw_data, fingerprint, "
        "parse_status) VALUES (gen_random_uuid(), :source, now(), "
        "convert_to(repeat('x', 65537), 'UTF8'), :fp, 'PARSED')",
        {"source": source.id, "fp": uuid.uuid4().hex},
    )
    assert "ck_raw_events_raw_data_size" in message


def test_raw_record_needs_a_known_source(db_session: Session) -> None:
    message = rejected(
        db_session,
        INSERT_RAW,
        {"source": uuid.uuid4(), "fp": uuid.uuid4().hex, "status": "PARSED", "error": None},
    )
    assert "fk_raw_events_source_id_log_sources" in message


@pytest.mark.parametrize(
    ("column", "value", "constraint"),
    [
        ("event_category", "'malware'", "ck_events_category_valid"),
        ("event_outcome", "'maybe'", "ck_events_outcome_valid"),
        ("event_action", "'Logon; DROP'", "ck_events_action_format"),
        ("source_port", "70000", "ck_events_source_port_range"),
        ("destination_port", "-1", "ck_events_destination_port_range"),
        ("host", "'WEB-01'", "ck_events_host_lowercase"),
        ("username", "'Root'", "ck_events_username_lowercase"),
        ("source_ip_scope", "'darknet'", "ck_events_ip_scope_valid"),
        ("asset_criticality", "'extreme'", "ck_events_criticality_valid"),
        ("command_line", "repeat('x', 8193)", "ck_events_command_line_size"),
    ],
)
def test_event_columns_are_constrained(
    db_session: Session, column: str, value: str, constraint: str
) -> None:
    source = make_source(db_session)
    raw = add_raw_event(db_session, source.id, f"line {uuid.uuid4()}")
    columns = {
        "event_category": "'authentication'",
        "event_action": "'logon'",
        "event_outcome": "'success'",
        column: value,
    }
    statement = (
        "INSERT INTO events (id, raw_event_id, source_id, source_type, timestamp, ingested_at, "  # noqa: S608
        f"{', '.join(columns)}) VALUES (gen_random_uuid(), :raw, :source, 'linux_auth', now(), "
        f"now(), {', '.join(columns.values())})"
    )
    assert constraint in rejected(db_session, statement, {"raw": raw.id, "source": source.id})


def test_one_normalized_event_per_raw_record(db_session: Session) -> None:
    source = make_source(db_session)
    raw = add_raw_event(db_session, source.id, LINE)
    add_event(db_session, raw, ssh_failure())
    savepoint = db_session.begin_nested()
    with pytest.raises(IntegrityError, match="uq_events_raw_event_id"):
        add_event(db_session, raw, ssh_failure())
    savepoint.rollback()


def test_an_asset_referenced_by_events_cannot_be_deleted(db_session: Session) -> None:
    source = make_source(db_session)
    asset = make_asset(db_session, "db-01", Criticality.HIGH)
    raw = add_raw_event(db_session, source.id, LINE)
    add_event(db_session, raw, ssh_failure(), Enrichment(asset_id=asset.id))
    message = rejected(db_session, "DELETE FROM assets WHERE id = :id", {"id": asset.id})
    assert "fk_events_asset_id_assets" in message
    assert db_session.get(Asset, asset.id) is not None


def test_log_source_type_is_constrained(db_session: Session) -> None:
    message = rejected(
        db_session,
        "INSERT INTO log_sources (id, name, source_type, timezone) "
        "VALUES (gen_random_uuid(), 'x', 'syslog-ng', 'UTC')",
    )
    assert "ck_log_sources_source_type_valid" in message
    assert db_session.scalar(select(LogSource).where(LogSource.name == "x")) is None
