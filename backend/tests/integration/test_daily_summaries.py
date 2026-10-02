"""Per-day summaries kept by database triggers (migration 0014, Phase 14): they always equal
the stored rows, whichever code path inserts them, and concurrent batches neither deadlock
nor lose counts."""

import functools
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.events.schema import EventCategory, EventOutcome, NormalizedEvent, SourceType
from app.ingestion.service import IngestRequest, ingest
from app.models.event import BatchChannel, LogSource
from tests.concurrency import Factory, Worker
from tests.helpers import make_source, stored_event, stored_raw

pytestmark = pytest.mark.integration

DAY = datetime(2026, 9, 20, 23, 50, tzinfo=UTC)  # ten minutes before midnight UTC


def line(moment: datetime, user: str, ip: str, outcome: str = "Accepted publickey") -> str:
    verb = "Failed password" if outcome == "failed" else outcome
    return f"{moment.isoformat()} web-01 sshd[1]: {verb} for {user} from {ip} port 52000 ssh2"


def send(db: Session, lines: list[str], source: LogSource | None = None) -> None:
    request = IngestRequest(
        source or make_source(db), [x.encode() for x in lines], BatchChannel.DEMO, None, True, False
    )
    ingest(db, request, get_settings())


def recount(db: Session) -> dict[str, Any]:
    """The summaries, and the same figures counted from the rows."""
    q = db.execute
    return {
        "events": (
            sorted(q(text("SELECT day, records FROM event_daily_counts WHERE kind = 'event'"))),
            sorted(
                q(
                    text(
                        "SELECT (timezone('UTC', timestamp))::date, count(*) FROM events GROUP BY 1"
                    )
                )
            ),
        ),
        "raw": (
            sorted(q(text("SELECT day, records FROM event_daily_counts WHERE kind = 'raw'"))),
            sorted(
                q(
                    text(
                        "SELECT (timezone('UTC', received_at))::date, count(*) "
                        "FROM raw_events GROUP BY 1"
                    )
                )
            ),
        ),
        "logons": (
            sorted(
                q(
                    text(
                        "SELECT username, host(source_ip), day, logons, last_logon "
                        "FROM logon_success_daily"
                    )
                )
            ),
            sorted(
                q(
                    text(
                        "SELECT username, host(source_ip), (timezone('UTC', timestamp))::date, "
                        "count(*), max(timestamp) FROM events "
                        "WHERE event_category = 'authentication' AND event_action = 'logon' "
                        "AND event_outcome = 'success' AND username IS NOT NULL "
                        "AND source_ip IS NOT NULL GROUP BY 1, 2, 3"
                    )
                )
            ),
        ),
    }


def assert_summaries_match(db: Session) -> None:
    for name, (summary, counted) in recount(db).items():
        assert summary == counted, name


def test_summaries_equal_the_stored_rows(db_session: Session) -> None:
    lines = []
    for minute in range(30):  # across midnight UTC: two days
        moment = DAY + timedelta(minutes=minute)
        lines.append(line(moment, "alice", "10.0.2.41"))
        lines.append(line(moment, "bob", f"10.0.3.{minute % 3 + 1}"))
        lines.append(line(moment, "alice", "203.0.113.9", "failed"))  # not a success
    lines.append(f"{DAY.isoformat()} web-01 CRON[9]: pam_unix(cron:session): session opened")
    source = make_source(db_session)
    send(db_session, lines, source)
    send(db_session, lines[:20], source)  # duplicates: stored once, counted once
    assert_summaries_match(db_session)
    alice = db_session.execute(
        text("SELECT day, logons FROM logon_success_daily WHERE username = 'alice' ORDER BY day")
    ).all()
    assert [n for _, n in alice] == [10, 20]  # ten minutes before midnight, twenty after


def test_rows_inserted_outside_ingestion_are_counted_too(db_session: Session) -> None:
    source = make_source(db_session)
    raw = stored_raw(db_session, source, "a hand-made record")
    event = NormalizedEvent(
        source_type=SourceType.LINUX_AUTH,
        timestamp=DAY,
        host="web-01",
        event_category=EventCategory.AUTHENTICATION,
        event_action="logon",
        event_outcome=EventOutcome.SUCCESS,
        username="carol",
        source_ip="10.0.9.9",
    )
    stored_event(db_session, raw, event)
    assert_summaries_match(db_session)
    count = db_session.scalar(
        text("SELECT logons FROM logon_success_daily WHERE username = 'carol'")
    )
    assert count == 1


def test_concurrent_batches_neither_deadlock_nor_lose_counts(scratch: Factory) -> None:
    """Four batches at once for the same accounts, addresses and days: every count adds up.
    The trigger writes summary rows in a fixed order, so the batches never deadlock."""
    users = [f"user{i}" for i in range(20)]

    def batch(offset: int) -> list[str]:
        return [
            line(DAY + timedelta(seconds=offset + 7 * i), user, f"10.0.4.{i % 5 + 1}")
            for i, user in enumerate(users * 5)
        ]

    def writer(offset: int) -> None:
        with scratch() as db:
            send(db, batch(offset))

    workers = [Worker(functools.partial(writer, offset)) for offset in (1, 2, 3, 4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.finish()
    with scratch() as db:
        assert_summaries_match(db)
        total = db.scalar(text("SELECT sum(logons) FROM logon_success_daily"))
        assert total == 4 * len(users) * 5
