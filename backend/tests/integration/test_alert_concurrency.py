"""Alerts under real concurrency: an analyst and a detection run touching the same alert at
the same time, and two batches reporting the same activity at once.

These need transactions that really commit on separate connections, which the rolled-back
test session cannot give. Committed rows in the append-only tables (events, audit log) could
never be cleaned up, so this module gets a database of its own, migrated from scratch and
dropped at the end.

The interleaving is forced, not hoped for: one side holds a lock, and the test waits until
PostgreSQL reports the other side blocked on it (pg_stat_activity) before letting go.
"""

import threading
import time
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from alembic import command
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from app.alerts import service
from app.core.config import get_settings
from app.database.migrations import alembic_config
from app.detection.library import get_library
from app.detection.storage import seed
from app.ingestion.service import IngestRequest, ingest
from app.models.alert import Alert, AlertStatus
from app.models.event import BatchChannel, BatchStatus, IngestionBatch, LogSource
from app.models.user import Role, User
from tests.conftest import _TEST_DATABASE_URL
from tests.helpers import make_user

pytestmark = pytest.mark.integration

START = (datetime.now(UTC) - timedelta(hours=1)).replace(microsecond=0)
WAIT_SECONDS = 15

Factory = sessionmaker[Session]


@pytest.fixture(scope="module")
def scratch() -> Iterator[Factory]:
    if not _TEST_DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL not set")
    base = make_url(_TEST_DATABASE_URL)
    name = f"sx_concurrency_{uuid.uuid4().hex[:8]}"
    admin = create_engine(base, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    settings = get_settings()
    original = settings.database_url
    url = base.set(database=name).render_as_string(hide_password=False)
    try:
        settings.database_url = url  # alembic/env.py migrates the configured database
        command.upgrade(alembic_config(), "head")
    finally:
        settings.database_url = original
    engine = create_engine(url)
    # The same settings as the application's sessions (app/database/session.py).
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with factory() as db:
        seed(db, get_library())
    try:
        yield factory
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


class Pause:
    """Makes the next detection run stop after alerting, before it commits, so it still holds
    its locks (the detection advisory lock and the alert rows it extended)."""

    def __init__(self) -> None:
        self.armed = False
        self.reached = threading.Event()
        self.release = threading.Event()

    def arm(self) -> None:
        self.armed = True
        self.reached.clear()
        self.release.clear()


@pytest.fixture
def pause(monkeypatch: pytest.MonkeyPatch) -> Iterator[Pause]:
    control = Pause()
    original = service.apply

    def apply(*args: Any, **kwargs: Any) -> Any:
        result = original(*args, **kwargs)
        if control.armed:
            control.armed = False
            control.reached.set()
            control.release.wait(WAIT_SECONDS)
        return result

    monkeypatch.setattr(service, "apply", apply)
    yield control
    control.release.set()


class Worker(threading.Thread):
    """Runs `work` in a thread and keeps its result or exception for the test."""

    def __init__(self, work: Callable[[], Any]) -> None:
        super().__init__(daemon=True)
        self.work = work
        self.result: Any = None
        self.error: BaseException | None = None

    def run(self) -> None:
        try:
            self.result = self.work()
        except BaseException as exc:  # reported by finish()
            self.error = exc

    def finish(self) -> Any:
        self.join(WAIT_SECONDS)
        assert not self.is_alive(), "the worker did not finish"
        if self.error is not None:
            raise self.error
        return self.result


def failures(start: datetime, host: str) -> list[bytes]:
    """Six failed SSH logons for root on `host`: one AUTH-001 detection."""
    return [
        (
            f"{(start + timedelta(seconds=i * 3)).isoformat()} {host} sshd[{3000 + i}]: "
            f"Failed password for root from 203.0.113.45 port {52000 + i} ssh2"
        ).encode()
        for i in range(6)
    ]


def new_source(factory: Factory) -> uuid.UUID:
    with factory() as db:
        source = LogSource(name=f"src-{uuid.uuid4().hex[:8]}", source_type="linux_auth")
        db.add(source)
        db.commit()
        return source.id


def send(factory: Factory, source_id: uuid.UUID, lines: list[bytes]) -> uuid.UUID:
    with factory() as db:
        source = db.get(LogSource, source_id)
        assert source is not None
        request = IngestRequest(source, lines, BatchChannel.API, None, False)
        return ingest(db, request, get_settings()).id


def alerts_on(factory: Factory, host: str) -> list[Alert]:
    with factory() as db:
        return list(db.scalars(select(Alert).where(Alert.host == host).order_by(Alert.created_at)))


def new_analyst(factory: Factory) -> uuid.UUID:
    with factory() as db:
        return make_user(db, Role.ANALYST).id


def change(
    db: Session, alert_id: uuid.UUID, analyst_id: uuid.UUID, target: AlertStatus, reason: str | None
) -> Alert:
    actor = db.get(User, analyst_id)
    assert actor is not None
    return service.transition(db, alert_id, target, None, reason, actor, datetime.now(UTC))


def wait_until_blocked(factory: Factory) -> None:
    """Until another session of this database waits on a lock (row or advisory)."""
    deadline = time.monotonic() + WAIT_SECONDS
    with factory() as probe:
        while time.monotonic() < deadline:
            waiting = probe.execute(
                text(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE datname = current_database() AND wait_event_type = 'Lock'"
                )
            ).scalar_one()
            if waiting:
                return
            probe.rollback()  # a fresh snapshot for the next look
            time.sleep(0.02)
    raise AssertionError("the other transaction never blocked on the lock")


def test_a_run_waiting_on_an_alert_the_analyst_closes_opens_a_new_one(scratch: Factory) -> None:
    """The analyst holds the alert (row lock) and closes it. The run that was blocked on the
    lock must not extend the closed alert: it opens a new one pointing to it."""
    host = f"race-a-{uuid.uuid4().hex[:6]}"
    source, analyst = new_source(scratch), new_analyst(scratch)
    send(scratch, source, failures(START, host))
    (first,) = alerts_on(scratch, host)

    with scratch() as db:
        db.scalars(select(Alert).where(Alert.id == first.id).with_for_update()).one()
        later = failures(START + timedelta(minutes=1), host)
        run = Worker(lambda: send(scratch, source, later))
        run.start()
        wait_until_blocked(scratch)
        change(db, first.id, analyst, AlertStatus.FALSE_POSITIVE, "our scanner")  # commits
    batch_id = run.finish()

    closed, reopened = alerts_on(scratch, host)
    assert closed.id == first.id and closed.status == AlertStatus.FALSE_POSITIVE
    assert (closed.event_count, closed.detection_count) == (6, 1)  # untouched after closing
    assert reopened.status == AlertStatus.NEW and reopened.previous_alert_id == first.id
    assert reopened.event_count == 6  # only the new events
    with scratch() as db:
        batch = db.get(IngestionBatch, batch_id)
        assert batch is not None and batch.status == BatchStatus.PROCESSED
        assert (batch.alerts_created, batch.alerts_updated) == (1, 0)


def test_an_analyst_waits_for_a_run_extending_the_alert_and_nothing_is_lost(
    scratch: Factory, pause: Pause
) -> None:
    host = f"race-b-{uuid.uuid4().hex[:6]}"
    source, analyst = new_source(scratch), new_analyst(scratch)
    send(scratch, source, failures(START, host))
    (first,) = alerts_on(scratch, host)

    pause.arm()  # the next run extends the alert, then stops before committing
    later = failures(START + timedelta(minutes=1), host)
    run = Worker(lambda: send(scratch, source, later))
    run.start()
    assert pause.reached.wait(WAIT_SECONDS)

    def triage() -> Alert:
        with scratch() as db:
            return change(db, first.id, analyst, AlertStatus.TRIAGED, None)

    analyst_change = Worker(triage)
    analyst_change.start()
    wait_until_blocked(scratch)  # the analyst waits for the run's row lock
    pause.release.set()
    run.finish()
    triaged = analyst_change.finish()

    assert triaged.status == AlertStatus.TRIAGED
    assert (triaged.event_count, triaged.detection_count) == (12, 2)  # the extension is kept
    assert [a.id for a in alerts_on(scratch, host)] == [first.id]


def test_two_batches_reporting_the_same_activity_at_once_make_one_alert(
    scratch: Factory, pause: Pause
) -> None:
    host = f"race-c-{uuid.uuid4().hex[:6]}"
    first_source, second_source = new_source(scratch), new_source(scratch)

    pause.arm()  # the first run creates the alert, then stops before committing
    one = Worker(lambda: send(scratch, first_source, failures(START, host)))
    one.start()
    assert pause.reached.wait(WAIT_SECONDS)
    later = failures(START + timedelta(seconds=30), host)
    two = Worker(lambda: send(scratch, second_source, later))
    two.start()
    wait_until_blocked(scratch)  # the second run waits for the detection lock
    pause.release.set()
    first_batch, second_batch = one.finish(), two.finish()

    (alert,) = alerts_on(scratch, host)
    assert alert.event_count == 12 and alert.detection_count == 2
    with scratch() as db:
        counts = [
            (b.alerts_created, b.alerts_updated)
            for b in (db.get(IngestionBatch, first_batch), db.get(IngestionBatch, second_batch))
            if b is not None
        ]
    assert counts == [(1, 0), (0, 1)]
