"""Helpers for tests that need real concurrent transactions (see
tests/integration/test_alert_concurrency.py for why and how)."""

import threading
import time
from collections.abc import Callable
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

WAIT_SECONDS = 15

Factory = sessionmaker[Session]


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
