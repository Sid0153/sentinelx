"""Rate limits in PostgreSQL (Phase 13): counted per key and scope, shared by every limiter
instance (a restart or another replica sees the same counts), sliding across windows."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from app.core.rate_limit import RateLimiter

pytestmark = pytest.mark.integration

T0 = datetime(2026, 10, 2, 9, 0, 0, tzinfo=UTC)  # the start of a one-minute window


def test_the_limit_holds_per_key_and_scope(db_session: Session) -> None:
    limiter = RateLimiter("login", max_events=3)
    seconds = (1, 2, 3, 4)
    assert [
        limiter.allow(db_session, "203.0.113.9", T0 + timedelta(seconds=s)) for s in seconds
    ] == [
        True,
        True,
        True,
        False,
    ]
    assert limiter.allow(db_session, "198.51.100.7", T0)  # another key
    assert RateLimiter("ingest", max_events=3).allow(db_session, "203.0.113.9", T0)  # another scope


def test_counts_survive_a_restart_and_are_shared_by_replicas(db_session: Session) -> None:
    first = RateLimiter("login", max_events=2)
    assert first.allow(db_session, "203.0.113.9", T0)
    assert first.allow(db_session, "203.0.113.9", T0 + timedelta(seconds=1))
    restarted = RateLimiter("login", max_events=2)  # a new process: same database
    assert not restarted.allow(db_session, "203.0.113.9", T0 + timedelta(seconds=2))


def test_the_window_slides_instead_of_resetting(db_session: Session) -> None:
    limiter = RateLimiter("login", max_events=4)
    for second in range(4):
        assert limiter.allow(db_session, "k", T0 + timedelta(seconds=50 + second))
    # Just after the minute boundary the previous window still counts almost fully: a fixed
    # window would allow another burst of 4 here.
    assert not limiter.allow(db_session, "k", T0 + timedelta(seconds=61))
    # Most of a minute later, the old attempts have slid out.
    assert limiter.allow(db_session, "k", T0 + timedelta(seconds=115))
