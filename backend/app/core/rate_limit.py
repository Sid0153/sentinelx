"""Rate limits kept in PostgreSQL (Phase 13), so they hold across restarts and replicas.

Before Phase 13 the counters lived in process memory: a restart reset them and each replica
counted separately (docs/security.md, residual risks). Now each limited key has one counter
row per window (a minute by default), incremented with a single atomic upsert, and the
decision uses a sliding-window estimate: the current window's count plus the previous
window's, weighted by how much of it still overlaps the last `window_seconds`. That avoids
the double burst a plain fixed window allows at its boundary, without storing every event.
"""

import random
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.rate_limit import RateLimitCounter

CLEANUP_PROBABILITY = 0.02  # about one call in fifty also removes counters past use


def sliding_count(previous: int, current: int, elapsed_fraction: float) -> float:
    """Events in the last window, estimated from two fixed windows: the share of the previous
    window that still overlaps it, plus all of the current one."""
    return previous * (1.0 - elapsed_fraction) + current


class RateLimiter:
    """At most `max_events` per `window_seconds` for each key of one `scope` ("login",
    "ingest"). The counter change is committed with the caller's transaction."""

    def __init__(self, scope: str, max_events: int, window_seconds: int = 60) -> None:
        self.scope = scope
        self.max_events = max_events
        self.window = timedelta(seconds=window_seconds)

    def _window_start(self, now: datetime) -> datetime:
        seconds = int(self.window.total_seconds())
        epoch = int(now.timestamp())
        return datetime.fromtimestamp(epoch - epoch % seconds, tz=UTC)

    def allow(self, db: Session, key: str, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        name = f"{self.scope}:{key}"[:200]
        start = self._window_start(now)
        previous = db.scalar(
            select(RateLimitCounter.count).where(
                RateLimitCounter.key == name, RateLimitCounter.window_start == start - self.window
            )
        )
        current = db.scalar(
            insert(RateLimitCounter)
            .values(key=name, window_start=start, count=1)
            .on_conflict_do_update(
                index_elements=["key", "window_start"],
                set_={"count": RateLimitCounter.count + 1},
            )
            .returning(RateLimitCounter.count)
        )
        if random.random() < CLEANUP_PROBABILITY:  # noqa: S311 (not security relevant)
            db.execute(
                delete(RateLimitCounter).where(
                    RateLimitCounter.window_start < start - 2 * self.window
                )
            )
        elapsed = (now - start) / self.window
        return sliding_count(previous or 0, current or 0, elapsed) <= self.max_events
