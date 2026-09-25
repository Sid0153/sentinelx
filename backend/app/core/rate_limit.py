import threading
import time
from collections import defaultdict, deque

_MAX_TRACKED_KEYS = 10_000


class SlidingWindowRateLimiter:
    """Allows at most `max_events` per `window_seconds` for each key.

    Kept in process memory: fine for a single backend container, but each replica would count
    separately and a restart resets the counters. A shared store (for example Redis) would be
    the next step if the app were scaled out (docs/security.md, residual risks).
    """

    def __init__(self, max_events: int, window_seconds: float = 60.0) -> None:
        self._max_events = max_events
        self._window = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        cutoff = current - self._window
        with self._lock:
            if len(self._events) > _MAX_TRACKED_KEYS:
                self._purge(cutoff)
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= self._max_events:
                return False
            events.append(current)
            return True

    def _purge(self, cutoff: float) -> None:
        stale = [key for key, events in self._events.items() if not events or events[-1] <= cutoff]
        for key in stale:
            del self._events[key]
