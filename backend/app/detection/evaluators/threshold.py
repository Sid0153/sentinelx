"""threshold: at least N matching events for the same group within any window of length W.

Sliding window with two pointers over each group's events (time order). Window edges are
inclusive: events exactly W apart count as inside. When the count first reaches N, the
detection is a *burst*: events that keep arriving within W of the previous one are added to it
as evidence, instead of producing a new detection on every event. After a gap longer than W,
counting starts again.
"""

from app.detection.evaluators.common import group_dict, grouped
from app.detection.events import DetectionEvent
from app.detection.model import Match, Rule


def evaluate(rule: Rule, events: list[DetectionEvent]) -> list[Match]:
    assert rule.threshold is not None and rule.time_window is not None  # noqa: S101
    window, needed = rule.time_window, rule.threshold
    matches = []
    for key, members in grouped(rule, events).items():
        start, index, count = 0, 0, len(members)
        while index < count:
            while members[index].timestamp - members[start].timestamp > window:
                start += 1
            if index - start + 1 >= needed:
                end = index
                while (
                    end + 1 < count
                    and members[end + 1].timestamp - members[end].timestamp <= window
                ):
                    end += 1
                evidence = members[start : end + 1]
                matches.append(
                    Match(
                        group=group_dict(rule, key),
                        events=evidence,
                        facts={"threshold": needed, "time_window": window},
                    )
                )
                index = start = end + 1
                continue
            index += 1
    return matches
