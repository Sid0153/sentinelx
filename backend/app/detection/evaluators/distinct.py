"""distinct: at least N different values of a field for the same group within a window W.

Example: one source (group) failing to log on as 5 different accounts (distinct field) within
10 minutes. Same sliding window and burst behaviour as threshold, counting distinct values
instead of events. Events without a value for the distinct field do not count.
"""

from collections import Counter

from app.detection.evaluators.common import group_dict, grouped
from app.detection.events import DetectionEvent
from app.detection.model import Match, Rule

SAMPLE_SIZE = 5


def evaluate(rule: Rule, events: list[DetectionEvent]) -> list[Match]:
    assert rule.threshold is not None and rule.time_window is not None  # noqa: S101
    assert rule.distinct_field is not None  # noqa: S101
    window, needed, field = rule.time_window, rule.threshold, rule.distinct_field
    matches = []
    for key, all_members in grouped(rule, events).items():
        members = [e for e in all_members if e.get(field) not in (None, "")]
        values: Counter[str] = Counter()
        start, index, count = 0, 0, len(members)
        while index < count:
            values[str(members[index].get(field))] += 1
            while members[index].timestamp - members[start].timestamp > window:
                old = str(members[start].get(field))
                values[old] -= 1
                if not values[old]:
                    del values[old]
                start += 1
            if len(values) >= needed:
                end = index
                while (
                    end + 1 < count
                    and members[end + 1].timestamp - members[end].timestamp <= window
                ):
                    end += 1
                evidence = members[start : end + 1]
                seen = list(dict.fromkeys(str(e.get(field)) for e in evidence))
                matches.append(
                    Match(
                        group=group_dict(rule, key),
                        events=evidence,
                        facts={
                            "threshold": needed,
                            "time_window": window,
                            "distinct_count": len(seen),
                            "values_sample": ", ".join(seen[:SAMPLE_SIZE])
                            + (", …" if len(seen) > SAMPLE_SIZE else ""),
                        },
                    )
                )
                index = start = end + 1
                values.clear()
                continue
            index += 1
    return matches
