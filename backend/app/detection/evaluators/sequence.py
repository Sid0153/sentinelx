"""sequence: ordered steps for the same group, all within a window W.

Example (AUTH-002): step 1 "failed logon" at least N times, then step 2 "successful logon",
same source, account and host, within 10 minutes, the success at most 5 minutes after the
last failure (max_gap).

For each event that matches the LAST step, the evaluator walks backwards: every earlier step
must have enough matching events before the first event of the step after it, inside the
window, and the gap between consecutive steps must not exceed max_gap. Every matching event of
a step inside those bounds becomes evidence (all 12 failures, not just the minimum 3).

Evidence is not reused: failures that led to one detected success do not also count toward a
second success a minute later. Order is by (time, id), so an event at the same second as the
next step still has a defined place.
"""

from datetime import timedelta

from app.detection.evaluators.common import group_dict, grouped
from app.detection.events import DetectionEvent, sort_key
from app.detection.model import Match, Rule


def evaluate(rule: Rule, events: list[DetectionEvent]) -> list[Match]:
    assert rule.steps is not None and rule.time_window is not None  # noqa: S101
    assert rule.threshold is not None  # noqa: S101
    steps, window = rule.steps, rule.time_window
    relevant = [e for e in events if any(step.match.evaluate(e) for step in steps)]
    matches = []
    for key, members in grouped(rule, relevant).items():
        used: set[str] = set()
        for final in members:
            if final.id in used or not steps[-1].match.evaluate(final):
                continue
            chosen = _walk_back(rule, members, final, used, window)
            if chosen is None:
                continue
            evidence = sorted((e for part in chosen for e in part), key=sort_key)
            used.update(e.id for e in evidence)
            facts: dict[str, object] = {
                "threshold": rule.threshold,
                "time_window": window,
                "gap": chosen[-1][0].timestamp - chosen[-2][-1].timestamp,
            }
            facts |= {
                f"{step.name}_count": len(part) for step, part in zip(steps, chosen, strict=True)
            }
            matches.append(Match(group=group_dict(rule, key), events=evidence, facts=facts))
    return matches


def _walk_back(
    rule: Rule,
    members: list[DetectionEvent],
    final: DetectionEvent,
    used: set[str],
    window: timedelta,
) -> list[list[DetectionEvent]] | None:
    assert rule.steps is not None and rule.threshold is not None  # noqa: S101
    earliest = final.timestamp - window
    chosen: list[list[DetectionEvent]] = [[final]]
    for index in range(len(rule.steps) - 2, -1, -1):
        step = rule.steps[index]
        needed = rule.threshold if index == 0 else step.min_count
        boundary = sort_key(chosen[0][0])  # the first event of the step after this one
        part = [
            e
            for e in members
            if e.id not in used
            and e.timestamp >= earliest
            and sort_key(e) < boundary
            and step.match.evaluate(e)
        ]
        if len(part) < needed:
            return None
        if rule.max_gap is not None and chosen[0][0].timestamp - part[-1].timestamp > rule.max_gap:
            return None
        chosen.insert(0, part)
    return chosen
