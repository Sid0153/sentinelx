"""single: every matching event is a detection (with its indicator, when the rule has them)."""

from app.detection.evaluators.common import group_key
from app.detection.events import DetectionEvent
from app.detection.model import Match, Rule


def evaluate(rule: Rule, events: list[DetectionEvent]) -> list[Match]:
    matches = []
    for event in events:
        key = group_key(rule, event)
        if key is None:
            continue
        indicator = None
        if rule.indicators:
            # The first matching indicator names the detection; order in the YAML is priority.
            indicator = next((i for i in rule.indicators if i.match.evaluate(event)), None)
            if indicator is None:
                continue
        group = {name: str(value) for name, value in zip(rule.group_by, key, strict=True)}
        matches.append(Match(group=group, events=[event], indicator=indicator))
    return matches
