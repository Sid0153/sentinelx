"""Helpers shared by the evaluators.

An event with no value for one of the rule's grouping fields cannot be attributed to a group
(a failed logon with no source address cannot count toward "one source"). Such an event is
skipped by that rule, not lumped together with other events that also lack the value.
"""

import ipaddress
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from app.detection.conditions import fold
from app.detection.events import DetectionEvent, sort_key
from app.detection.model import Exclusion, Rule


def group_key(rule: Rule, event: DetectionEvent) -> tuple[Any, ...] | None:
    values = tuple(event.get(name) for name in rule.group_by)
    return None if any(v is None or v == "" for v in values) else values


def group_dict(rule: Rule, key: tuple[Any, ...]) -> dict[str, Any]:
    return {name: str(value) for name, value in zip(rule.group_by, key, strict=True)}


def excluded(event: DetectionEvent, exclusions: list[Exclusion]) -> bool:
    for exclusion in exclusions:
        actual = event.get(exclusion.field)
        if actual is None:
            continue
        if exclusion.field == "source_ip":
            try:
                ip = ipaddress.ip_address(str(actual))
                network = ipaddress.ip_network(exclusion.value, strict=False)
            except ValueError:
                continue
            if ip.version == network.version and ip in network:
                return True
        elif fold(actual) == fold(exclusion.value):  # ASCII only: see conditions.fold
            return True
    return False


def grouped(
    rule: Rule, events: Iterable[DetectionEvent]
) -> dict[tuple[Any, ...], list[DetectionEvent]]:
    groups: dict[tuple[Any, ...], list[DetectionEvent]] = defaultdict(list)
    for event in events:
        if (key := group_key(rule, event)) is not None:
            groups[key].append(event)
    for members in groups.values():
        members.sort(key=sort_key)
    return groups
