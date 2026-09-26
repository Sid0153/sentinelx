"""new_value: an event whose value was not seen for the same key during the lookback period.

Example (AUTH-004): a successful logon for an account from a source network (/24 for IPv4,
/64 for IPv6) that this account has not logged on from in the previous 14 days. The rule only
fires for keys with enough history (min_history earlier events): without a baseline, every
first logon would look "new" (the cold-start problem), so new accounts are not flagged.

`history` holds (timestamp, value) pairs per key from before the evaluated range (loaded by
the engine); events in the range are added as they are evaluated, in time order. Each new
(key, value) pair is reported once per run.
"""

import ipaddress
from collections import defaultdict
from datetime import datetime
from typing import Any

from app.detection.evaluators.common import group_dict, grouped
from app.detection.events import DetectionEvent
from app.detection.model import Match, Rule


def transform(rule: Rule, value: Any) -> str | None:
    if value is None or value == "":
        return None
    if rule.value_transform == "ip_network":
        try:
            ip = ipaddress.ip_address(str(value))
        except ValueError:
            return None
        prefix = 24 if ip.version == 4 else 64
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    return str(value)


def evaluate(
    rule: Rule,
    events: list[DetectionEvent],
    history: dict[tuple[Any, ...], list[tuple[datetime, Any]]],
) -> list[Match]:
    assert rule.value_field and rule.lookback and rule.min_history  # noqa: S101
    seen: dict[tuple[Any, ...], list[tuple[datetime, str]]] = defaultdict(list)
    for key, entries in history.items():
        for stamp, raw in entries:
            if (value := transform(rule, raw)) is not None:
                seen[key].append((stamp, value))
    reported: set[tuple[tuple[Any, ...], str]] = set()
    matches = []
    for key, members in grouped(rule, events).items():
        for event in members:
            value = transform(rule, event.get(rule.value_field))
            if value is None:
                continue
            since = event.timestamp - rule.lookback
            prior = [v for stamp, v in seen[key] if since <= stamp < event.timestamp]
            if (
                len(prior) >= rule.min_history
                and value not in prior
                and (key, value) not in reported
            ):
                reported.add((key, value))
                matches.append(
                    Match(
                        group=group_dict(rule, key),
                        events=[event],
                        facts={
                            "value": value,
                            "lookback": rule.lookback,
                            "history_count": len(prior),
                        },
                    )
                )
            seen[key].append((event.timestamp, value))
    return matches
