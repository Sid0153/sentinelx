"""Runs one rule over events: the pure entry point to the five evaluator kinds.

(rule, events, history) -> matches. The rule's exclusions and `match` condition filter the
events first (a sequence filters per step instead). No database, no clock: the engine loads
the events, this decides.
"""

from datetime import datetime
from typing import Any

from app.detection.evaluators import distinct, new_value, sequence, single, threshold
from app.detection.evaluators.common import excluded
from app.detection.events import DetectionEvent, sort_key
from app.detection.model import Match, Rule


def evaluate(
    rule: Rule,
    events: list[DetectionEvent],
    history: dict[tuple[Any, ...], list[tuple[datetime, Any]]] | None = None,
) -> list[Match]:
    """`history` is only used by new_value rules: earlier (time, value) pairs per key."""
    usable = sorted((e for e in events if not excluded(e, rule.exclusions)), key=sort_key)
    if rule.kind == "sequence":
        return sequence.evaluate(rule, usable)
    if rule.match is None:  # impossible for a validated rule; kept as a clear failure
        raise ValueError(f"{rule.id} has no match condition")
    matching = [e for e in usable if rule.match.evaluate(e)]
    if rule.kind == "single":
        return single.evaluate(rule, matching)
    if rule.kind == "threshold":
        return threshold.evaluate(rule, matching)
    if rule.kind == "distinct":
        return distinct.evaluate(rule, matching)
    return new_value.evaluate(rule, matching, history or {})
