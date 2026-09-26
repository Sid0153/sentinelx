"""The incident workflow (pure): which status changes are allowed and what each one needs.

- OPEN → TRIAGED or RESOLVED
- TRIAGED → INVESTIGATING or RESOLVED
- INVESTIGATING → CONTAINED or RESOLVED
- CONTAINED → INVESTIGATING (containment did not hold) or RESOLVED
- RESOLVED → CLOSED, or INVESTIGATING (reopen)
- CLOSED: final

RESOLVED needs a disposition and a resolution summary (they stay when the incident is
closed). Reopening needs a reason. Any open status may go straight to RESOLVED: an incident
found benign during triage does not have to pass through containment.
"""

from app.models.incident import IncidentDisposition, IncidentStatus

S = IncidentStatus

TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    S.OPEN: frozenset({S.TRIAGED, S.RESOLVED}),
    S.TRIAGED: frozenset({S.INVESTIGATING, S.RESOLVED}),
    S.INVESTIGATING: frozenset({S.CONTAINED, S.RESOLVED}),
    S.CONTAINED: frozenset({S.INVESTIGATING, S.RESOLVED}),
    S.RESOLVED: frozenset({S.CLOSED, S.INVESTIGATING}),
    S.CLOSED: frozenset(),
}


class TransitionError(ValueError):
    """Not allowed from the current status (a state conflict)."""


class MissingInput(ValueError):
    """Allowed, but a disposition, resolution or reason is missing."""


def is_reopen(current: IncidentStatus, target: IncidentStatus) -> bool:
    return current == S.RESOLVED and target == S.INVESTIGATING


def check(
    current: IncidentStatus,
    target: IncidentStatus,
    disposition: IncidentDisposition | None,
    resolution: str | None,
    reason: str | None,
) -> None:
    if current == S.CLOSED:
        raise TransitionError("A closed incident is final; open a new one if activity returns")
    if target == current:
        raise TransitionError(f"The incident is already {current}")
    if target not in TRANSITIONS[current]:
        raise TransitionError(f"An incident cannot go from {current} to {target}")
    if target == S.RESOLVED and (disposition is None or not resolution):
        raise MissingInput("Resolving needs a disposition and a resolution summary")
    if target != S.RESOLVED and (disposition is not None or resolution):
        raise MissingInput("A disposition and resolution are only given when resolving")
    if is_reopen(current, target) and not reason:
        raise MissingInput("Say why: a reason is required to reopen an incident")


def allowed(current: IncidentStatus) -> list[IncidentStatus]:
    return sorted(TRANSITIONS[current], key=list(IncidentStatus).index)


def accepts_alerts(status: IncidentStatus) -> bool:
    """Only open incidents take new alerts; resolved and closed ones are never extended."""
    return status not in (S.RESOLVED, S.CLOSED)
