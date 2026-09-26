"""The alert workflow (pure): which status changes are allowed and what each one needs.

- NEW → TRIAGED, IN_PROGRESS or FALSE_POSITIVE
- TRIAGED → IN_PROGRESS, RESOLVED or FALSE_POSITIVE
- IN_PROGRESS → TRIAGED (put back), RESOLVED or FALSE_POSITIVE
- RESOLVED or FALSE_POSITIVE → TRIAGED (reopen)

RESOLVED needs a disposition (confirmed_malicious or benign_expected). FALSE_POSITIVE and
reopening need a reason. NEW cannot go straight to RESOLVED: closing an alert as handled
means someone looked at it, so it is triaged first.
"""

from app.models.alert import ACTIVE_STATUSES, AlertStatus, Disposition

TRANSITIONS: dict[AlertStatus, frozenset[AlertStatus]] = {
    AlertStatus.NEW: frozenset(
        {AlertStatus.TRIAGED, AlertStatus.IN_PROGRESS, AlertStatus.FALSE_POSITIVE}
    ),
    AlertStatus.TRIAGED: frozenset(
        {AlertStatus.IN_PROGRESS, AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE}
    ),
    AlertStatus.IN_PROGRESS: frozenset(
        {AlertStatus.TRIAGED, AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE}
    ),
    AlertStatus.RESOLVED: frozenset({AlertStatus.TRIAGED}),
    AlertStatus.FALSE_POSITIVE: frozenset({AlertStatus.TRIAGED}),
}


class TransitionError(ValueError):
    """The change is not allowed from the current status (a state conflict)."""


class MissingInput(ValueError):
    """The change is allowed but lacks what it needs (a disposition or a reason)."""


def is_reopen(current: AlertStatus, target: AlertStatus) -> bool:
    return current not in ACTIVE_STATUSES and target in ACTIVE_STATUSES


def check(
    current: AlertStatus,
    target: AlertStatus,
    disposition: Disposition | None,
    reason: str | None,
) -> None:
    if target == current:
        raise TransitionError(f"The alert is already {current}")
    if target not in TRANSITIONS[current]:
        raise TransitionError(f"An alert cannot go from {current} to {target}")
    if target == AlertStatus.RESOLVED and disposition is None:
        raise MissingInput("Resolving needs a disposition: confirmed_malicious or benign_expected")
    if target != AlertStatus.RESOLVED and disposition is not None:
        raise MissingInput("A disposition is only given when resolving")
    if (target == AlertStatus.FALSE_POSITIVE or is_reopen(current, target)) and not reason:
        raise MissingInput(
            "Say why: a reason is required to mark a false positive or to reopen an alert"
        )


def allowed(current: AlertStatus) -> list[AlertStatus]:
    return sorted(TRANSITIONS[current], key=list(AlertStatus).index)
