"""The alert workflow (every status pair) and what makes two detections the same alert."""

import itertools

import pytest

from app.alerts import workflow
from app.alerts.dedup import dedup_key, title
from app.models.alert import AlertStatus, Disposition

S = AlertStatus
ALLOWED = {
    (S.NEW, S.TRIAGED),
    (S.NEW, S.IN_PROGRESS),
    (S.NEW, S.FALSE_POSITIVE),
    (S.TRIAGED, S.IN_PROGRESS),
    (S.TRIAGED, S.RESOLVED),
    (S.TRIAGED, S.FALSE_POSITIVE),
    (S.IN_PROGRESS, S.TRIAGED),
    (S.IN_PROGRESS, S.RESOLVED),
    (S.IN_PROGRESS, S.FALSE_POSITIVE),
    (S.RESOLVED, S.TRIAGED),
    (S.FALSE_POSITIVE, S.TRIAGED),
}


def valid_inputs(target: AlertStatus) -> tuple[Disposition | None, str | None]:
    return (
        Disposition.CONFIRMED_MALICIOUS if target == S.RESOLVED else None,
        "checked with the owner",
    )


@pytest.mark.parametrize(("current", "target"), list(itertools.product(S, S)))
def test_every_status_pair(current: AlertStatus, target: AlertStatus) -> None:
    """All 25 pairs: the allowed ones pass with the inputs they need, the rest are refused."""
    disposition, reason = valid_inputs(target)
    if (current, target) in ALLOWED:
        workflow.check(current, target, disposition, reason)
        assert target in workflow.allowed(current)
    else:
        with pytest.raises(workflow.TransitionError):
            workflow.check(current, target, disposition, reason)
        assert target not in workflow.allowed(current)


def test_resolving_needs_a_disposition_and_only_resolving_takes_one() -> None:
    with pytest.raises(workflow.MissingInput, match="disposition"):
        workflow.check(S.TRIAGED, S.RESOLVED, None, None)
    workflow.check(S.TRIAGED, S.RESOLVED, Disposition.BENIGN_EXPECTED, None)  # note optional
    with pytest.raises(workflow.MissingInput, match="only given when resolving"):
        workflow.check(S.NEW, S.TRIAGED, Disposition.BENIGN_EXPECTED, None)


@pytest.mark.parametrize(
    ("current", "target"),
    [(S.NEW, S.FALSE_POSITIVE), (S.RESOLVED, S.TRIAGED), (S.FALSE_POSITIVE, S.TRIAGED)],
)
def test_false_positives_and_reopening_need_a_reason(
    current: AlertStatus, target: AlertStatus
) -> None:
    for missing in (None, ""):
        with pytest.raises(workflow.MissingInput, match="reason"):
            workflow.check(current, target, None, missing)


def test_ordinary_progress_needs_no_reason() -> None:
    workflow.check(S.NEW, S.TRIAGED, None, None)
    workflow.check(S.TRIAGED, S.IN_PROGRESS, None, None)


# ---------- deduplication key ----------

GROUP = {"source_ip": "203.0.113.45", "host": "web-01", "username": "root"}


def test_the_key_ignores_the_order_of_grouped_values() -> None:
    reordered = {"username": "root", "host": "web-01", "source_ip": "203.0.113.45"}
    assert dedup_key("AUTH-001", None, GROUP) == dedup_key("AUTH-001", None, reordered)


@pytest.mark.parametrize(
    ("rule_id", "indicator", "group"),
    [
        ("AUTH-002", None, GROUP),  # another rule
        ("AUTH-001", "root_shell", GROUP),  # another indicator
        ("AUTH-001", None, {**GROUP, "source_ip": "203.0.113.46"}),  # another value
        ("AUTH-001", None, {"source_ip": "203.0.113.45", "host": "web-01"}),  # fewer fields
    ],
)
def test_anything_else_is_different_activity(
    rule_id: str, indicator: str | None, group: dict[str, str]
) -> None:
    assert dedup_key(rule_id, indicator, group) != dedup_key("AUTH-001", None, GROUP)


def test_values_cannot_be_shifted_between_fields() -> None:
    """A separator inside a value must not make two different groups collide."""
    a = dedup_key("R-001", None, {"a": "x\x1fy", "b": "z"})
    b = dedup_key("R-001", None, {"a": "x", "b": "y\x1fz"})
    assert a != b


def test_titles_name_the_rule_indicator_and_values() -> None:
    assert (
        title("Repeated SSH authentication failures", None, GROUP)
        == "Repeated SSH authentication failures (203.0.113.45, web-01, root)"
    )
    assert title("Suspicious command line", "Encoded PowerShell command", {"host": "ws-1"}) == (
        "Suspicious command line: Encoded PowerShell command (ws-1)"
    )
    assert len(title("x" * 200, None, {"v": "y" * 200})) == 300
