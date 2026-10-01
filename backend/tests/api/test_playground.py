"""Phase 12: the detection testing playground, time-boxed suppression windows, and the grouped
alert queue."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.demo.scenarios import generate
from app.detection.evaluators.common import excluded
from app.detection.events import DetectionEvent
from app.detection.library import Library
from app.detection.model import Exclusion
from app.models.alert import Alert
from app.models.detection import DetectionRule, DetectionRun
from app.models.event import Event, RawEvent
from app.models.user import Role
from tests.helpers import bearer, make_user

pytestmark = pytest.mark.integration

START = (datetime.now(UTC) - timedelta(hours=2)).replace(microsecond=0)


@pytest.fixture
def admin(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.ADMIN, email="admin@example.com"))


@pytest.fixture
def analyst(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.ANALYST, email="analyst@example.com"))


@pytest.fixture
def viewer(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.VIEWER, email="viewer@example.com"))


def try_rule(
    client: TestClient, headers: dict[str, str], rule_id: str, lines: list[str], **extra: Any
) -> Any:
    body = {"source_type": "linux_auth", "records": lines, **extra}
    return client.post(f"/api/detections/{rule_id}/test", json=body, headers=headers)


def counts(db: Session) -> tuple[int, int, int, int]:
    return (
        db.scalar(select(func.count()).select_from(RawEvent)) or 0,
        db.scalar(select(func.count()).select_from(Event)) or 0,
        db.scalar(select(func.count()).select_from(Alert)) or 0,
        db.scalar(select(func.count()).select_from(DetectionRun)) or 0,
    )


# ---------- playground ----------


def test_a_rule_fires_on_sample_lines_and_says_why(
    db_client: TestClient, db_session: Session, seeded_rules: Library, analyst: dict[str, str]
) -> None:
    before = counts(db_session)
    lines = generate("brute_force", START)  # 12 failures, each with a preauth line
    response = try_rule(db_client, analyst, "AUTH-001", lines)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["triggered"] is True
    assert data["rule"]["threshold"] == 5 and data["rule"]["time_window"] == "5 min"
    assert data["rule"]["tried"] == {}
    summary = data["summary"]
    assert (summary["lines"], summary["parsed"], summary["skipped"]) == (24, 12, 12)
    assert summary["matched"] == 12 and summary["detections"] == 1
    [detection] = data["detections"]
    assert detection["explanation"].startswith('12 failed SSH logons for "root" on web-01')
    assert (detection["severity"], detection["confidence"]) == ("medium", "medium")
    assert detection["evidence_lines"] == list(range(1, 24, 2))  # the "Failed password" lines
    assert detection["mitre"] == ["T1110.001"]
    by_line = {line["line"]: line for line in data["lines"]}
    assert by_line[1]["evidence"] and by_line[1]["matched"] is True
    assert by_line[1]["source_ip"] == "203.0.113.45"
    assert by_line[2]["status"] == "skipped" and by_line[2]["code"]
    assert counts(db_session) == before  # nothing was stored


def test_why_a_rule_did_not_fire_and_a_what_if_threshold(
    db_client: TestClient, seeded_rules: Library, analyst: dict[str, str]
) -> None:
    lines = generate("brute_force", START, count=3)  # under the threshold of 5
    data = try_rule(db_client, analyst, "AUTH-001", lines).json()
    assert data["triggered"] is False and data["summary"]["matched"] == 3
    # What if the threshold were 3? Within the rule's bounds (2-1000).
    tried = try_rule(db_client, analyst, "AUTH-001", lines, changes={"threshold": 3}).json()
    assert tried["triggered"] is True and tried["rule"]["tried"] == {"threshold": 3}
    # A value a real change would refuse is refused here too.
    response = try_rule(db_client, analyst, "AUTH-001", lines, changes={"threshold": 1})
    assert response.status_code == 400 and "between 2 and 1000" in response.text
    response = try_rule(db_client, analyst, "AUTH-001", lines, changes={"enabled": False})
    assert response.status_code == 400


def test_sequence_rules_show_which_step_each_line_matches(
    db_client: TestClient, seeded_rules: Library, analyst: dict[str, str]
) -> None:
    data = try_rule(db_client, analyst, "AUTH-002", generate("brute_force_success", START)).json()
    assert data["triggered"] is True
    steps = [line["steps"] for line in data["lines"] if line["status"] == "parsed"]
    assert steps[0] == ["failures"] and steps[-1] == ["success"]
    assert all(line["matched"] is None for line in data["lines"])


def test_exclusions_and_suppressions_apply_in_the_playground(
    db_client: TestClient, seeded_rules: Library, admin: dict[str, str], analyst: dict[str, str]
) -> None:
    lines = generate("brute_force", START)
    window = {
        "active_from": (START - timedelta(hours=1)).isoformat(),
        "active_until": (START + timedelta(hours=1)).isoformat(),
    }
    suppress = {"field": "source_ip", "value": "203.0.113.0/24", "comment": "pen test", **window}
    data = try_rule(
        db_client, analyst, "AUTH-001", lines, changes={"exclusions": [suppress]}
    ).json()
    assert data["triggered"] is False and data["summary"]["excluded"] == 12
    # The same suppression a day later does not cover these events.
    later = {
        **suppress,
        "active_from": (START + timedelta(days=1)).isoformat(),
        "active_until": (START + timedelta(days=2)).isoformat(),
    }
    data = try_rule(db_client, analyst, "AUTH-001", lines, changes={"exclusions": [later]}).json()
    assert data["triggered"] is True and data["summary"]["excluded"] == 0


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ({"source_type": "linux_auth", "records": []}, 422),
        ({"source_type": "linux_auth", "records": ["x"] * 501}, 422),
        ({"source_type": "linux_auth", "records": ["x" * 8193]}, 422),
        ({"source_type": "nope", "records": ["x"]}, 422),
        ({"source_type": "linux_auth", "records": ["x"], "timezone": "Mars/Base"}, 422),
    ],
)
def test_playground_input_is_bounded(
    db_client: TestClient, seeded_rules: Library, analyst: dict[str, str], body: Any, status: int
) -> None:
    response = db_client.post("/api/detections/AUTH-001/test", json=body, headers=analyst)
    assert response.status_code == status, response.text


def test_viewers_cannot_use_the_playground(
    db_client: TestClient, seeded_rules: Library, viewer: dict[str, str]
) -> None:
    assert try_rule(db_client, viewer, "AUTH-001", ["x"]).status_code == 403


# ---------- suppression windows ----------


def _event(at: datetime) -> DetectionEvent:
    return DetectionEvent(
        id=str(uuid.uuid4()),
        timestamp=at,
        source_type="linux_auth",
        event_category="authentication",
        event_action="logon",
        event_outcome="failure",
        source_ip="203.0.113.45",
    )


def test_a_suppression_covers_only_its_window() -> None:
    start = datetime(2026, 10, 1, 8, tzinfo=UTC)
    suppression = Exclusion(
        field="source_ip",
        value="203.0.113.45",
        active_from=start,
        active_until=start + timedelta(hours=2),
    )
    assert excluded(_event(start), [suppression])  # start is inside
    assert excluded(_event(start + timedelta(minutes=119)), [suppression])
    assert not excluded(_event(start + timedelta(hours=2)), [suppression])  # end is outside
    assert not excluded(_event(start - timedelta(seconds=1)), [suppression])
    permanent = Exclusion(field="source_ip", value="203.0.113.45")
    assert excluded(_event(start - timedelta(days=400)), [permanent])


@pytest.mark.parametrize(
    ("window", "message"),
    [
        ({"active_from": "2026-10-01T08:00:00Z"}, "both active_from and active_until"),
        ({"active_from": "2026-10-01T10:00:00Z", "active_until": "2026-10-01T08:00:00Z"}, "before"),
        (
            {"active_from": "2026-10-01T08:00:00Z", "active_until": "2027-01-01T08:00:00Z"},
            "90 days",
        ),
        (
            {"active_from": "2026-10-01T08:00:00", "active_until": "2026-10-02T08:00:00"},
            "time zone",
        ),
    ],
)
def test_suppression_windows_are_validated(window: dict[str, str], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        Exclusion.model_validate({"field": "host", "value": "web-01", **window})


def test_a_tuned_suppression_is_versioned_and_stops_detection_inside_it(
    db_client: TestClient, db_session: Session, seeded_rules: Library, admin: dict[str, str]
) -> None:
    suppress = {
        "field": "source_ip",
        "value": "203.0.113.45",
        "comment": "authorised pen test",
        "active_from": (START - timedelta(minutes=10)).isoformat(),
        "active_until": (START + timedelta(hours=1)).isoformat(),
    }
    response = db_client.patch(
        "/api/detections/AUTH-001",
        json={"exclusions": [suppress], "reason": "pen test this morning"},
        headers=admin,
    )
    assert response.status_code == 200, response.text
    rule = db_session.get(DetectionRule, "AUTH-001")
    assert rule is not None and rule.version == 2
    source = db_client.post(
        "/api/sources", json={"name": "pen test log", "source_type": "linux_auth"}, headers=admin
    ).json()
    inside = generate("brute_force", START)
    after = generate("brute_force", START + timedelta(hours=2), source_ip="203.0.113.45")
    for lines in (inside, after):
        db_client.post(f"/api/ingest/{source['id']}", json={"records": lines}, headers=admin)
    alerts = db_session.scalars(select(Alert).where(Alert.rule_id == "AUTH-001")).all()
    assert len(alerts) == 1  # only the activity after the window
    assert alerts[0].first_event_at >= START + timedelta(hours=2)


# ---------- grouped queue ----------


def test_the_queue_can_be_grouped(
    db_client: TestClient, seeded_rules: Library, admin: dict[str, str], viewer: dict[str, str]
) -> None:
    source = db_client.post(
        "/api/sources", json={"name": "group log", "source_type": "linux_auth"}, headers=admin
    ).json()
    for i in range(3):
        lines = generate("brute_force", START + timedelta(minutes=i), source_ip=f"198.51.100.{i}")
        db_client.post(f"/api/ingest/{source['id']}", json={"records": lines}, headers=admin)
    lines = generate("brute_force_success", START + timedelta(minutes=30))
    db_client.post(f"/api/ingest/{source['id']}", json={"records": lines}, headers=admin)

    by_rule = db_client.get("/api/alerts/groups?by=rule", headers=viewer).json()
    groups = {g["key"]: g for g in by_rule["items"]}
    assert groups["AUTH-001"]["alerts"] == 4 and groups["AUTH-001"]["open"] == 4
    assert groups["AUTH-001"]["label"] == "Repeated SSH authentication failures"
    assert by_rule["items"][0]["key"] == "AUTH-002"  # highest priority first
    assert by_rule["total"] == len(by_rule["items"])

    by_source = db_client.get(
        "/api/alerts/groups?by=source_ip&rule_id=AUTH-001", headers=viewer
    ).json()
    assert sorted(g["key"] for g in by_source["items"]) == [
        "198.51.100.0",
        "198.51.100.1",
        "198.51.100.2",
        "203.0.113.45",
    ]
    assert db_client.get("/api/alerts/groups?by=password", headers=viewer).status_code == 422
