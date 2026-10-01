"""Phase 13: raw log records (which can hold a secret typed into the wrong field) are shown to
analysts and admins only; viewers see the normalized events, with the raw text withheld."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.demo.scenarios import generate
from app.detection.library import Library
from app.models.user import Role
from tests.helpers import bearer, make_user

pytestmark = pytest.mark.integration

START = (datetime.now(UTC) - timedelta(hours=1)).replace(microsecond=0)


@pytest.fixture
def setup(db_client: TestClient, db_session: Session, seeded_rules: Library) -> dict[str, Any]:
    admin = bearer(make_user(db_session, Role.ADMIN, email="admin@example.com"))
    source = db_client.post(
        "/api/sources", json={"name": "raw access", "source_type": "linux_auth"}, headers=admin
    ).json()
    batch = db_client.post(
        f"/api/ingest/{source['id']}",
        json={"records": generate("brute_force_success", START)},
        headers=admin,
    ).json()
    alert = db_client.get("/api/alerts?rule_id=AUTH-002", headers=admin).json()["items"][0]
    incident = db_client.get("/api/incidents", headers=admin).json()["items"][0]
    event = db_client.get(f"/api/alerts/{alert['id']}/events", headers=admin).json()["items"][0]
    return {
        "batch": batch["id"],
        "alert": alert["id"],
        "incident": incident["id"],
        "event": event["id"],
    }


def raw_views(client: TestClient, headers: dict[str, str], ids: dict[str, Any]) -> list[Any]:
    event = client.get(f"/api/events/{ids['event']}", headers=headers).json()["raw"]
    records = client.get(f"/api/ingest/batches/{ids['batch']}/records", headers=headers).json()
    evidence = client.get(f"/api/alerts/{ids['alert']}/events", headers=headers).json()
    timeline = client.get(f"/api/incidents/{ids['incident']}/timeline", headers=headers).json()
    timeline_events = [i["event"] for i in timeline["items"] if i["kind"] == "event"]
    return [
        (event["text"], event["withheld"]),
        (records["items"][0]["text"], records["items"][0]["withheld"]),
        (evidence["items"][0]["raw_text"], evidence["items"][0]["raw_withheld"]),
        (timeline_events[0]["raw_text"], None),
    ]


def test_viewers_see_normalized_events_without_the_raw_text(
    db_client: TestClient, db_session: Session, setup: dict[str, Any]
) -> None:
    viewer = bearer(make_user(db_session, Role.VIEWER, email="viewer@example.com"))
    views = raw_views(db_client, viewer, setup)
    assert views == [(None, True), (None, True), (None, True), (None, None)]
    # The normalized event is still there.
    event = db_client.get(f"/api/events/{setup['event']}", headers=viewer).json()
    assert event["username"] and event["source_ip"]


def test_analysts_see_the_raw_record(
    db_client: TestClient, db_session: Session, setup: dict[str, Any]
) -> None:
    analyst = bearer(make_user(db_session, Role.ANALYST, email="analyst@example.com"))
    for text, withheld in raw_views(db_client, analyst, setup):
        assert text and "sshd" in text
        assert withheld in (False, None)
