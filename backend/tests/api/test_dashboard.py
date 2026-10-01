"""The SOC dashboard and the asset / identity context: every number is checked against what
was ingested (or an independent count), an empty system shows zeros and empty lists, closed
work stops counting, and trends have every day."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.demo.scenarios import generate
from app.detection.library import Library
from app.models.alert import Alert
from app.models.event import Event
from app.models.user import Role
from tests.helpers import bearer, make_user

pytestmark = pytest.mark.integration

# Recent enough to be "today" in most hours; tests that need "today" compute it independently.
START = (datetime.now(UTC) - timedelta(minutes=15)).replace(microsecond=0)


@pytest.fixture
def admin(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.ADMIN, email="admin@example.com"))


@pytest.fixture
def viewer(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.VIEWER, email="viewer@example.com"))


def ingest(client: TestClient, admin: dict[str, str], lines: list[str]) -> None:
    source = client.post(
        "/api/sources",
        json={"name": f"log {lines[0][:26]}", "source_type": "linux_auth"},
        headers=admin,
    ).json()
    response = client.post(f"/api/ingest/{source['id']}", json={"records": lines}, headers=admin)
    assert response.status_code == 201, response.text


def summary(client: TestClient, headers: dict[str, str]) -> dict[str, Any]:
    response = client.get("/api/dashboard/summary", headers=headers)
    assert response.status_code == 200, response.text
    return dict(response.json())


def test_an_empty_system_shows_zeros_not_made_up_numbers(
    db_client: TestClient, viewer: dict[str, str]
) -> None:
    data = summary(db_client, viewer)
    for key in (
        "records_processed",
        "events_stored",
        "events_today",
        "alerts_today",
        "open_alerts",
        "critical_alerts",
        "high_alerts",
        "open_incidents",
        "incidents_under_investigation",
        "monitored_hosts",
    ):
        assert data[key] == 0, key
    assert data["severity_distribution"] == [
        {"severity": s, "count": 0} for s in ("critical", "high", "medium", "low")
    ]
    assert data["top_rules"] == data["top_source_ips"] == []
    assert data["recent_alerts"] == data["recent_incidents"] == []


def test_the_numbers_match_what_was_ingested(
    db_client: TestClient,
    db_session: Session,
    seeded_rules: Library,
    admin: dict[str, str],
    viewer: dict[str, str],
) -> None:
    ingest(db_client, admin, generate("multi_stage_attack", START))
    data = summary(db_client, viewer)
    today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    # Independent counts, written as plain SQL rather than through the code under test.

    def count(sql: str) -> int:
        return int(db_session.execute(text(sql), {"today": today}).scalar_one())

    assert data["records_processed"] == count("SELECT count(*) FROM raw_events") > 0
    assert data["events_stored"] == count("SELECT count(*) FROM events") > 0
    assert data["events_today"] == count("SELECT count(*) FROM events WHERE timestamp >= :today")
    assert data["alerts_today"] == count("SELECT count(*) FROM alerts WHERE created_at >= :today")
    # The chain: AUTH-002 and ACCT-001 are high, AUTH-001 and PRIV-001 medium.
    assert (data["open_alerts"], data["high_alerts"], data["critical_alerts"]) == (4, 2, 0)
    assert data["open_alerts_simulated"] == 0  # sent through the API, not demo-ingest
    assert {d["severity"]: d["count"] for d in data["severity_distribution"]} == {
        "critical": 0,
        "high": 2,
        "medium": 2,
        "low": 0,
    }
    assert (data["open_incidents"], data["incidents_under_investigation"]) == (1, 0)
    assert data["monitored_hosts"] == 1
    assert (data["active_rules"], data["library_rules"]) == (9, 9)
    assert sorted(r["rule_id"] for r in data["top_rules"]) == [
        "ACCT-001",
        "AUTH-001",
        "AUTH-002",
        "PRIV-001",
    ]
    assert data["top_source_ips"] == [{"source_ip": "203.0.113.45", "alerts": 2}]
    created = [a["created_at"] for a in data["recent_alerts"]]
    assert len(created) == 4 and created == sorted(created, reverse=True)
    assert data["recent_incidents"][0]["title"].startswith("Multi-stage activity on web-01")


def test_closed_work_stops_counting_and_picked_up_incidents_are_under_investigation(
    db_client: TestClient, seeded_rules: Library, admin: dict[str, str], viewer: dict[str, str]
) -> None:
    ingest(db_client, admin, generate("multi_stage_attack", START))
    before = summary(db_client, viewer)
    (high,) = [a for a in before["recent_alerts"] if a["rule_id"] == "ACCT-001"]
    db_client.post(
        f"/api/alerts/{high['id']}/transition",
        json={"status": "FALSE_POSITIVE", "reason": "admin created it"},
        headers=admin,
    )
    incident = before["recent_incidents"][0]
    db_client.post(
        f"/api/incidents/{incident['id']}/transition", json={"status": "TRIAGED"}, headers=admin
    )
    after = summary(db_client, viewer)
    assert (after["open_alerts"], after["high_alerts"]) == (3, 1)
    assert (after["open_incidents"], after["incidents_under_investigation"]) == (1, 1)


def test_trends_have_every_day_and_add_up(
    db_client: TestClient,
    db_session: Session,
    seeded_rules: Library,
    admin: dict[str, str],
    viewer: dict[str, str],
) -> None:
    ingest(db_client, admin, generate("brute_force", START - timedelta(days=3)))
    ingest(db_client, admin, generate("multi_stage_attack", START))
    trends = db_client.get("/api/dashboard/trends?days=7", headers=viewer).json()
    days = [item["day"] for item in trends["items"]]
    assert len(days) == 7 and days == sorted(days) and days[-1] == str(datetime.now(UTC).date())
    alerts = db_session.scalar(select(func.count()).select_from(Alert))
    assert sum(sum(item["alerts"].values()) for item in trends["items"]) == alerts
    assert sum(item["incidents"] for item in trends["items"]) == 1
    first = datetime.fromisoformat(days[0]).replace(tzinfo=UTC)
    events = db_session.scalar(select(func.count()).where(Event.timestamp >= first))
    assert sum(item["events"] for item in trends["items"]) == events
    old_day = str((START - timedelta(days=3)).date())
    assert next(i for i in trends["items"] if i["day"] == old_day)["events"] > 0
    for bad in ("0", "91", "x"):
        assert db_client.get(f"/api/dashboard/trends?days={bad}", headers=viewer).status_code == 422


def test_assets_and_identities_carry_their_context(
    db_client: TestClient,
    db_session: Session,
    seeded_rules: Library,
    admin: dict[str, str],
    viewer: dict[str, str],
) -> None:
    ingest(db_client, admin, generate("multi_stage_attack", START))
    # Created after the events: found by host name and username.
    web = db_client.post(
        "/api/assets",
        json={
            "hostname": "web-01",
            "asset_type": "server",
            "environment": "production",
            "criticality": "high",
        },
        headers=admin,
    ).json()
    idle = db_client.post(
        "/api/assets",
        json={
            "hostname": "idle-01",
            "asset_type": "server",
            "environment": "staging",
            "criticality": "low",
        },
        headers=admin,
    ).json()
    deploy = db_client.post(
        "/api/identities", json={"username": "deploy", "privilege_level": "standard"}, headers=admin
    ).json()

    activity = db_client.get(f"/api/assets/{web['id']}/activity", headers=viewer).json()
    assert (activity["open_alerts"], activity["total_alerts"]) == (4, 4)
    assert (activity["open_incidents"], activity["total_incidents"]) == (1, 1)
    latest = db_session.scalar(select(func.max(Event.timestamp)).where(Event.host == "web-01"))
    assert datetime.fromisoformat(activity["last_seen_at"]) == latest
    assert len(activity["recent_alerts"]) == 4

    listed = {
        a["hostname"]: a for a in db_client.get("/api/assets", headers=viewer).json()["items"]
    }
    assert listed["web-01"]["open_alerts"] == 4 and listed["web-01"]["last_seen_at"]
    assert (listed["idle-01"]["open_alerts"], listed["idle-01"]["last_seen_at"]) == (0, None)
    quiet = db_client.get(f"/api/assets/{idle['id']}/activity", headers=viewer).json()
    assert quiet["recent_alerts"] == quiet["incidents"] == [] and quiet["total_alerts"] == 0

    person = db_client.get(f"/api/identities/{deploy['id']}/activity", headers=viewer).json()
    # deploy is the actor of AUTH-001, AUTH-002 and PRIV-001, not of the account creation.
    assert person["total_alerts"] == 3 and person["total_incidents"] == 1
    missing = "00000000-0000-0000-0000-000000000000"
    assert db_client.get(f"/api/assets/{missing}/activity", headers=viewer).status_code == 404
