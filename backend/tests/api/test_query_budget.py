"""Phase 14: list endpoints do a fixed number of SQL statements, however many rows they return.

An N+1 query (one extra statement per row, e.g. looking up each item's owner) is invisible on
small test data and slow on real data. Each list endpoint is measured on a small dataset and
on a larger one; the statement count must not grow. The session's identity map is cleared
before every measured request, as in production where each request has a fresh session
(otherwise `db.get()` could answer from memory and hide per-row lookups).
"""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, event
from sqlalchemy.orm import Session

from app.demo.scenarios import brute_force, multi_stage_attack, password_spray
from app.detection.library import Library
from app.models.user import Role
from tests.helpers import bearer, make_user

pytestmark = pytest.mark.integration

START = (datetime.now(UTC) - timedelta(hours=20)).replace(microsecond=0)
HUNT = {
    "kind": "query",
    "query": {
        "time_range": {"last": "7d"},
        "filters": [{"field": "source_ip", "op": "eq", "value": "203.0.113.41"}],
    },
}

# Every list (and list-like summary) a page loads. Detail routes return one record.
LIST_ROUTES = [
    "/api/users",
    "/api/audit",
    "/api/assets",
    "/api/identities",
    "/api/sources",
    "/api/ingest/batches",
    "/api/events",
    "/api/detections/runs",
    "/api/detections",
    "/api/detections/metrics",
    "/api/mitre/coverage",
    "/api/alerts",
    "/api/alerts/groups?by=host",
    "/api/alerts/groups?by=rule",
    "/api/incidents",
    "/api/incidents/assignees",
    "/api/dashboard/summary",
    "/api/dashboard/trends",
    "/api/hunt/saved",
]


@contextmanager
def statements(engine: Engine) -> Iterator[list[str]]:
    seen: list[str] = []

    def record(*args: Any) -> None:
        seen.append(args[2])  # (conn, cursor, statement, parameters, context, executemany)

    event.listen(engine, "before_cursor_execute", record)
    try:
        yield seen
    finally:
        event.remove(engine, "before_cursor_execute", record)


def add_round(client: TestClient, db: Session, admin: dict[str, str], n: int) -> None:
    """One more of everything: an attack on another host (alerts, an incident), a spray, an
    asset, an identity, a user and a shared saved hunt by that user."""
    at = START + timedelta(hours=4 * n)  # far apart: separate incidents
    source = client.post(
        "/api/sources", json={"name": f"auth {n}", "source_type": "linux_auth"}, headers=admin
    ).json()
    lines = multi_stage_attack(at, host=f"web-{n:02d}", source_ip=f"203.0.113.{40 + n}")
    lines += password_spray(at + timedelta(minutes=30), host=f"web-{n:02d}")
    batch = client.post(f"/api/ingest/{source['id']}", json={"records": lines}, headers=admin)
    assert batch.status_code == 201, batch.text
    asset = {
        "hostname": f"web-{n:02d}",
        "asset_type": "server",
        "environment": "production",
        "criticality": "high",
    }
    assert client.post("/api/assets", json=asset, headers=admin).status_code == 201
    identity = {"username": f"svc-{n:02d}", "privilege_level": "service"}
    assert client.post("/api/identities", json=identity, headers=admin).status_code == 201
    owner = bearer(make_user(db, Role.ANALYST, email=f"hunter{n}@example.com"))
    saved = {"name": f"hunt {n}", "definition": HUNT, "shared": True}
    assert client.post("/api/hunt/saved", json=saved, headers=owner).status_code == 201


def measure(
    client: TestClient, db: Session, engine: Engine, headers: dict[str, str]
) -> dict[str, int]:
    counts = {}
    for route in LIST_ROUTES:
        db.expunge_all()
        with statements(engine) as seen:
            response = client.get(route, headers=headers)
        assert response.status_code == 200, (route, response.text)
        counts[route] = len(seen)
    return counts


def test_list_endpoints_do_not_query_per_row(
    db_client: TestClient, db_session: Session, db_engine: Engine, seeded_rules: Library
) -> None:
    admin_user = make_user(db_session, Role.ADMIN, email="admin@example.com")
    admin = bearer(admin_user)
    add_round(db_client, db_session, admin, 1)
    small = measure(db_client, db_session, db_engine, admin)
    for n in range(2, 6):
        add_round(db_client, db_session, admin, n)
    large = measure(db_client, db_session, db_engine, admin)

    # The larger dataset really is larger where it matters.
    incidents = db_client.get("/api/incidents", headers=admin).json()
    assert incidents["total"] == 5
    assert len(db_client.get("/api/hunt/saved", headers=admin).json()) == 5

    grew = {r: (small[r], large[r]) for r in LIST_ROUTES if large[r] > small[r]}
    assert grew == {}, f"statements per request grew with the data (small, large): {grew}"


def test_list_activity_matches_each_records_own_activity(
    db_client: TestClient, db_session: Session, seeded_rules: Library
) -> None:
    """The one-statement list figures equal the per-record activity endpoint's, row by row."""
    admin = bearer(make_user(db_session, Role.ADMIN, email="admin@example.com"))
    for n in range(1, 4):
        add_round(db_client, db_session, admin, n)
    # An asset and an identity nothing refers to: zero alerts, never seen.
    idle = {
        "hostname": "idle-01",
        "asset_type": "server",
        "environment": "test",
        "criticality": "low",
    }
    assert db_client.post("/api/assets", json=idle, headers=admin).status_code == 201
    # The account the attacks use (alerts and events), registered after them.
    deploy = {"username": "deploy", "privilege_level": "standard"}
    assert db_client.post("/api/identities", json=deploy, headers=admin).status_code == 201

    # Assets web-01..03 and idle-01; identities svc-01..03 (never in a log) and deploy.
    for kind in ("assets", "identities"):
        listed = db_client.get(f"/api/{kind}", headers=admin).json()["items"]
        assert len(listed) == 4
        figures = set()
        for row in listed:
            own = db_client.get(f"/api/{kind}/{row['id']}/activity", headers=admin).json()
            assert (row["open_alerts"], row["last_seen_at"]) == (
                own["open_alerts"],
                own["last_seen_at"],
            ), (kind, row)
            figures.add((row["open_alerts"] > 0, row["last_seen_at"] is not None))
        assert figures == {(True, True), (False, False)}, (kind, figures)  # both shapes checked


def test_detail_pages_do_not_query_per_item(
    db_client: TestClient, db_session: Session, db_engine: Engine, seeded_rules: Library
) -> None:
    """An incident with five alerts costs what one with a single alert costs; a long timeline
    page and a long evidence page cost what a short one costs."""
    admin = bearer(make_user(db_session, Role.ADMIN, email="admin@example.com"))
    source = db_client.post(
        "/api/sources", json={"name": "db hosts", "source_type": "linux_auth"}, headers=admin
    ).json()
    lines: list[str] = []
    for n in range(5):  # five unrelated brute forces: five standalone alerts
        lines += brute_force(
            START + timedelta(hours=3 * n), host=f"db-{n:02d}", source_ip=f"198.51.100.{10 + n}"
        )
    batch = db_client.post(f"/api/ingest/{source['id']}", json={"records": lines}, headers=admin)
    assert batch.status_code == 201 and batch.json()["incidents_created"] == 0, batch.text
    alerts = db_client.get("/api/alerts?limit=200", headers=admin).json()["items"]
    assert len(alerts) == 5

    def cost(url: str) -> int:
        db_session.expunge_all()
        with statements(db_engine) as seen:
            assert db_client.get(url, headers=admin).status_code == 200
        return len(seen)

    escalated = db_client.post(
        f"/api/alerts/{alerts[0]['id']}/escalate", json={"reason": "one alert"}, headers=admin
    )
    assert escalated.status_code == 201, escalated.text
    path = f"/api/incidents/{escalated.json()['id']}"
    one_alert = cost(path)
    for alert in alerts[1:]:
        linked = db_client.post(
            f"{path}/alerts", json={"alert_id": alert["id"], "reason": "same"}, headers=admin
        )
        assert linked.status_code == 201, linked.text
    assert db_client.get(path, headers=admin).json()["alert_count"] == 5
    assert cost(path) == one_alert, "incident detail cost grew with its alerts"

    assert cost(f"{path}/timeline?limit=2") == cost(f"{path}/timeline?limit=200")
    busiest = max(alerts, key=lambda a: a["event_count"])
    assert busiest["event_count"] >= 5
    evidence = f"/api/alerts/{busiest['id']}/events"
    assert cost(f"{evidence}?limit=2") == cost(f"{evidence}?limit=200")


# Lists returned without a `limit`, and what keeps each one small.
NATURALLY_BOUNDED = {
    "/api/alerts/groups": "at most MAX_GROUPS (100) groups",
    "/api/detections": "one entry per rule in the shipped library",
    "/api/mitre/techniques": "the techniques the library maps",
    "/api/incidents/assignees": "active analysts and admins (staff accounts)",
    "/api/hunt/saved": "at most MAX_SAVED_PER_USER per user (own and shared)",
    "/api/hunt/templates": "the reviewed templates shipped with the app",
}


def test_every_list_response_is_bounded(app: Any) -> None:
    """§33 bounded API responses: a list or page comes with a capped `limit`, or is listed
    above with the reason it cannot grow without bound."""
    spec = app.openapi()
    problems = []
    for path, operations in spec["paths"].items():
        get = operations.get("get")
        if not get:
            continue
        schema = get["responses"]["200"]["content"]["application/json"]["schema"]
        ref = schema.get("$ref", "")
        is_list = schema.get("type") == "array" or ref.split("/")[-1].startswith("Page")
        if not is_list or path in NATURALLY_BOUNDED:
            continue
        limit = [p for p in get.get("parameters", []) if p["name"] == "limit"]
        if not limit or not limit[0]["schema"].get("maximum"):
            problems.append(path)
    assert problems == []
    assert set(NATURALLY_BOUNDED) <= set(spec["paths"])  # no stale entries
