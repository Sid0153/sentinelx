"""Incident API: queue and filters, the workspace (why each alert is linked, ATT&CK, response,
risk), the timeline over HTTP, and analyst actions with their inputs, conflicts and audit."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.demo.scenarios import generate
from app.detection.library import Library
from app.models.user import Role, User
from tests.helpers import audit_entries, bearer, make_user

pytestmark = pytest.mark.integration

START = (datetime.now(UTC) - timedelta(hours=3)).replace(microsecond=0)


@pytest.fixture
def admin_user(db_session: Session) -> User:
    return make_user(db_session, Role.ADMIN, email="admin@example.com")


@pytest.fixture
def admin(admin_user: User) -> dict[str, str]:
    return bearer(admin_user)


@pytest.fixture
def analyst_user(db_session: Session) -> User:
    return make_user(db_session, Role.ANALYST, email="analyst@example.com")


@pytest.fixture
def analyst(analyst_user: User) -> dict[str, str]:
    return bearer(analyst_user)


@pytest.fixture
def viewer(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.VIEWER, email="viewer@example.com"))


def ingest(client: TestClient, admin: dict[str, str], lines: list[str]) -> dict[str, Any]:
    source = client.post(
        "/api/sources",
        json={"name": f"log {len(lines)} {lines[0][:19]}", "source_type": "linux_auth"},
        headers=admin,
    ).json()
    response = client.post(f"/api/ingest/{source['id']}", json={"records": lines}, headers=admin)
    assert response.status_code == 201, response.text
    return dict(response.json())


def the_incident(client: TestClient, headers: dict[str, str]) -> dict[str, Any]:
    page = client.get("/api/incidents", headers=headers).json()
    assert page["total"] == 1, page
    return dict(client.get(f"/api/incidents/{page['items'][0]['id']}", headers=headers).json())


def act(client: TestClient, headers: dict[str, str], path: str, **body: Any) -> Any:
    return client.post(path, json=body, headers=headers)


@pytest.fixture
def chain(db_client: TestClient, seeded_rules: Library, admin: dict[str, str]) -> dict[str, Any]:
    batch = ingest(db_client, admin, generate("multi_stage_attack", START))
    assert batch["incidents_created"] == 1
    return the_incident(db_client, admin)


# ---------- queue and workspace ----------


def test_the_workspace_explains_the_incident(
    db_client: TestClient, chain: dict[str, Any], viewer: dict[str, str]
) -> None:
    incident = the_incident(db_client, viewer)
    assert incident["number"] >= 1 and incident["status"] == "OPEN"
    assert incident["title"] == "Multi-stage activity on web-01 (deploy from 203.0.113.45)"
    assert "4 alert(s) from 4 rule(s)" in incident["summary"]
    assert incident["created_reason"].startswith("Multi-stage activity")
    reasons = {a["alert"]["rule_id"]: (a["link_strength"], a["reason"]) for a in incident["alerts"]}
    assert reasons["PRIV-001"][0] == "STRONG" and "host web-01" in reasons["PRIV-001"][1]
    assert reasons["ACCT-001"][0] == "MEDIUM" and "new kind of finding" in reasons["ACCT-001"][1]
    assert sum(f["points"] for f in incident["risk_breakdown"]) == incident["risk_score"]
    techniques = {t["technique"]: t for t in incident["mitre"]}
    assert {"T1110.001", "T1110", "T1078", "T1548.003", "T1136.001", "T1098.007"} <= set(techniques)
    assert techniques["T1078"]["url"] == "https://attack.mitre.org/techniques/T1078/"
    assert [g["rule_id"] for g in incident["response"]] == [
        "AUTH-001",
        "AUTH-002",
        "PRIV-001",
        "ACCT-001",
    ]
    assert incident["allowed_transitions"] == ["TRIAGED", "RESOLVED"]
    assert [a["kind"] for a in incident["activity"]][:2] == ["CREATED", "LINK"]
    # And the alert page points to it.
    alert_id = incident["alerts"][0]["alert"]["id"]
    alert = db_client.get(f"/api/alerts/{alert_id}", headers=viewer).json()
    assert (alert["incident_id"], alert["incident_number"]) == (incident["id"], incident["number"])


def test_queue_filters(
    db_client: TestClient, chain: dict[str, Any], analyst: dict[str, str], analyst_user: User
) -> None:
    def total(query: str) -> int:
        return int(db_client.get(f"/api/incidents{query}", headers=analyst).json()["total"])

    assert total("?status=OPEN") == 1 and total("?status=RESOLVED") == 0
    assert total("?host=WEB-01") == 1 and total("?host=db-01") == 0
    assert total("?username=svc-backup2") == 1
    assert total("?source_ip=203.0.113.45") == 1
    assert total("?assigned=unassigned") == 1 and total("?assigned=me") == 0
    act(
        db_client, analyst, f"/api/incidents/{chain['id']}/assign", assignee_id=str(analyst_user.id)
    )
    assert total("?assigned=me") == 1
    assert db_client.get("/api/incidents?severity=urgent", headers=analyst).status_code == 400
    assert db_client.get("/api/incidents?source_ip=nope", headers=analyst).status_code == 400


def test_the_timeline_pages_through_stored_rows(
    db_client: TestClient, chain: dict[str, Any], viewer: dict[str, str]
) -> None:
    path = f"/api/incidents/{chain['id']}/timeline"
    whole = db_client.get(f"{path}?limit=200", headers=viewer).json()
    assert whole["next_cursor"] is None
    items: list[dict[str, Any]] = []
    cursor = ""
    while True:
        page = db_client.get(f"{path}?limit=10{cursor}", headers=viewer).json()
        items += page["items"]
        if not page["next_cursor"]:
            break
        cursor = f"&cursor={page['next_cursor']}"
    assert [i["id"] for i in items] == [i["id"] for i in whole["items"]]
    first = whole["items"][0]
    assert first["kind"] == "event" and first["event"]["rules"] == ["AUTH-001", "AUTH-002"]
    assert db_client.get(f"{path}?cursor=garbage", headers=viewer).status_code == 400


# ---------- actions ----------


def test_an_incident_is_worked_through_to_closed(
    db_client: TestClient, db_session: Session, chain: dict[str, Any], analyst: dict[str, str]
) -> None:
    path = f"/api/incidents/{chain['id']}"
    for status in ("TRIAGED", "INVESTIGATING", "CONTAINED"):
        assert act(db_client, analyst, f"{path}/transition", status=status).status_code == 200
    assert act(db_client, analyst, f"{path}/transition", status="RESOLVED").status_code == 400
    resolved = act(
        db_client,
        analyst,
        f"{path}/transition",
        status="RESOLVED",
        disposition="confirmed_malicious",
        resolution="Account removed, deploy key rotated, host rebuilt",
    ).json()
    assert resolved["resolved_by"] == "analyst@example.com" and resolved["resolved_at"]
    closed = act(db_client, analyst, f"{path}/transition", status="CLOSED").json()
    assert closed["status"] == "CLOSED" and closed["allowed_transitions"] == []
    assert closed["disposition"] == "confirmed_malicious"
    assert act(db_client, analyst, f"{path}/notes", body="late").status_code == 409
    changes = audit_entries(db_session, "INCIDENT_STATUS_CHANGED")
    assert [(e.details["from"], e.details["to"]) for e in changes][-2:] == [
        ("CONTAINED", "RESOLVED"),
        ("RESOLVED", "CLOSED"),
    ]


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ({"status": "CONTAINED"}, 409),  # not investigating yet
        ({"status": "OPEN"}, 409),
        ({"status": "TRIAGED", "disposition": "benign_expected"}, 400),
        ({"status": "DONE"}, 422),
    ],
)
def test_transitions_the_workflow_does_not_allow(
    db_client: TestClient, chain: dict[str, Any], analyst: dict[str, str], body: Any, status: int
) -> None:
    response = act(db_client, analyst, f"/api/incidents/{chain['id']}/transition", **body)
    assert response.status_code == status


def test_assignment_notes_evidence_and_rename(
    db_client: TestClient,
    db_session: Session,
    chain: dict[str, Any],
    analyst: dict[str, str],
    analyst_user: User,
    viewer: dict[str, str],
) -> None:
    path = f"/api/incidents/{chain['id']}"
    assignable = {
        u["email"] for u in db_client.get("/api/incidents/assignees", headers=analyst).json()
    }
    assert assignable == {"admin@example.com", "analyst@example.com"}  # no viewers
    viewer_id = db_session.scalar(select(User.id).where(User.email == "viewer@example.com"))
    assert act(db_client, analyst, f"{path}/assign", assignee_id=str(viewer_id)).status_code == 400
    assigned = act(db_client, analyst, f"{path}/assign", assignee_id=str(analyst_user.id)).json()
    assert assigned["assigned_to"]["email"] == "analyst@example.com"

    note = act(db_client, analyst, f"{path}/notes", body="Source is a VPS; check other hosts.")
    assert note.status_code == 201 and note.json()["author"] == "analyst@example.com"
    (entry,) = audit_entries(db_session, "INCIDENT_NOTE_ADDED")
    assert "VPS" not in str(entry.details)  # the note text stays out of the audit log

    event_id = db_client.get(f"{path}/timeline?limit=1", headers=analyst).json()["items"][0]["id"]
    pinned = act(
        db_client,
        analyst,
        f"{path}/evidence",
        event_id=event_id,
        tag="initial_access",
        comment="first try",
    )
    assert pinned.status_code == 201
    assert [p["tag"] for p in pinned.json()["evidence"]] == ["initial_access"]
    again = act(db_client, analyst, f"{path}/evidence", event_id=event_id)
    assert again.status_code == 409
    unpinned = act(db_client, analyst, f"{path}/evidence", event_id=event_id, action="UNPIN")
    assert unpinned.json()["evidence"] == []

    renamed = db_client.patch(path, json={"title": "Web-01 takeover"}, headers=analyst).json()
    assert renamed["title"] == "Web-01 takeover" and renamed["title_edited"]
    kinds = [a["kind"] for a in renamed["activity"]]
    assert {"ASSIGN", "NOTE", "EVIDENCE", "RENAME"} <= set(kinds)
    assert db_client.patch(path, json={"title": "x"}, headers=viewer).status_code == 403


def test_manual_link_unlink_and_escalation(
    db_client: TestClient,
    db_session: Session,
    seeded_rules: Library,
    admin: dict[str, str],
    analyst: dict[str, str],
) -> None:
    ingest(db_client, admin, generate("brute_force", START, host="db-07", source_ip="198.51.100.9"))
    (standalone,) = db_client.get("/api/alerts?host=db-07", headers=analyst).json()["items"]
    escalated = act(
        db_client,
        analyst,
        f"/api/alerts/{standalone['id']}/escalate",
        reason="Targets our DB server",
    )
    assert escalated.status_code == 201
    incident = escalated.json()
    assert incident["alerts"][0]["link_strength"] == "MANUAL"
    assert incident["created_reason"].startswith("Escalated by analyst@example.com")
    again = act(db_client, analyst, f"/api/alerts/{standalone['id']}/escalate", reason="twice")
    assert again.status_code == 409

    ingest(db_client, admin, generate("password_spray", START))
    (spray,) = db_client.get("/api/alerts?rule_id=AUTH-003", headers=analyst).json()["items"]
    path = f"/api/incidents/{incident['id']}"
    linked = act(db_client, analyst, f"{path}/alerts", alert_id=spray["id"], reason="same campaign")
    assert linked.status_code == 201 and linked.json()["alert_count"] == 2
    unlinked = act(
        db_client, analyst, f"{path}/alerts/{spray['id']}/unlink", reason="different actor"
    ).json()
    assert unlinked["alert_count"] == 1
    assert len(audit_entries(db_session, "INCIDENT_CREATED")) == 1
    assert len(audit_entries(db_session, "INCIDENT_ALERT_LINKED")) == 1
    assert len(audit_entries(db_session, "INCIDENT_ALERT_UNLINKED")) == 1


def test_viewers_can_read_but_not_act(
    db_client: TestClient, chain: dict[str, Any], viewer: dict[str, str]
) -> None:
    path = f"/api/incidents/{chain['id']}"
    assert db_client.get(path, headers=viewer).status_code == 200
    assert act(db_client, viewer, f"{path}/transition", status="TRIAGED").status_code == 403
    assert act(db_client, viewer, f"{path}/notes", body="hello").status_code == 403


# ---------- settings ----------


def test_admins_tune_the_correlation_windows(
    db_client: TestClient, db_session: Session, admin: dict[str, str], analyst: dict[str, str]
) -> None:
    assert db_client.get("/api/settings", headers=admin).json() == {
        "correlation_window_minutes": 120,
        "sequence_window_minutes": 30,
    }
    changed = db_client.patch(
        "/api/settings", json={"correlation_window_minutes": 60}, headers=admin
    )
    assert changed.json()["correlation_window_minutes"] == 60
    for body, status in (
        ({"correlation_window_minutes": 5}, 422),
        ({"sequence_window_minutes": 90}, 400),  # longer than the correlation window
        ({"internal_networks": "0.0.0.0/0"}, 422),
        ({}, 400),
    ):
        assert db_client.patch("/api/settings", json=body, headers=admin).status_code == status
    assert db_client.get("/api/settings", headers=analyst).status_code == 403
    (entry,) = audit_entries(db_session, "SETTINGS_CHANGED")
    assert entry.details["changes"] == {"correlation_window_minutes": {"from": 120, "to": 60}}
