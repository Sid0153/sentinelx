"""Alert API: the queue (order, filters), one alert's investigation data, its evidence, and
the workflow through HTTP (roles, required inputs, conflicts, audit, timestamps)."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.demo.scenarios import generate
from app.detection.library import Library
from app.models.context import Identity
from app.models.user import Role
from tests.helpers import audit_entries, bearer, make_asset, make_user

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


def ingest(client: TestClient, admin: dict[str, str], *scenarios: str) -> None:
    source = client.post(
        "/api/sources", json={"name": "web-01 auth.log", "source_type": "linux_auth"}, headers=admin
    ).json()
    for name in scenarios:
        response = client.post(
            f"/api/ingest/{source['id']}", json={"records": generate(name, START)}, headers=admin
        )
        assert response.status_code == 201, response.text


def queue(client: TestClient, headers: dict[str, str], query: str = "") -> dict[str, Any]:
    response = client.get(f"/api/alerts{query}", headers=headers)
    assert response.status_code == 200, response.text
    return dict(response.json())


def only(client: TestClient, headers: dict[str, str], rule_id: str) -> dict[str, Any]:
    (item,) = queue(client, headers, f"?rule_id={rule_id}")["items"]
    return dict(item)


def move(client: TestClient, headers: dict[str, str], alert_id: str, **body: Any) -> Any:
    return client.post(f"/api/alerts/{alert_id}/transition", json=body, headers=headers)


# ---------- queue ----------


def test_the_queue_is_ordered_by_priority(
    db_client: TestClient, seeded_rules: Library, admin: dict[str, str], viewer: dict[str, str]
) -> None:
    ingest(db_client, admin, "brute_force_success", "password_spray")
    page = queue(db_client, viewer)
    assert page["total"] == 3
    scores = [a["priority_score"] for a in page["items"]]
    assert scores == sorted(scores, reverse=True)
    assert page["items"][0]["rule_id"] == "AUTH-002"  # high severity ranks first
    recent = queue(db_client, viewer, "?sort=recent")["items"]
    times = [a["last_event_at"] for a in recent]
    assert times == sorted(times, reverse=True)


def test_queue_filters(
    db_client: TestClient, seeded_rules: Library, admin: dict[str, str], viewer: dict[str, str]
) -> None:
    ingest(db_client, admin, "brute_force_success", "password_spray")
    assert queue(db_client, viewer, "?severity=high")["total"] == 1
    assert queue(db_client, viewer, "?source_ip=198.51.100.23")["total"] == 1  # the spray
    assert queue(db_client, viewer, "?username=ROOT")["total"] == 2  # case-insensitive
    assert queue(db_client, viewer, "?status=NEW&status=TRIAGED")["total"] == 3
    assert queue(db_client, viewer, "?status=RESOLVED")["total"] == 0
    later = (datetime.now(UTC) + timedelta(hours=1)).isoformat().replace("+", "%2B")
    assert queue(db_client, viewer, f"?since={later}")["total"] == 0
    assert queue(db_client, viewer, "?limit=1&offset=1")["items"][0]["rule_id"] != "AUTH-002"


@pytest.mark.parametrize(
    ("query", "status"),
    [
        ("?band=urgent", 400),
        ("?source_ip=not-an-ip", 400),
        ("?status=OPEN", 422),
        ("?sort=random", 422),
        ("?rule_id=auth-1", 422),
    ],
)
def test_bad_queue_filters_are_refused(
    db_client: TestClient, viewer: dict[str, str], query: str, status: int
) -> None:
    assert db_client.get(f"/api/alerts{query}", headers=viewer).status_code == status


# ---------- one alert ----------


def test_an_alert_explains_itself(
    db_client: TestClient,
    db_session: Session,
    seeded_rules: Library,
    admin: dict[str, str],
    viewer: dict[str, str],
) -> None:
    make_asset(db_session, "web-01", criticality="high")
    db_session.add(Identity(username="root", privilege_level="privileged"))
    db_session.flush()
    ingest(db_client, admin, "brute_force_success")
    alert = db_client.get(
        f"/api/alerts/{only(db_client, viewer, 'AUTH-002')['id']}", headers=viewer
    ).json()
    # What and why, from the evidence.
    assert alert["explanation"].startswith('12 failed logons for "root" on web-01')
    assert alert["description"] and alert["investigation"] and alert["response"]
    assert alert["facts"]["count"] == 13
    # Entities and their inventory context.
    assert (alert["host"], alert["username"], alert["source_ip"]) == (
        "web-01",
        "root",
        "203.0.113.45",
    )
    assert (alert["asset_hostname"], alert["identity_username"]) == ("web-01", "root")
    # A priority anyone can recompute.
    assert sum(f["points"] for f in alert["priority_breakdown"]) == alert["priority_score"]
    assert alert["risk_model_version"] == "1"
    # ATT&CK, with links.
    assert {m["technique"] for m in alert["mitre"]} == {"T1110", "T1078"}
    assert all(m["url"].startswith("https://attack.mitre.org/techniques/") for m in alert["mitre"])
    # Workflow state, related activity, correlation (Phase 8).
    assert alert["status"] == "NEW"
    assert alert["allowed_transitions"] == ["TRIAGED", "IN_PROGRESS", "FALSE_POSITIVE"]
    assert [r["rule_id"] for r in alert["related"]] == ["AUTH-001"]
    assert set(alert["related"][0]["shared"]) == {
        "host web-01",
        "user root",
        "source 203.0.113.45",
    }
    assert alert["incident_id"] is None and alert["activity"] == []


def test_evidence_comes_with_its_raw_records(
    db_client: TestClient, seeded_rules: Library, admin: dict[str, str], viewer: dict[str, str]
) -> None:
    ingest(db_client, admin, "brute_force")
    alert = only(db_client, viewer, "AUTH-001")
    page = db_client.get(f"/api/alerts/{alert['id']}/events?limit=5", headers=viewer).json()
    assert page["total"] == 12 and len(page["items"]) == 5
    first = page["items"][0]
    # Sent through the ingest API, not demo-ingest: real data as far as SentinelX knows.
    assert first["event_outcome"] == "failure" and not first["simulated"]
    assert "Failed password for root from 203.0.113.45" in first["raw_text"]
    times = [e["timestamp"] for e in page["items"]]
    assert times == sorted(times)
    # From the event, back to the alerts citing it.
    event = db_client.get(f"/api/events/{first['id']}", headers=viewer).json()
    assert [a["id"] for a in event["alerts"]] == [alert["id"]]


def test_unknown_alerts_are_404(db_client: TestClient, viewer: dict[str, str]) -> None:
    missing = "00000000-0000-0000-0000-000000000000"
    for path in (f"/api/alerts/{missing}", f"/api/alerts/{missing}/events"):
        assert db_client.get(path, headers=viewer).status_code == 404


# ---------- workflow ----------


def test_an_alert_is_worked_to_resolution_and_audited(
    db_client: TestClient,
    db_session: Session,
    seeded_rules: Library,
    admin: dict[str, str],
    analyst: dict[str, str],
) -> None:
    ingest(db_client, admin, "brute_force")
    alert_id = only(db_client, analyst, "AUTH-001")["id"]
    triaged = move(db_client, analyst, alert_id, status="TRIAGED").json()
    assert triaged["status"] == "TRIAGED" and triaged["triaged_at"]
    move(db_client, analyst, alert_id, status="IN_PROGRESS")
    done = move(
        db_client,
        analyst,
        alert_id,
        status="RESOLVED",
        disposition="confirmed_malicious",
        reason="Source blocked at the firewall",
    ).json()
    assert done["status"] == "RESOLVED" and done["disposition"] == "confirmed_malicious"
    assert done["resolved_by"] == "analyst@example.com" and done["resolved_at"]
    assert done["triaged_at"] == triaged["triaged_at"]  # set once
    assert done["allowed_transitions"] == ["TRIAGED"]
    assert [(a["from_status"], a["to_status"]) for a in done["activity"]] == [
        ("NEW", "TRIAGED"),
        ("TRIAGED", "IN_PROGRESS"),
        ("IN_PROGRESS", "RESOLVED"),
    ]
    assert done["activity"][2]["actor"] == "analyst@example.com"
    entries = audit_entries(db_session, "ALERT_STATUS_CHANGED")
    assert len(entries) == 3 and entries[2].entity_id == alert_id
    assert entries[2].details["reason"] == "Source blocked at the firewall"


def test_false_positive_and_reopen_need_a_reason(
    db_client: TestClient, seeded_rules: Library, admin: dict[str, str], analyst: dict[str, str]
) -> None:
    ingest(db_client, admin, "brute_force")
    alert_id = only(db_client, analyst, "AUTH-001")["id"]
    assert move(db_client, analyst, alert_id, status="FALSE_POSITIVE").status_code == 400
    assert (
        move(db_client, analyst, alert_id, status="FALSE_POSITIVE", reason="  ").status_code == 400
    )
    fp = move(
        db_client, analyst, alert_id, status="FALSE_POSITIVE", reason="Our vulnerability scanner"
    ).json()
    assert fp["status"] == "FALSE_POSITIVE" and fp["disposition"] is None
    assert fp["status_note"] == "Our vulnerability scanner"
    assert move(db_client, analyst, alert_id, status="TRIAGED").status_code == 400
    reopened = move(
        db_client, analyst, alert_id, status="TRIAGED", reason="Scanner was not scheduled then"
    ).json()
    assert reopened["status"] == "TRIAGED" and reopened["resolved_at"] is None


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ({"status": "RESOLVED", "disposition": "confirmed_malicious"}, 409),  # not triaged
        ({"status": "NEW"}, 409),  # already NEW
        ({"status": "TRIAGED", "disposition": "benign_expected"}, 400),
        ({"status": "CLOSED"}, 422),
        ({"status": "TRIAGED", "assignee": "bob"}, 422),
    ],
)
def test_transitions_the_workflow_does_not_allow(
    db_client: TestClient,
    seeded_rules: Library,
    admin: dict[str, str],
    analyst: dict[str, str],
    body: dict[str, Any],
    status: int,
) -> None:
    ingest(db_client, admin, "brute_force")
    alert_id = only(db_client, analyst, "AUTH-001")["id"]
    assert move(db_client, analyst, alert_id, **body).status_code == status


def test_a_closed_alert_cannot_be_reopened_once_newer_activity_has_its_own_alert(
    db_client: TestClient, seeded_rules: Library, admin: dict[str, str], analyst: dict[str, str]
) -> None:
    ingest(db_client, admin, "brute_force")
    old = only(db_client, analyst, "AUTH-001")["id"]
    move(db_client, analyst, old, status="FALSE_POSITIVE", reason="Looked like our scanner")
    # The same activity again, later: a new alert pointing to the closed one.
    source = db_client.post(
        "/api/sources", json={"name": "web-01 again", "source_type": "linux_auth"}, headers=admin
    ).json()
    lines = generate("brute_force", START + timedelta(minutes=20))
    db_client.post(f"/api/ingest/{source['id']}", json={"records": lines}, headers=admin)
    new = only(db_client, analyst, "AUTH-001&status=NEW")
    assert (
        db_client.get(f"/api/alerts/{new['id']}", headers=analyst).json()["previous_alert_id"]
        == old
    )
    response = move(db_client, analyst, old, status="TRIAGED", reason="It was not the scanner")
    assert response.status_code == 409
    assert new["id"] in response.json()["error"]["message"]


def test_viewers_cannot_change_alerts(
    db_client: TestClient, seeded_rules: Library, admin: dict[str, str], viewer: dict[str, str]
) -> None:
    ingest(db_client, admin, "brute_force")
    alert_id = only(db_client, viewer, "AUTH-001")["id"]
    assert move(db_client, viewer, alert_id, status="TRIAGED").status_code == 403


def test_the_batch_report_counts_alerts(
    db_client: TestClient, seeded_rules: Library, admin: dict[str, str]
) -> None:
    source = db_client.post(
        "/api/sources", json={"name": "web-01", "source_type": "linux_auth"}, headers=admin
    ).json()
    batch = db_client.post(
        f"/api/ingest/{source['id']}",
        json={"records": generate("brute_force_success", START)},
        headers=admin,
    ).json()
    assert (batch["detection_count"], batch["alerts_created"], batch["alerts_updated"]) == (
        2,
        2,
        0,
    )
