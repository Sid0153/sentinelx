"""Phase 11: detection metrics, implemented ATT&CK coverage, and the inventory context shown
next to alerts and incidents. Metrics are checked against alerts whose outcomes and times are
set to known values, so every number can be worked out by hand."""

import uuid
from datetime import UTC, datetime, timedelta
from statistics import median
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.demo.scenarios import generate
from app.detection.library import Library
from app.models.alert import Alert
from app.models.user import Role
from tests.helpers import bearer, make_user

pytestmark = pytest.mark.integration

START = (datetime.now(UTC) - timedelta(hours=3)).replace(microsecond=0)


@pytest.fixture
def admin(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.ADMIN, email="admin@example.com"))


@pytest.fixture
def viewer(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.VIEWER, email="viewer@example.com"))


def ingest(
    client: TestClient, admin: dict[str, str], lines: list[str], kind: str = "linux_auth"
) -> None:
    source = client.post(
        "/api/sources",
        json={"name": f"log {uuid.uuid4().hex[:8]}", "source_type": kind},
        headers=admin,
    ).json()
    response = client.post(f"/api/ingest/{source['id']}", json={"records": lines}, headers=admin)
    assert response.status_code == 201, response.text


def get(client: TestClient, headers: dict[str, str], path: str) -> dict[str, Any]:
    response = client.get(path, headers=headers)
    assert response.status_code == 200, response.text
    return dict(response.json())


# ---------- detection metrics ----------

# (status, disposition, seconds to triage, seconds to close) for four AUTH-001 alerts.
OUTCOMES = [
    ("FALSE_POSITIVE", None, 60, 600),
    ("RESOLVED", "confirmed_malicious", 120, 1800),
    ("RESOLVED", "benign_expected", 300, 3600),
    ("NEW", None, None, None),
]


def test_rule_metrics_count_outcomes_and_resolution_times(
    db_client: TestClient,
    db_session: Session,
    seeded_rules: Library,
    admin: dict[str, str],
    viewer: dict[str, str],
) -> None:
    for i in range(4):  # four sources: four AUTH-001 alerts
        ingest(db_client, admin, generate("brute_force", START, source_ip=f"203.0.113.{10 + i}"))
    alerts = list(
        db_session.scalars(select(Alert).where(Alert.rule_id == "AUTH-001").order_by(Alert.id))
    )
    assert len(alerts) == 4
    created = START + timedelta(minutes=5)
    for alert, (status, disposition, triage, close) in zip(alerts, OUTCOMES, strict=True):
        db_session.execute(
            update(Alert)
            .where(Alert.id == alert.id)
            .values(
                status=status,
                disposition=disposition,
                created_at=created,
                triaged_at=created + timedelta(seconds=triage) if triage else None,
                resolved_at=created + timedelta(seconds=close) if close else None,
                status_note="fixture" if status == "FALSE_POSITIVE" else None,
            )
        )
    db_session.flush()

    items = {m["rule_id"]: m for m in get(db_client, viewer, "/api/detections/metrics")["items"]}
    auth = items["AUTH-001"]
    assert (auth["alerts"], auth["open"], auth["closed"]) == (4, 1, 3)
    assert (auth["confirmed"], auth["benign"], auth["false_positives"]) == (1, 1, 1)
    assert auth["false_positive_rate"] == round(1 / 3, 3)
    assert auth["median_triage_seconds"] == median([60, 120, 300])
    assert auth["median_resolve_seconds"] == median([600, 1800, 3600])
    assert auth["match_count"] >= 4 and auth["last_match_at"]
    # Every rule is listed; one without alerts shows zeros and no rate (not 0 %).
    quiet = items["NET-001"]
    assert (quiet["alerts"], quiet["closed"], quiet["false_positive_rate"]) == (0, 0, None)
    assert quiet["median_resolve_seconds"] is None
    assert set(items) == set(seeded_rules.rules)

    # Alerts created before the period do not count.
    db_session.execute(
        update(Alert)
        .where(Alert.rule_id == "AUTH-001")
        .values(created_at=START - timedelta(days=40))
    )
    db_session.flush()
    late = {m["rule_id"]: m for m in get(db_client, viewer, "/api/detections/metrics")["items"]}
    assert late["AUTH-001"]["alerts"] == 0
    longer = get(db_client, viewer, "/api/detections/metrics?days=60")["items"]
    assert {m["rule_id"]: m for m in longer}["AUTH-001"]["alerts"] == 4


@pytest.mark.parametrize("days", [0, 366, "x"])
def test_the_metrics_period_is_bounded(
    db_client: TestClient, viewer: dict[str, str], days: object
) -> None:
    for path in ("/api/detections/metrics", "/api/mitre/coverage"):
        assert db_client.get(f"{path}?days={days}", headers=viewer).status_code == 422


# ---------- implemented coverage ----------


def test_coverage_shows_every_tactic_and_only_implemented_techniques(
    db_client: TestClient, seeded_rules: Library, admin: dict[str, str], viewer: dict[str, str]
) -> None:
    ingest(db_client, admin, generate("brute_force", START))
    ingest(db_client, admin, generate("suspicious_process", START), kind="windows_security")
    data = get(db_client, viewer, "/api/mitre/coverage")
    assert data["label"] == "Implemented coverage"
    assert data["attack_version"] == "19.2"
    tactics = [t["name"] for t in data["tactics"]]
    assert tactics[:3] == ["Reconnaissance", "Resource Development", "Initial Access"]
    assert len(tactics) == 15 and tactics[-1] == "Impact"
    by_tactic = {t["name"]: t for t in data["tactics"]}
    assert by_tactic["Exfiltration"]["techniques"] == []  # a gap is shown, not hidden
    assert by_tactic["Exfiltration"]["active"] is False
    assert "T1110.001" in by_tactic["Credential Access"]["techniques"]

    techniques = {t["technique_id"]: t for t in data["techniques"]}
    mapped = set().union(*(r.techniques() for r in seeded_rules.rules.values()))
    assert set(techniques) == mapped  # nothing beyond what the rules map
    guessing = techniques["T1110.001"]
    assert {r["rule_id"] for r in guessing["rules"]} == {"AUTH-001", "AUTH-005"}
    assert guessing["alerts"] == 1 and guessing["last_triggered_at"]
    # An alert counts for the techniques of its own indicator only (PROC-001).
    assert techniques["T1059.001"]["alerts"] == 1  # encoded PowerShell
    assert techniques["T1105"]["alerts"] == 0  # download indicators did not fire
    summary = data["summary"]
    assert summary["tactics_total"] == 15
    assert summary["rules_in_library"] == summary["rules_enabled"] == len(seeded_rules.rules)
    assert summary["techniques_covered"] == len(mapped)
    assert summary["categories"]["authentication"] >= 5


def test_a_disabled_rule_does_not_count_as_coverage(
    db_client: TestClient, seeded_rules: Library, admin: dict[str, str], viewer: dict[str, str]
) -> None:
    response = db_client.patch(
        "/api/detections/NET-001",
        json={"enabled": False, "reason": "noisy during the migration"},
        headers=admin,
    )
    assert response.status_code == 200, response.text
    data = get(db_client, viewer, "/api/mitre/coverage")
    scanning = {t["technique_id"]: t for t in data["techniques"]}["T1046"]
    assert scanning["active"] is False and scanning["rules"][0]["enabled"] is False
    assert {t["name"]: t for t in data["tactics"]}["Discovery"]["active"] is False
    assert data["summary"]["rules_enabled"] == data["summary"]["rules_in_library"] - 1


# ---------- inventory context ----------


def test_alerts_and_incidents_show_the_inventory_behind_their_entities(
    db_client: TestClient, seeded_rules: Library, admin: dict[str, str], viewer: dict[str, str]
) -> None:
    db_client.post(
        "/api/assets",
        json={
            "hostname": "web-01.corp.example",  # matched by its short name
            "asset_type": "server",
            "environment": "production",
            "criticality": "critical",
            "owner": "Platform team",
        },
        headers=admin,
    )
    db_client.post(
        "/api/identities",
        json={"username": "root", "privilege_level": "privileged", "department": "IT"},
        headers=admin,
    )
    ingest(db_client, admin, generate("privilege_escalation", START))
    page = get(db_client, viewer, "/api/alerts?rule_id=PRIV-001")
    deploy = next(a for a in page["items"] if a["username"] == "deploy")
    detail = get(db_client, viewer, f"/api/alerts/{deploy['id']}")
    inventory = detail["inventory"]
    [asset] = inventory["assets"]
    assert (asset["hostname"], asset["criticality"], asset["owner"]) == (
        "web-01.corp.example",
        "critical",
        "Platform team",
    )
    [root] = inventory["identities"]
    assert (root["username"], root["privilege_level"], root["roles"]) == (
        "root",
        "privileged",
        ["target"],
    )
    assert inventory["unknown_accounts"] == ["deploy"]  # the actor is not in the inventory
    assert inventory["unknown_hosts"] == []
    assert {"factor": "identity", "value": "root privileged (target account)", "points": 10} in (
        detail["priority_breakdown"]
    )

    # A brute force that succeeds (high severity) opens an incident on the same host.
    ingest(db_client, admin, generate("brute_force_success", START + timedelta(minutes=30)))
    [incident] = get(db_client, viewer, "/api/incidents")["items"]
    context = get(db_client, viewer, f"/api/incidents/{incident['id']}")["inventory"]
    assert [a["hostname"] for a in context["assets"]] == ["web-01.corp.example"]
    # root logged on (actor, brute force) and was the target of the sudo root shell, which
    # correlation linked to the same incident.
    assert [(i["username"], i["roles"]) for i in context["identities"]] == [
        ("root", ["actor", "target"])
    ]
