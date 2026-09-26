"""Detection API: rules (read, tune), runs (history, manual), ATT&CK techniques, and the
detection fields of the batch report. The CLI commands for rules and runs are here too."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import cli
from app.demo.scenarios import generate
from app.detection.library import Library
from app.models.user import Role
from tests.helpers import audit_entries, bearer, make_user

pytestmark = pytest.mark.integration

START = (datetime.now(UTC) - timedelta(hours=2)).replace(microsecond=0)


@pytest.fixture
def admin(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.ADMIN, email="admin@example.com"))


@pytest.fixture
def viewer(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.VIEWER))


def ingest_scenario(client: TestClient, admin: dict[str, str], name: str) -> dict[str, Any]:
    source = client.post(
        "/api/sources", json={"name": f"{name} log", "source_type": "linux_auth"}, headers=admin
    ).json()
    response = client.post(
        f"/api/ingest/{source['id']}", json={"records": generate(name, START)}, headers=admin
    )
    assert response.status_code == 201, response.text
    return dict(response.json())


# ---------- rules ----------


def test_rules_are_listed_with_their_state(
    db_client: TestClient, seeded_rules: Library, viewer: dict[str, str]
) -> None:
    response = db_client.get("/api/detections", headers=viewer)
    assert response.status_code == 200
    rules = {r["rule_id"]: r for r in response.json()}
    assert set(rules) == set(seeded_rules.rules)
    auth = rules["AUTH-001"]
    assert (auth["kind"], auth["severity"], auth["version"], auth["enabled"]) == (
        "threshold",
        "medium",
        1,
        True,
    )
    assert auth["techniques"] == ["T1110.001"]


def test_a_rule_shows_its_definition_tuning_bounds_and_attack_mapping(
    db_client: TestClient, seeded_rules: Library, viewer: dict[str, str]
) -> None:
    rule = db_client.get("/api/detections/PROC-001", headers=viewer).json()
    assert rule["definition"]["kind"] == "single" and rule["overrides"] == {}
    assert "explanation" in rule["definition"]
    by_indicator = {(m["indicator"], m["technique_id"]) for m in rule["mitre"]}
    assert ("encoded_powershell", "T1059.001") in by_indicator
    assert all(m["url"].startswith("https://attack.mitre.org/techniques/T") for m in rule["mitre"])

    auth = db_client.get("/api/detections/AUTH-001", headers=viewer).json()
    assert auth["tunable"]["threshold"] == {"min": 2, "max": 1000}


@pytest.mark.parametrize(("rule_id", "status"), [("NOPE-999", 404), ("auth-001", 422)])
def test_unknown_or_malformed_rule_ids(
    db_client: TestClient, seeded_rules: Library, viewer: dict[str, str], rule_id: str, status: int
) -> None:
    assert db_client.get(f"/api/detections/{rule_id}", headers=viewer).status_code == status


def test_an_admin_tunes_a_rule_and_the_versions_show_it(
    db_client: TestClient, db_session: Session, seeded_rules: Library, admin: dict[str, str]
) -> None:
    response = db_client.patch(
        "/api/detections/AUTH-001",
        json={"threshold": 10, "time_window": "15m", "reason": "fewer alerts on the bastion"},
        headers=admin,
    )
    assert response.status_code == 200, response.text
    rule = response.json()
    assert rule["version"] == 2
    assert rule["overrides"] == {"threshold": 10, "time_window": "PT900S"}
    assert rule["definition"]["threshold"] == 10
    versions = db_client.get("/api/detections/AUTH-001/versions", headers=admin).json()
    assert [(v["version"], v["source"]) for v in versions] == [(2, "admin"), (1, "library")]
    assert versions[0]["change_reason"] == "fewer alerts on the bastion"
    assert len(audit_entries(db_session, "RULE_UPDATED")) == 1


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ({"threshold": 10}, 422),  # a reason is required
        ({"threshold": 10, "reason": "ok"}, 422),  # ...of at least 5 characters
        ({"match": {"field": "host", "op": "eq", "value": "x"}, "reason": "rewrite it"}, 422),
        ({"threshold": 1, "reason": "too sensitive"}, 400),  # below the rule's minimum
        ({"time_window": "banana", "reason": "bad value"}, 422),
    ],
)
def test_only_tunable_values_within_bounds_are_accepted(
    db_client: TestClient,
    db_session: Session,
    seeded_rules: Library,
    admin: dict[str, str],
    body: dict[str, Any],
    status: int,
) -> None:
    response = db_client.patch("/api/detections/AUTH-001", json=body, headers=admin)
    assert response.status_code == status, response.text
    assert audit_entries(db_session, "RULE_UPDATED") == []


# ---------- runs ----------


def test_an_ingest_batch_reports_its_detections_and_its_run(
    db_client: TestClient, seeded_rules: Library, admin: dict[str, str], viewer: dict[str, str]
) -> None:
    batch = ingest_scenario(db_client, admin, "brute_force_success")
    assert batch["status"] == "PROCESSED" and batch["detection_count"] == 2
    report = db_client.get(f"/api/ingest/batches/{batch['id']}", headers=viewer).json()
    assert report["detection_count"] == 2

    runs = db_client.get("/api/detections/runs", headers=viewer).json()
    assert runs["total"] == 1
    (summary,) = runs["items"]
    assert summary["trigger"] == "batch" and summary["batch_id"] == batch["id"]
    detail = db_client.get(f"/api/detections/runs/{summary['id']}", headers=viewer).json()
    assert {d["rule_id"] for d in detail["detections"]} == {"AUTH-001", "AUTH-002"}
    assert detail["rule_results"]["AUTH-002"]["detections"] == 1

    rules = {r["rule_id"]: r for r in db_client.get("/api/detections", headers=viewer).json()}
    assert rules["AUTH-002"]["match_count"] == 1 and rules["AUTH-002"]["last_match_at"]


def test_an_admin_runs_detection_over_a_time_range(
    db_client: TestClient, db_session: Session, seeded_rules: Library, admin: dict[str, str]
) -> None:
    ingest_scenario(db_client, admin, "password_spray")
    body = {"from": (START - timedelta(hours=1)).isoformat(), "to": datetime.now(UTC).isoformat()}
    response = db_client.post("/api/detections/run", json=body, headers=admin)
    assert response.status_code == 201, response.text
    run = response.json()
    assert run["trigger"] == "manual" and run["status"] == "COMPLETED"
    assert [d["rule_id"] for d in run["detections"]] == ["AUTH-003"]
    assert len(audit_entries(db_session, "DETECTION_RUN_REQUESTED")) == 1
    manual = db_client.get("/api/detections/runs?trigger=manual", headers=admin).json()
    assert [r["id"] for r in manual["items"]] == [run["id"]]


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ({"from": START.isoformat(), "to": (START + timedelta(days=40)).isoformat()}, 400),
        ({"from": START.isoformat(), "to": START.isoformat()}, 400),
        ({"from": START.isoformat()}, 422),
        ({"from": START.isoformat(), "to": START.isoformat(), "rules": ["AUTH-001"]}, 422),
    ],
)
def test_manual_run_requests_are_validated(
    db_client: TestClient, seeded_rules: Library, admin: dict[str, str], body: Any, status: int
) -> None:
    assert db_client.post("/api/detections/run", json=body, headers=admin).status_code == status


def test_unknown_run_is_404(db_client: TestClient, viewer: dict[str, str]) -> None:
    missing = "00000000-0000-0000-0000-000000000000"
    assert db_client.get(f"/api/detections/runs/{missing}", headers=viewer).status_code == 404


def test_attack_techniques_list_the_rules_mapped_to_them(
    db_client: TestClient, seeded_rules: Library, viewer: dict[str, str]
) -> None:
    techniques = {
        t["technique_id"]: t for t in db_client.get("/api/mitre/techniques", headers=viewer).json()
    }
    assert set(techniques) == {t.id for t in seeded_rules.attack.techniques}
    assert techniques["T1078"]["rules"] == ["AUTH-002", "AUTH-004"]
    assert techniques["T1110.001"]["attack_version"] == "19.2"


# ---------- CLI ----------


def test_cli_seeds_rules_and_runs_detection(
    cli_sessions: Session, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["seed-rules"]) == 0
    assert "AUTH-001: added" in capsys.readouterr().out
    assert cli.main(["seed-rules"]) == 0
    assert "no changes" in capsys.readouterr().out

    end = datetime.now(UTC).isoformat()
    start = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    assert cli.main(["run-detection", "--from", start, "--to", end]) == 0
    assert "COMPLETED" in capsys.readouterr().out
    (entry,) = audit_entries(cli_sessions, "DETECTION_RUN_REQUESTED")
    assert entry.actor_id is None

    assert cli.main(["run-detection", "--from", end, "--to", start]) == 1
    assert "must be before" in capsys.readouterr().err
    assert cli.main(["run-detection", "--from", "yesterday", "--to", end]) == 1
