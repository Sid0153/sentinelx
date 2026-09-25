"""Asset and identity inventory: validation, filters, PATCH semantics and the audit trail."""

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import Role
from tests.helpers import audit_entries, bearer, make_user

pytestmark = pytest.mark.integration

WEB = {
    "hostname": "WEB-01.corp.example.",
    "ip_addresses": ["10.0.1.20", "::ffff:10.0.1.21", "10.0.1.20"],
    "asset_type": "server",
    "environment": "production",
    "criticality": "critical",
    "owner": "Platform team",
    "tags": ["DMZ", "linux", " linux "],
}


@pytest.fixture
def admin(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.ADMIN, email="admin@example.com"))


@pytest.fixture
def viewer(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.VIEWER))


def create(client: TestClient, headers: dict[str, str], path: str, body: dict[str, Any]) -> Any:
    response = client.post(path, json=body, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


# ---------- assets ----------


def test_asset_is_stored_in_canonical_form(db_client: TestClient, admin: dict[str, str]) -> None:
    asset = create(db_client, admin, "/api/assets", WEB)
    assert asset["hostname"] == "web-01.corp.example"
    assert asset["ip_addresses"] == ["10.0.1.20", "10.0.1.21"]  # deduplicated, unmapped
    assert asset["tags"] == ["dmz", "linux"]
    assert asset["status"] == "active"


def test_asset_creation_is_audited(
    db_client: TestClient, db_session: Session, admin: dict[str, str]
) -> None:
    asset = create(db_client, admin, "/api/assets", WEB)
    (entry,) = audit_entries(db_session, "ASSET_CREATED")
    assert entry.entity_type == "ASSET" and entry.entity_id == asset["id"]
    assert entry.details == {"hostname": "web-01.corp.example", "criticality": "critical"}


def test_duplicate_hostname_is_a_conflict(db_client: TestClient, admin: dict[str, str]) -> None:
    create(db_client, admin, "/api/assets", WEB)
    again = db_client.post(
        "/api/assets", json={**WEB, "hostname": "web-01.CORP.example"}, headers=admin
    )
    assert again.status_code == 409


@pytest.mark.parametrize(
    "change",
    [
        {"hostname": "not a host"},
        {"ip_addresses": ["10.0.0.256"]},
        {"ip_addresses": [f"10.0.0.{i}" for i in range(17)]},
        {"criticality": "extreme"},
        {"environment": "prod"},
        {"tags": ["has space"]},
        {"tags": [f"t{i}" for i in range(21)]},
        {"owner": "x" * 129},
        {"asset_type": "toaster"},
        {"unexpected": "field"},
    ],
)
def test_invalid_assets_are_rejected(
    db_client: TestClient, admin: dict[str, str], change: dict[str, Any]
) -> None:
    response = db_client.post("/api/assets", json={**WEB, **change}, headers=admin)
    assert response.status_code == 422


def test_update_changes_only_sent_fields_and_audits_from_and_to(
    db_client: TestClient, db_session: Session, admin: dict[str, str]
) -> None:
    asset = create(db_client, admin, "/api/assets", WEB)
    response = db_client.patch(
        f"/api/assets/{asset['id']}",
        json={"criticality": "high", "owner": None, "ip_addresses": ["10.0.1.22"]},
        headers=admin,
    )
    assert response.status_code == 200
    body = response.json()
    assert (body["criticality"], body["owner"], body["environment"]) == (
        "high",
        None,
        "production",
    )
    (entry,) = audit_entries(db_session, "ASSET_UPDATED")
    assert entry.details["changes"] == {
        "criticality": {"from": "critical", "to": "high"},
        "owner": {"from": "Platform team", "to": None},
        "ip_addresses": {"from": ["10.0.1.20", "10.0.1.21"], "to": ["10.0.1.22"]},
    }


def test_update_without_real_changes_records_nothing(
    db_client: TestClient, db_session: Session, admin: dict[str, str]
) -> None:
    asset = create(db_client, admin, "/api/assets", WEB)
    db_client.patch(f"/api/assets/{asset['id']}", json={"criticality": "critical"}, headers=admin)
    assert audit_entries(db_session, "ASSET_UPDATED") == []


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"criticality": None},
        {"status": None},
        {"hostname": "renamed-01", "criticality": "high"},
        {"critcality": "high"},
    ],
    ids=["empty", "null-criticality", "null-status", "hostname-is-fixed", "misspelled"],
)
def test_invalid_updates_are_rejected(
    db_client: TestClient, admin: dict[str, str], body: dict[str, Any]
) -> None:
    asset = create(db_client, admin, "/api/assets", WEB)
    response = db_client.patch(f"/api/assets/{asset['id']}", json=body, headers=admin)
    # Unknown fields, including the fixed hostname, are errors rather than silently ignored.
    assert response.status_code == 422


def test_retiring_keeps_the_asset(db_client: TestClient, admin: dict[str, str]) -> None:
    asset = create(db_client, admin, "/api/assets", WEB)
    db_client.patch(f"/api/assets/{asset['id']}", json={"status": "retired"}, headers=admin)
    kept = db_client.get(f"/api/assets/{asset['id']}", headers=admin).json()
    assert kept["status"] == "retired"


def test_asset_filters_and_search(
    db_client: TestClient, admin: dict[str, str], viewer: dict[str, str]
) -> None:
    create(db_client, admin, "/api/assets", WEB)
    create(
        db_client,
        admin,
        "/api/assets",
        {
            "hostname": "ws-042",
            "asset_type": "workstation",
            "environment": "production",
            "criticality": "medium",
            "description": "Finance laptop (100% managed)",
            "tags": ["finance"],
        },
    )

    def hostnames(params: dict[str, str]) -> list[str]:
        page = db_client.get("/api/assets", params=params, headers=viewer).json()
        return [a["hostname"] for a in page["items"]]

    assert hostnames({}) == ["web-01.corp.example", "ws-042"]
    assert hostnames({"criticality": "critical"}) == ["web-01.corp.example"]
    assert hostnames({"tag": "FINANCE"}) == ["ws-042"]
    assert hostnames({"search": "platform"}) == ["web-01.corp.example"]
    assert hostnames({"search": "100%"}) == ["ws-042"]  # % matches literally
    assert hostnames({"search": "%"}) == ["ws-042"]
    assert hostnames({"search": "_"}) == []  # "_" is not a wildcard either
    assert (
        db_client.get("/api/assets", params={"criticality": "extreme"}, headers=viewer).status_code
        == 422
    )


def test_unknown_asset_is_404(db_client: TestClient, viewer: dict[str, str]) -> None:
    response = db_client.get("/api/assets/00000000-0000-0000-0000-000000000000", headers=viewer)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


# ---------- identities ----------

ALICE = {
    "username": " Alice ",
    "display_name": "Alice Moreau",
    "department": "Database administration",
    "title": "DBA",
    "privilege_level": "privileged",
    "tags": ["oncall"],
}


def test_identity_lifecycle_is_audited(
    db_client: TestClient, db_session: Session, admin: dict[str, str]
) -> None:
    identity = create(db_client, admin, "/api/identities", ALICE)
    assert identity["username"] == "alice"
    response = db_client.patch(
        f"/api/identities/{identity['id']}",
        json={"privilege_level": "standard", "status": "disabled", "title": None},
        headers=admin,
    )
    assert response.status_code == 200
    (created,) = audit_entries(db_session, "IDENTITY_CREATED")
    (updated,) = audit_entries(db_session, "IDENTITY_UPDATED")
    assert created.details == {"username": "alice", "privilege_level": "privileged"}
    assert updated.details["changes"]["privilege_level"] == {"from": "privileged", "to": "standard"}
    assert updated.details["changes"]["title"] == {"from": "DBA", "to": None}


@pytest.mark.parametrize(
    "username",
    ["", "   ", "alice smith", "bob\tadmin", "x" * 257],
    ids=["empty", "blank", "space", "tab", "long"],
)
def test_invalid_usernames_are_rejected(
    db_client: TestClient, admin: dict[str, str], username: str
) -> None:
    response = db_client.post(
        "/api/identities", json={**ALICE, "username": username}, headers=admin
    )
    assert response.status_code == 422


def test_duplicate_username_is_a_conflict(db_client: TestClient, admin: dict[str, str]) -> None:
    create(db_client, admin, "/api/identities", ALICE)
    again = db_client.post("/api/identities", json={**ALICE, "username": "ALICE"}, headers=admin)
    assert again.status_code == 409


def test_identity_filters(
    db_client: TestClient, admin: dict[str, str], viewer: dict[str, str]
) -> None:
    create(db_client, admin, "/api/identities", ALICE)
    create(
        db_client,
        admin,
        "/api/identities",
        {"username": "svc-backup", "privilege_level": "service", "department": "IT"},
    )

    def usernames(params: dict[str, str]) -> list[str]:
        page = db_client.get("/api/identities", params=params, headers=viewer).json()
        return [i["username"] for i in page["items"]]

    assert usernames({}) == ["alice", "svc-backup"]
    assert usernames({"privilege_level": "service"}) == ["svc-backup"]
    assert usernames({"search": "database"}) == ["alice"]
    assert usernames({"tag": "oncall"}) == ["alice"]
    assert usernames({"status": "disabled"}) == []


def test_identity_null_privilege_is_rejected(db_client: TestClient, admin: dict[str, str]) -> None:
    identity = create(db_client, admin, "/api/identities", ALICE)
    response = db_client.patch(
        f"/api/identities/{identity['id']}", json={"privilege_level": None}, headers=admin
    )
    assert response.status_code == 422


def test_unknown_identity_is_404(db_client: TestClient, admin: dict[str, str]) -> None:
    response = db_client.patch(
        "/api/identities/00000000-0000-0000-0000-000000000000",
        json={"title": "x"},
        headers=admin,
    )
    assert response.status_code == 404
