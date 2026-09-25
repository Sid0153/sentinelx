import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import Role
from tests.helpers import (
    TEST_PASSWORD,
    audit_entries,
    bearer,
    cookie_header,
    login,
    make_user,
    refresh_cookie_value,
)

pytestmark = pytest.mark.integration


@pytest.fixture
def admin_headers(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.ADMIN, email="admin@example.com"))


def test_admin_creates_a_user_who_can_sign_in(
    db_client: TestClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    response = db_client.post(
        "/api/users",
        json={"email": " New.Analyst@Example.com ", "password": TEST_PASSWORD, "role": "ANALYST"},
        headers=admin_headers,
    )
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "new.analyst@example.com"
    assert body["role"] == "ANALYST"
    assert "password" not in response.text and "hash" not in response.text
    assert login(db_client, "new.analyst@example.com", TEST_PASSWORD).status_code == 200

    (entry,) = audit_entries(db_session, "USER_CREATED")
    assert entry.details == {"email": "new.analyst@example.com", "role": "ANALYST", "via": "api"}
    assert entry.actor_label == "admin@example.com"


def test_duplicate_email_is_a_conflict(
    db_client: TestClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    make_user(db_session, email="taken@example.com")
    response = db_client.post(
        "/api/users",
        json={"email": "TAKEN@example.com", "password": TEST_PASSWORD, "role": "VIEWER"},
        headers=admin_headers,
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "conflict"


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "not-an-email", "password": TEST_PASSWORD, "role": "VIEWER"},
        {"email": "a@example.com", "password": "short", "role": "VIEWER"},
        {"email": "a@example.com", "password": TEST_PASSWORD, "role": "SUPERUSER"},
    ],
)
def test_invalid_new_users_are_rejected(
    db_client: TestClient, admin_headers: dict[str, str], payload: dict[str, str]
) -> None:
    response = db_client.post("/api/users", json=payload, headers=admin_headers)
    assert response.status_code == 422
    assert TEST_PASSWORD not in response.text


def test_list_users_is_paginated(
    db_client: TestClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    for _ in range(3):
        make_user(db_session)
    page = db_client.get("/api/users?limit=2&offset=0", headers=admin_headers).json()
    assert page["total"] == 4  # three users plus the admin
    assert len(page["items"]) == 2
    assert page["limit"] == 2 and page["offset"] == 0
    rest = db_client.get("/api/users?limit=2&offset=2", headers=admin_headers).json()
    ids = {u["id"] for u in page["items"]} | {u["id"] for u in rest["items"]}
    assert len(ids) == 4


def test_role_change_is_audited_with_old_and_new_role(
    db_client: TestClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    user = make_user(db_session, Role.VIEWER)
    response = db_client.patch(
        f"/api/users/{user.id}", json={"role": "ANALYST"}, headers=admin_headers
    )
    assert response.status_code == 200
    assert response.json()["role"] == "ANALYST"
    (entry,) = audit_entries(db_session, "USER_ROLE_CHANGED")
    assert entry.details["from"] == "VIEWER" and entry.details["to"] == "ANALYST"
    assert entry.entity_id == str(user.id)


def test_deactivation_ends_sessions_and_reactivation_is_audited(
    db_client: TestClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    session = refresh_cookie_value(login(db_client, user.email, TEST_PASSWORD))

    off = db_client.patch(f"/api/users/{user.id}", json={"is_active": False}, headers=admin_headers)
    assert off.json()["is_active"] is False
    assert db_client.post("/api/auth/refresh", headers=cookie_header(session)).status_code == 401

    db_client.patch(f"/api/users/{user.id}", json={"is_active": True}, headers=admin_headers)
    assert len(audit_entries(db_session, "USER_DEACTIVATED")) == 1
    assert len(audit_entries(db_session, "USER_REACTIVATED")) == 1


def test_unchanged_values_record_nothing(
    db_client: TestClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    user = make_user(db_session, Role.VIEWER)
    db_client.patch(
        f"/api/users/{user.id}", json={"role": "VIEWER", "is_active": True}, headers=admin_headers
    )
    assert audit_entries(db_session, "USER_ROLE_CHANGED") == []
    assert audit_entries(db_session, "USER_REACTIVATED") == []


def test_admin_cannot_change_their_own_role_or_status(
    db_client: TestClient, db_session: Session
) -> None:
    admin = make_user(db_session, Role.ADMIN)
    response = db_client.patch(
        f"/api/users/{admin.id}", json={"role": "VIEWER"}, headers=bearer(admin)
    )
    assert response.status_code == 400
    db_session.refresh(admin)
    assert admin.role == Role.ADMIN


def test_update_needs_at_least_one_field_and_an_existing_user(
    db_client: TestClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    user = make_user(db_session)
    assert (
        db_client.patch(f"/api/users/{user.id}", json={}, headers=admin_headers).status_code == 422
    )
    missing = db_client.patch(
        "/api/users/00000000-0000-0000-0000-000000000000",
        json={"role": "ADMIN"},
        headers=admin_headers,
    )
    assert missing.status_code == 404
