import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.audit.events import AuditAction, AuditResult, EntityType
from app.audit.service import record
from app.models.user import Role
from tests.helpers import audit_entries, bearer, login, make_user

pytestmark = pytest.mark.integration


def test_viewer_denied_admin_route_is_audited_as_denied(
    db_client: TestClient, db_session: Session
) -> None:
    viewer = make_user(db_session, Role.VIEWER)
    response = db_client.get("/api/audit", headers=bearer(viewer))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"
    (entry,) = audit_entries(db_session, "ACCESS_DENIED")
    assert entry.result == "DENIED"
    assert entry.actor_id == viewer.id
    assert entry.entity_type == "ROUTE"
    assert entry.details == {
        "method": "GET",
        "path": "/api/audit",
        "role": "VIEWER",
        "required": "ADMIN",
    }


def test_audit_list_filters_and_orders_newest_first(
    db_client: TestClient, db_session: Session
) -> None:
    admin = make_user(db_session, Role.ADMIN)
    login(db_client, "nobody@example.com", "wrong-password-123")
    login(db_client, "nobody@example.com", "wrong-password-123")
    record(
        db_session,
        AuditAction.USER_CREATED,
        actor=admin,
        entity_type=EntityType.USER,
        entity_id="x",
    )
    db_session.commit()

    page = db_client.get("/api/audit", headers=bearer(admin)).json()
    assert page["total"] == 3
    assert [e["action"] for e in page["items"]] == ["USER_CREATED", "LOGIN_FAILED", "LOGIN_FAILED"]

    failed = db_client.get("/api/audit", params={"result": "FAILURE"}, headers=bearer(admin)).json()
    assert failed["total"] == 2
    by_action = db_client.get(
        "/api/audit", params={"action": ["USER_CREATED"]}, headers=bearer(admin)
    ).json()
    assert [e["actor_label"] for e in by_action["items"]] == [admin.email]
    by_entity = db_client.get(
        "/api/audit", params={"entity_type": "USER", "entity_id": "x"}, headers=bearer(admin)
    ).json()
    assert by_entity["total"] == 1


def test_unknown_filter_values_are_rejected(db_client: TestClient, db_session: Session) -> None:
    admin = make_user(db_session, Role.ADMIN)
    response = db_client.get("/api/audit", params={"action": "DROP_TABLE"}, headers=bearer(admin))
    assert response.status_code == 422


def test_audit_log_rejects_update_delete_and_truncate(db_session: Session) -> None:
    record(db_session, AuditAction.LOGIN_FAILED, result=AuditResult.FAILURE)
    db_session.flush()
    for statement in (
        "UPDATE audit_logs SET action = 'TAMPERED'",
        "DELETE FROM audit_logs",
        "TRUNCATE audit_logs",
    ):
        savepoint = db_session.begin_nested()
        with pytest.raises(DBAPIError, match="append-only"):
            db_session.execute(text(statement))
        savepoint.rollback()
    assert audit_entries(db_session)[0].action == "LOGIN_FAILED"


def test_invalid_result_value_is_rejected_by_the_database(db_session: Session) -> None:
    with pytest.raises(DBAPIError, match="result_valid"):
        db_session.execute(
            text(
                "INSERT INTO audit_logs (id, occurred_at, action, result, details) "
                "VALUES (gen_random_uuid(), now(), 'X', 'MAYBE', '{}')"
            )
        )
