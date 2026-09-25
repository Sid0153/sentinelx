"""Sign-in, sessions, lockout, rate limiting and password changes against a real database."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.tokens import hash_refresh_token
from app.models.refresh_token import RefreshToken
from app.models.user import Role
from tests.helpers import (
    REFRESH_COOKIE,
    TEST_PASSWORD,
    access_token_for,
    audit_entries,
    bearer,
    cookie_header,
    login,
    make_user,
    refresh_cookie_value,
)

pytestmark = pytest.mark.integration

NEW_PASSWORD = "a-brand-new-passphrase"


# ---------- login ----------


def test_login_returns_token_user_and_a_locked_down_cookie(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, Role.ANALYST, password=TEST_PASSWORD)
    response = login(db_client, user.email, TEST_PASSWORD)

    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["expires_in"] == 15 * 60
    assert body["user"]["email"] == user.email
    assert body["user"]["role"] == "ANALYST"
    assert "password" not in response.text

    cookie = response.headers["set-cookie"].lower()
    assert f"{REFRESH_COOKIE}=" in cookie
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "path=/api/auth" in cookie
    assert "secure" not in cookie  # plain http in tests; production sets Secure


def test_access_token_from_login_works_on_a_protected_route(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    token = login(db_client, user.email, TEST_PASSWORD).json()["access_token"]
    me = db_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["id"] == str(user.id)


def test_refresh_token_is_stored_only_as_a_hash(db_client: TestClient, db_session: Session) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    plain = refresh_cookie_value(login(db_client, user.email, TEST_PASSWORD))
    row = db_session.scalar(select(RefreshToken).where(RefreshToken.user_id == user.id))
    assert row is not None
    assert row.token_hash == hash_refresh_token(plain)
    assert plain not in row.token_hash


def test_login_email_is_case_and_space_insensitive(
    db_client: TestClient, db_session: Session
) -> None:
    make_user(db_session, email="mixed@example.com", password=TEST_PASSWORD)
    assert login(db_client, "  Mixed@Example.COM ", TEST_PASSWORD).status_code == 200


def test_wrong_password_and_unknown_email_look_identical(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    wrong_password = login(db_client, user.email, "definitely-the-wrong-one")
    unknown_email = login(db_client, "nobody@example.com", "definitely-the-wrong-one")

    assert wrong_password.status_code == unknown_email.status_code == 401

    def without_request_id(body: dict[str, dict[str, str]]) -> dict[str, str]:
        return {k: v for k, v in body["error"].items() if k != "request_id"}

    assert without_request_id(wrong_password.json()) == without_request_id(unknown_email.json())
    assert "set-cookie" not in wrong_password.headers


def test_disabled_account_cannot_sign_in_even_with_the_right_password(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD, is_active=False)
    response = login(db_client, user.email, TEST_PASSWORD)
    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Invalid email or password"


def test_account_locks_after_repeated_failures(db_client: TestClient, db_session: Session) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    for _ in range(5):
        assert login(db_client, user.email, "wrong-password-123").status_code == 401

    # Locked: even the correct password is refused, with the same generic answer.
    assert login(db_client, user.email, TEST_PASSWORD).status_code == 401
    db_session.refresh(user)
    assert user.locked_until is not None
    assert len(audit_entries(db_session, "ACCOUNT_LOCKED")) == 1
    reasons = [e.details["reason"] for e in audit_entries(db_session, "LOGIN_FAILED")]
    assert reasons == ["wrong_password"] * 5 + ["account_locked"]


def test_lock_expires_and_success_resets_the_counter(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    user.locked_until = datetime.now(UTC) - timedelta(seconds=1)
    user.failed_login_count = 3
    db_session.commit()

    assert login(db_client, user.email, TEST_PASSWORD).status_code == 200
    db_session.refresh(user)
    assert user.failed_login_count == 0
    assert user.locked_until is None
    assert user.last_login_at is not None


def test_login_is_rate_limited_per_client(db_client: TestClient) -> None:
    codes = [
        login(db_client, "nobody@example.com", "wrong-password-123").status_code for _ in range(11)
    ]
    assert codes[:10] == [401] * 10
    assert codes[10] == 429


def test_rate_limited_response_has_retry_after_and_is_audited(
    db_client: TestClient, db_session: Session
) -> None:
    for _ in range(10):
        login(db_client, "nobody@example.com", "wrong-password-123")
    response = login(db_client, "nobody@example.com", "wrong-password-123")
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "60"
    assert response.json()["error"]["code"] == "rate_limited"
    assert len(audit_entries(db_session, "LOGIN_RATE_LIMITED")) == 1


def test_failed_login_audit_never_stores_the_submitted_email_or_password(
    db_client: TestClient, db_session: Session
) -> None:
    login(db_client, "typed-password-here@example.com", "the-secret-password")
    (entry,) = audit_entries(db_session, "LOGIN_FAILED")
    stored = str(entry.details) + str(entry.actor_label) + str(entry.entity_id)
    assert "typed-password-here" not in stored
    assert "the-secret-password" not in stored
    assert entry.details == {"reason": "unknown_email"}
    assert entry.result == "FAILURE"
    assert entry.client_ip == "testclient"


def test_successful_login_is_audited_with_actor_and_request_id(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    response = db_client.post(
        "/api/auth/login",
        json={"email": user.email, "password": TEST_PASSWORD},
        headers={"X-Request-ID": "login-trace-000001"},
    )
    assert response.status_code == 200
    (entry,) = audit_entries(db_session, "LOGIN_SUCCEEDED")
    assert entry.actor_id == user.id
    assert entry.actor_label == user.email
    assert entry.request_id == "login-trace-000001"


def test_login_validation_error_does_not_echo_the_password(db_client: TestClient) -> None:
    response = db_client.post(
        "/api/auth/login", json={"email": "a@example.com", "password": "x" * 500}
    )
    assert response.status_code == 422
    assert "xxxxxxxx" not in response.text


# ---------- access tokens on protected routes ----------


def test_missing_or_malformed_token_is_401(db_client: TestClient) -> None:
    assert db_client.get("/api/auth/me").status_code == 401
    response = db_client.get("/api/auth/me", headers={"Authorization": "Bearer not-a-jwt"})
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_expired_access_token_is_401(db_client: TestClient, db_session: Session) -> None:
    user = make_user(db_session)
    token = access_token_for(user, expires_in=timedelta(seconds=-5))
    response = db_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_deactivation_takes_effect_before_the_token_expires(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, Role.ADMIN)
    headers = bearer(user)
    assert db_client.get("/api/auth/me", headers=headers).status_code == 200
    user.is_active = False
    db_session.commit()
    assert db_client.get("/api/auth/me", headers=headers).status_code == 401


def test_demotion_takes_effect_before_the_token_expires(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, Role.ADMIN)
    headers = bearer(user)
    assert db_client.get("/api/users", headers=headers).status_code == 200
    user.role = Role.VIEWER
    db_session.commit()
    assert db_client.get("/api/users", headers=headers).status_code == 403


# ---------- refresh ----------


def test_refresh_rotates_the_token(db_client: TestClient, db_session: Session) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    first = refresh_cookie_value(login(db_client, user.email, TEST_PASSWORD))

    response = db_client.post("/api/auth/refresh", headers=cookie_header(first))
    assert response.status_code == 200
    assert response.json()["access_token"]
    second = refresh_cookie_value(response)
    assert second != first


def test_reusing_a_rotated_refresh_token_revokes_every_session(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    stolen = refresh_cookie_value(login(db_client, user.email, TEST_PASSWORD))
    current = refresh_cookie_value(
        db_client.post("/api/auth/refresh", headers=cookie_header(stolen))
    )

    replay = db_client.post("/api/auth/refresh", headers=cookie_header(stolen))
    assert replay.status_code == 401
    assert f"{REFRESH_COOKIE}=" in replay.headers["set-cookie"]  # cleared

    # The legitimate session is gone too: the attacker and the user both sign in again.
    # (That second refusal is a revoked token, not another theft signal.)
    assert db_client.post("/api/auth/refresh", headers=cookie_header(current)).status_code == 401
    (entry,) = audit_entries(db_session, "REFRESH_TOKEN_REUSED")
    assert entry.entity_id == str(user.id)


def test_old_tab_refreshing_after_logout_is_not_treated_as_theft(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    old_tab = refresh_cookie_value(login(db_client, user.email, TEST_PASSWORD))
    other_device = refresh_cookie_value(login(db_client, user.email, TEST_PASSWORD))
    db_client.post("/api/auth/logout", headers=cookie_header(old_tab))

    assert db_client.post("/api/auth/refresh", headers=cookie_header(old_tab)).status_code == 401
    # The user's other device keeps working, and no theft alarm was raised.
    assert (
        db_client.post("/api/auth/refresh", headers=cookie_header(other_device)).status_code == 200
    )
    assert audit_entries(db_session, "REFRESH_TOKEN_REUSED") == []


def test_refresh_without_cookie_or_with_unknown_token_is_401(db_client: TestClient) -> None:
    assert db_client.post("/api/auth/refresh").status_code == 401
    unknown = db_client.post("/api/auth/refresh", headers=cookie_header("made-up"))
    assert unknown.status_code == 401
    assert unknown.json()["error"]["code"] == "unauthorized"


def test_expired_refresh_token_is_rejected(db_client: TestClient, db_session: Session) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    plain = refresh_cookie_value(login(db_client, user.email, TEST_PASSWORD))
    row = db_session.scalar(select(RefreshToken).where(RefreshToken.user_id == user.id))
    assert row is not None
    row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.commit()
    assert db_client.post("/api/auth/refresh", headers=cookie_header(plain)).status_code == 401


def test_deactivated_user_cannot_refresh(db_client: TestClient, db_session: Session) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    plain = refresh_cookie_value(login(db_client, user.email, TEST_PASSWORD))
    user.is_active = False
    db_session.commit()
    assert db_client.post("/api/auth/refresh", headers=cookie_header(plain)).status_code == 401


# ---------- logout ----------


def test_logout_revokes_the_session_and_clears_the_cookie(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    plain = refresh_cookie_value(login(db_client, user.email, TEST_PASSWORD))

    response = db_client.post("/api/auth/logout", headers=cookie_header(plain))
    assert response.status_code == 204
    assert f'{REFRESH_COOKIE}=""' in response.headers["set-cookie"]
    assert db_client.post("/api/auth/refresh", headers=cookie_header(plain)).status_code == 401
    (entry,) = audit_entries(db_session, "LOGOUT")
    assert entry.actor_id == user.id


def test_logout_without_a_session_is_harmless(db_client: TestClient) -> None:
    assert db_client.post("/api/auth/logout").status_code == 204


# ---------- change password ----------


def test_change_password_requires_the_current_one(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    response = db_client.post(
        "/api/auth/change-password",
        json={"current_password": "not-my-password", "new_password": NEW_PASSWORD},
        headers=bearer(user),
    )
    assert response.status_code == 400  # not 401: the session is fine
    (entry,) = audit_entries(db_session, "PASSWORD_CHANGED")
    assert entry.result == "FAILURE"


def test_change_password_signs_out_everywhere_and_the_new_password_works(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    other_device = refresh_cookie_value(login(db_client, user.email, TEST_PASSWORD))

    response = db_client.post(
        "/api/auth/change-password",
        json={"current_password": TEST_PASSWORD, "new_password": NEW_PASSWORD},
        headers=bearer(user),
    )
    assert response.status_code == 204
    assert (
        db_client.post("/api/auth/refresh", headers=cookie_header(other_device)).status_code == 401
    )
    assert login(db_client, user.email, TEST_PASSWORD).status_code == 401
    assert login(db_client, user.email, NEW_PASSWORD).status_code == 200


def test_new_password_must_meet_the_policy(db_client: TestClient, db_session: Session) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    response = db_client.post(
        "/api/auth/change-password",
        json={"current_password": TEST_PASSWORD, "new_password": "short"},
        headers=bearer(user),
    )
    assert response.status_code == 422
