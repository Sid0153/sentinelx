"""Phase 13: two-factor sign-in (TOTP + recovery codes) and admin resets with a forced
password change, against a real database."""

import base64
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.auth import mfa
from app.models.user import Role, User
from tests.helpers import TEST_PASSWORD, audit_entries, bearer, login, make_user

pytestmark = pytest.mark.integration

NEW_PASSWORD = "a-brand-new-passphrase"


def code_for(secret_b32: str, steps_ahead: int = 0) -> str:
    """What an authenticator app shows, from the secret it was given at setup."""
    padded = secret_b32 + "=" * (-len(secret_b32) % 8)
    secret = base64.b32decode(padded)
    return mfa.hotp(secret, mfa.time_step(datetime.now(UTC)) + steps_ahead)


def enrol(client: TestClient, headers: dict[str, str]) -> tuple[str, list[str]]:
    """Turns two-factor sign-in on; returns (secret, recovery codes)."""
    setup = client.post("/api/auth/mfa/setup", headers=headers)
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    assert setup.json()["otpauth_uri"].startswith("otpauth://totp/SentinelX:")
    enabled = client.post("/api/auth/mfa/enable", json={"code": code_for(secret)}, headers=headers)
    assert enabled.status_code == 200, enabled.text
    return secret, enabled.json()["recovery_codes"]


def sign_in(client: TestClient, email: str, **second: str) -> Any:
    return client.post(
        "/api/auth/login", json={"email": email, "password": TEST_PASSWORD, **second}
    )


@pytest.fixture
def enrolled(db_client: TestClient, db_session: Session) -> tuple[User, str, list[str]]:
    user = make_user(db_session, Role.ANALYST, password=TEST_PASSWORD)
    secret, codes = enrol(db_client, bearer(user))
    return user, secret, codes


def test_enrolment_returns_ten_single_use_recovery_codes_and_stores_no_secret(
    db_client: TestClient, db_session: Session, enrolled: tuple[User, str, list[str]]
) -> None:
    user, secret, codes = enrolled
    assert len(codes) == 10 and len(set(codes)) == 10
    db_session.refresh(user)
    assert user.mfa_enabled and user.totp_pending_salt is None
    # Neither the secret nor the codes are in the database, only a salt and hashes.
    stored = f"{user.totp_salt} {user.mfa_recovery_hashes}"
    assert secret not in stored and not any(code in stored for code in codes)
    me = db_client.get("/api/auth/me", headers=bearer(user)).json()
    assert me["mfa_enabled"] is True
    assert [e.result for e in audit_entries(db_session, "MFA_ENABLED")] == ["SUCCESS"]


def test_a_wrong_confirmation_code_does_not_turn_it_on(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    db_client.post("/api/auth/mfa/setup", headers=bearer(user))
    response = db_client.post("/api/auth/mfa/enable", json={"code": "000000"}, headers=bearer(user))
    # 000000 could be right once in a million runs; the assertion would then show it.
    assert response.status_code == 400
    db_session.refresh(user)
    assert not user.mfa_enabled
    assert [e.result for e in audit_entries(db_session, "MFA_ENABLED")] == ["FAILURE"]
    # Enabling without setup first is refused too.
    other = make_user(db_session)
    assert (
        db_client.post("/api/auth/mfa/enable", json={"code": "123456"}, headers=bearer(other))
    ).status_code == 400


def test_sign_in_needs_the_code_after_the_password(
    db_client: TestClient, enrolled: tuple[User, str, list[str]]
) -> None:
    user, secret, _ = enrolled
    first = login(db_client, user.email, TEST_PASSWORD)
    assert first.status_code == 401
    assert first.json()["error"]["code"] == "mfa_required"
    assert "set-cookie" not in first.headers

    # The setup used the current step; the app's next code (one step of drift) signs in.
    second = sign_in(db_client, user.email, otp=code_for(secret, 1))
    assert second.status_code == 200
    assert second.json()["user"]["mfa_enabled"] is True


def test_a_code_works_once(db_client: TestClient, enrolled: tuple[User, str, list[str]]) -> None:
    user, secret, _ = enrolled
    code = code_for(secret, 1)
    assert sign_in(db_client, user.email, otp=code).status_code == 200
    replay = sign_in(db_client, user.email, otp=code)
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "unauthorized"


def test_wrong_codes_count_towards_the_lockout(
    db_client: TestClient, db_session: Session, enrolled: tuple[User, str, list[str]]
) -> None:
    user, secret, _ = enrolled
    for _ in range(5):
        assert sign_in(db_client, user.email, otp="not-it").status_code == 401
    db_session.refresh(user)
    assert user.locked_until is not None
    reasons = [e.details["reason"] for e in audit_entries(db_session, "LOGIN_FAILED")]
    assert reasons == ["wrong_mfa_code"] * 5
    # Locked: even the right code does not get in now.
    assert sign_in(db_client, user.email, otp=code_for(secret, 1)).status_code == 401


def test_a_recovery_code_signs_in_once(
    db_client: TestClient, db_session: Session, enrolled: tuple[User, str, list[str]]
) -> None:
    user, _, codes = enrolled
    assert sign_in(db_client, user.email, recovery_code=codes[3].upper()).status_code == 200
    assert sign_in(db_client, user.email, recovery_code=codes[3]).status_code == 401
    db_session.refresh(user)
    assert len(user.mfa_recovery_hashes) == 9
    used = audit_entries(db_session, "MFA_RECOVERY_CODE_USED")
    assert [e.details for e in used] == [{"remaining": 9}]


def test_turning_it_off_needs_the_password_and_a_code(
    db_client: TestClient, db_session: Session, enrolled: tuple[User, str, list[str]]
) -> None:
    user, secret, _ = enrolled
    headers = bearer(user)
    wrong_password = {"password": "not-the-password", "code": code_for(secret, 1)}
    assert (
        db_client.post("/api/auth/mfa/disable", json=wrong_password, headers=headers).status_code
        == 400
    )
    wrong_code = {"password": TEST_PASSWORD, "code": "000000"}
    assert (
        db_client.post("/api/auth/mfa/disable", json=wrong_code, headers=headers).status_code == 400
    )
    db_session.refresh(user)
    assert user.mfa_enabled

    right = {"password": TEST_PASSWORD, "code": code_for(secret, 1)}
    assert db_client.post("/api/auth/mfa/disable", json=right, headers=headers).status_code == 204
    db_session.refresh(user)
    assert not user.mfa_enabled and user.totp_salt is None and user.mfa_recovery_hashes == []
    assert login(db_client, user.email, TEST_PASSWORD).status_code == 200
    results = [e.result for e in audit_entries(db_session, "MFA_DISABLED")]
    assert results == ["FAILURE", "FAILURE", "SUCCESS"]


def test_setup_is_refused_while_it_is_on(
    db_client: TestClient, enrolled: tuple[User, str, list[str]]
) -> None:
    user, _, _ = enrolled
    assert db_client.post("/api/auth/mfa/setup", headers=bearer(user)).status_code == 409


def test_secret_key_rotation_ends_enrolments(enrolled: tuple[User, str, list[str]]) -> None:
    """Documented consequence of deriving the secret from SECRET_KEY (docs/security.md)."""
    user, secret, _ = enrolled
    assert user.totp_salt is not None
    other_key = mfa.derive_secret("a-different-server-secret-key-value", user.totp_salt)
    assert base64.b32encode(other_key).decode().rstrip("=") != secret


# ---------- admin resets ----------


def test_admin_resets_two_factor_for_a_locked_out_user(
    db_client: TestClient, db_session: Session, enrolled: tuple[User, str, list[str]]
) -> None:
    user, _, _ = enrolled
    admin = make_user(db_session, Role.ADMIN)
    response = db_client.post(f"/api/users/{user.id}/reset-mfa", headers=bearer(admin))
    assert response.status_code == 200
    assert response.json()["mfa_enabled"] is False
    assert login(db_client, user.email, TEST_PASSWORD).status_code == 200
    (entry,) = audit_entries(db_session, "MFA_RESET")
    assert entry.actor_id == admin.id and entry.entity_id == str(user.id)
    # Not for one's own account (that goes through the password + code flow).
    own = db_client.post(f"/api/users/{admin.id}/reset-mfa", headers=bearer(admin))
    assert own.status_code == 400


def test_password_reset_forces_a_change_before_anything_else(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, Role.ANALYST, password=TEST_PASSWORD)
    admin = make_user(db_session, Role.ADMIN)
    old_session = login(db_client, user.email, TEST_PASSWORD)
    assert old_session.status_code == 200

    reset = db_client.post(f"/api/users/{user.id}/reset-password", headers=bearer(admin))
    assert reset.status_code == 200
    assert reset.headers["cache-control"] == "no-store"
    temporary = reset.json()["temporary_password"]
    assert len(temporary) >= 20

    # The old password and the old session are gone; the temporary password signs in.
    assert login(db_client, user.email, TEST_PASSWORD).status_code == 401
    refreshed = db_client.post("/api/auth/refresh", cookies=old_session.cookies)
    assert refreshed.status_code == 401
    signed_in = db_client.post("/api/auth/login", json={"email": user.email, "password": temporary})
    assert signed_in.status_code == 200
    assert signed_in.json()["user"]["must_change_password"] is True
    headers = {"Authorization": f"Bearer {signed_in.json()['access_token']}"}

    # Only /me and change-password work until the password is changed.
    blocked = db_client.get("/api/alerts", headers=headers)
    assert blocked.status_code == 403
    assert blocked.json()["error"]["code"] == "password_change_required"
    assert db_client.get("/api/auth/me", headers=headers).status_code == 200
    same = {"current_password": temporary, "new_password": temporary}
    assert (
        db_client.post("/api/auth/change-password", json=same, headers=headers).status_code == 400
    )
    change = {"current_password": temporary, "new_password": NEW_PASSWORD}
    assert (
        db_client.post("/api/auth/change-password", json=change, headers=headers).status_code == 204
    )
    assert db_client.get("/api/alerts", headers=headers).status_code == 200

    # The temporary password is in no audit record.
    (entry,) = audit_entries(db_session, "PASSWORD_RESET")
    assert entry.actor_id == admin.id
    assert temporary not in str(entry.details)


def test_password_reset_lifts_a_lockout_but_keeps_two_factor(
    db_client: TestClient, db_session: Session, enrolled: tuple[User, str, list[str]]
) -> None:
    user, secret, _ = enrolled
    admin = make_user(db_session, Role.ADMIN)
    for _ in range(5):
        login(db_client, user.email, "wrong-password-here")
    temporary = db_client.post(
        f"/api/users/{user.id}/reset-password", headers=bearer(admin)
    ).json()["temporary_password"]
    password_only = db_client.post(
        "/api/auth/login", json={"email": user.email, "password": temporary}
    )
    assert password_only.json()["error"]["code"] == "mfa_required"
    with_code = db_client.post(
        "/api/auth/login",
        json={"email": user.email, "password": temporary, "otp": code_for(secret, 1)},
    )
    assert with_code.status_code == 200
    own = db_client.post(f"/api/users/{admin.id}/reset-password", headers=bearer(admin))
    assert own.status_code == 400
