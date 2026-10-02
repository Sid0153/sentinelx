"""Guest access for a public demo: a shared, read-only account, signed into without a
password, whose sign-in settings nobody can change (docs/deployment.md, free public
deployment)."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import cli
from app.audit.events import AuditAction
from app.core.config import get_settings
from app.models.user import Role, User
from tests.helpers import audit_entries, bearer, make_user

GUEST = "guest@sentinelx.example"


@pytest.fixture
def guest_on(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("GUEST_EMAIL", GUEST)
    get_settings.cache_clear()
    yield
    monkeypatch.delenv("GUEST_EMAIL")
    get_settings.cache_clear()


def test_guest_access_is_off_by_default(db_client: TestClient) -> None:
    assert db_client.get("/api/auth/options").json() == {"guest_access": False}
    response = db_client.post("/api/auth/guest")
    assert response.status_code == 404


@pytest.mark.usefixtures("guest_on")
def test_a_visitor_signs_in_as_the_read_only_guest(
    db_client: TestClient, db_session: Session
) -> None:
    make_user(db_session, Role.VIEWER, email=GUEST)
    assert db_client.get("/api/auth/options").json() == {"guest_access": True}

    response = db_client.post("/api/auth/guest")
    assert response.status_code == 200
    body = response.json()
    assert body["user"]["email"] == GUEST and body["user"]["role"] == "VIEWER"
    assert body["user"]["is_guest"] is True
    assert response.cookies.get("sx_refresh")  # a normal session, refreshed the normal way

    me = db_client.get("/api/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.json()["is_guest"] is True
    (entry,) = [e for e in audit_entries(db_session, AuditAction.LOGIN_SUCCEEDED)]
    assert entry.details == {"method": "guest"}


@pytest.mark.usefixtures("guest_on")
def test_the_guest_can_read_but_not_act(db_client: TestClient, db_session: Session) -> None:
    guest = make_user(db_session, Role.VIEWER, email=GUEST)
    assert db_client.get("/api/alerts", headers=bearer(guest)).status_code == 200
    assert db_client.post("/api/sources", headers=bearer(guest), json={}).status_code == 403


@pytest.mark.usefixtures("guest_on")
@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/auth/change-password", {"current_password": "x" * 12, "new_password": "y" * 12}),
        ("/api/auth/mfa/setup", None),
        ("/api/auth/mfa/enable", {"code": "123456"}),
    ],
)
def test_nobody_can_lock_the_other_visitors_out(
    db_client: TestClient, db_session: Session, path: str, body: dict[str, str] | None
) -> None:
    guest = make_user(db_session, Role.VIEWER, email=GUEST)
    response = db_client.post(path, headers=bearer(guest), json=body)
    assert response.status_code == 403
    assert "guest account" in response.json()["error"]["message"]


@pytest.mark.usefixtures("guest_on")
@pytest.mark.parametrize(
    ("setup", "reason"),
    [
        (None, "guest_missing"),
        ({"role": Role.ANALYST}, "guest_not_viewer"),
        ({"role": Role.ADMIN}, "guest_not_viewer"),
        ({"role": Role.VIEWER, "is_active": False}, "guest_disabled"),
    ],
)
def test_a_misconfigured_guest_is_refused_never_used(
    db_client: TestClient, db_session: Session, setup: dict[str, object] | None, reason: str
) -> None:
    if setup is not None:
        make_user(db_session, email=GUEST, **setup)  # type: ignore[arg-type]
    response = db_client.post("/api/auth/guest")
    assert response.status_code == 403
    assert response.json()["error"]["message"] == "Guest access is not available"
    (entry,) = audit_entries(db_session, AuditAction.LOGIN_FAILED)
    assert entry.details == {"reason": reason}


def test_other_users_are_not_guests(db_client: TestClient, db_session: Session) -> None:
    user = make_user(db_session, Role.VIEWER)
    assert db_client.get("/api/auth/me", headers=bearer(user)).json()["is_guest"] is False


# ---------- the startup command ----------


@pytest.mark.usefixtures("guest_on")
def test_ensure_guest_creates_a_viewer_once(
    cli_sessions: Session, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["ensure-guest"]) == 0
    assert "created (VIEWER, read-only)" in capsys.readouterr().out
    guest = cli_sessions.query(User).filter_by(email=GUEST).one()
    assert guest.role == Role.VIEWER and guest.is_active
    assert cli.main(["ensure-guest"]) == 0
    assert "ready" in capsys.readouterr().out


@pytest.mark.usefixtures("guest_on")
def test_ensure_guest_refuses_an_existing_privileged_account(
    cli_sessions: Session, capsys: pytest.CaptureFixture[str]
) -> None:
    make_user(cli_sessions, Role.ADMIN, email=GUEST)
    assert cli.main(["ensure-guest"]) == 1
    assert "not an active VIEWER" in capsys.readouterr().err


def test_ensure_guest_needs_the_setting(
    cli_sessions: Session, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["ensure-guest"]) == 1
    assert "GUEST_EMAIL is not set" in capsys.readouterr().err
