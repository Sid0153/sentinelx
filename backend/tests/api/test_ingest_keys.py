"""Phase 13: per-source ingest keys for log shippers, the per-source ingest rate limit, and the
backend's own request body limit."""

import logging
from collections.abc import Iterator

import httpx2
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import cli
from app.core.rate_limit import RateLimiter
from app.models.audit_log import AuditLog
from app.models.event import IngestionBatch, LogSource, RawEvent
from app.models.user import Role
from tests.helpers import audit_entries, bearer, make_user

pytestmark = pytest.mark.integration

LINE = (
    "2026-10-01T08:00:00+00:00 web-01 sshd[4122]: "
    "Failed password for root from 203.0.113.45 port 50412 ssh2"
)


@pytest.fixture
def admin(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.ADMIN, email="admin@example.com"))


@pytest.fixture
def viewer(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.VIEWER, email="viewer@example.com"))


def new_source(client: TestClient, admin: dict[str, str], name: str) -> str:
    response = client.post(
        "/api/sources", json={"name": name, "source_type": "linux_auth"}, headers=admin
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def issue(client: TestClient, admin: dict[str, str], source_id: str) -> str:
    response = client.post(f"/api/sources/{source_id}/ingest-key", headers=admin)
    assert response.status_code == 201, response.text
    return str(response.json()["key"])


def ship(client: TestClient, source_id: str, key: str, line: str = LINE) -> httpx2.Response:
    return client.post(
        f"/api/ingest/{source_id}",
        content=line,
        headers={"X-Ingest-Key": key, "Content-Type": "text/plain"},
    )


def test_a_shipper_sends_logs_with_its_sources_key(
    db_client: TestClient, db_session: Session, admin: dict[str, str], viewer: dict[str, str]
) -> None:
    source_id = new_source(db_client, admin, "web-01 auth")
    response = db_client.post(f"/api/sources/{source_id}/ingest-key", headers=admin)
    issued = response.json()
    key = issued["key"]
    assert key.startswith("sxk_") and len(key) >= 40
    assert key.startswith(issued["key_prefix"]) and len(issued["key_prefix"]) == 10

    # Anyone signed in sees that there is a key and its prefix, never the key or its hash.
    shown = db_client.get(f"/api/sources/{source_id}", headers=viewer).json()
    assert shown["ingest_key_prefix"] == issued["key_prefix"]
    assert key not in str(shown) and "hash" not in str(shown)

    response = ship(db_client, source_id, key)  # no user session at all
    assert response.status_code == 201, response.text
    batch = db_session.get(IngestionBatch, response.json()["id"])
    assert batch is not None and batch.submitted_by is None
    assert batch.ingest_key_prefix == issued["key_prefix"]
    source = db_session.get(LogSource, source_id)
    assert source is not None and source.ingest_key_last_used_at is not None
    (entry,) = audit_entries(db_session, "INGEST_KEY_ISSUED")
    assert entry.details == {
        "source": "web-01 auth",
        "key_prefix": issued["key_prefix"],
        "rotated": False,
    }


def test_a_key_works_for_its_own_source_only(
    db_client: TestClient, db_session: Session, admin: dict[str, str]
) -> None:
    first = new_source(db_client, admin, "first")
    second = new_source(db_client, admin, "second")
    key = issue(db_client, admin, first)
    before = db_session.query(RawEvent).count()
    for source_id, sent in ((second, key), (first, "sxk_not-a-real-key"), (first, "garbage")):
        response = ship(db_client, source_id, sent)
        assert response.status_code == 401, response.text
    assert db_session.query(RawEvent).count() == before  # nothing stored
    refused = audit_entries(db_session, "INGEST_REJECTED")
    assert [e.details["reason"] for e in refused] == ["invalid_ingest_key"] * 3
    assert all(e.actor_id is None for e in refused)


def test_rotation_and_revocation_end_the_old_key(
    db_client: TestClient, db_session: Session, admin: dict[str, str]
) -> None:
    source_id = new_source(db_client, admin, "rotating")
    old = issue(db_client, admin, source_id)
    new = issue(db_client, admin, source_id)
    assert ship(db_client, source_id, old).status_code == 401
    assert ship(db_client, source_id, new).status_code == 201
    entries = audit_entries(db_session, "INGEST_KEY_ISSUED")
    assert sorted(e.details["rotated"] for e in entries) == [False, True]

    assert (
        db_client.delete(f"/api/sources/{source_id}/ingest-key", headers=admin).status_code == 204
    )
    assert ship(db_client, source_id, new).status_code == 401
    assert (
        db_client.delete(f"/api/sources/{source_id}/ingest-key", headers=admin).status_code == 404
    )
    (revoked,) = audit_entries(db_session, "INGEST_KEY_REVOKED")
    assert revoked.details["key_prefix"] == new[:10]


def test_keys_are_issued_by_admins_only(
    db_client: TestClient, admin: dict[str, str], viewer: dict[str, str], db_session: Session
) -> None:
    source_id = new_source(db_client, admin, "guarded")
    analyst = bearer(make_user(db_session, Role.ANALYST, email="analyst@example.com"))
    for headers in (viewer, analyst):
        assert (
            db_client.post(f"/api/sources/{source_id}/ingest-key", headers=headers).status_code
            == 403
        )
    # Without a key header, ingest still needs an analyst session.
    plain = {"Content-Type": "text/plain"}
    assert (
        db_client.post(f"/api/ingest/{source_id}", content=LINE, headers=plain).status_code == 401
    )
    assert (
        db_client.post(
            f"/api/ingest/{source_id}", content=LINE, headers={**plain, **viewer}
        ).status_code
        == 403
    )


def test_the_key_is_never_logged_or_audited(
    db_client: TestClient,
    db_session: Session,
    admin: dict[str, str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    source_id = new_source(db_client, admin, "secretive")
    key = issue(db_client, admin, source_id)
    ship(db_client, source_id, key)
    ship(db_client, source_id, key + "x")  # a wrong key: refused and audited
    assert key not in caplog.text
    audit_text = " ".join(str(e.details) for e in db_session.scalars(select(AuditLog)))
    assert key not in audit_text and key[10:] not in audit_text


def test_each_source_has_an_ingest_rate_limit(
    app: FastAPI, db_client: TestClient, db_session: Session, admin: dict[str, str]
) -> None:
    app.state.ingest_limiter = RateLimiter("ingest", 2)
    noisy = new_source(db_client, admin, "noisy")
    quiet = new_source(db_client, admin, "quiet")
    key = issue(db_client, admin, noisy)
    assert [ship(db_client, noisy, key, f"{LINE} {i}").status_code for i in range(3)] == [
        201,
        201,
        429,
    ]
    limited = ship(db_client, noisy, key)
    assert limited.status_code == 429 and limited.headers["Retry-After"] == "60"
    other = issue(db_client, admin, quiet)
    assert ship(db_client, quiet, other).status_code == 201  # per source, not global
    reasons = [e.details["reason"] for e in audit_entries(db_session, "INGEST_REJECTED")]
    assert reasons.count("rate_limited") == 2


def test_cli_issues_a_working_key(
    cli_sessions: Session,
    capsys: pytest.CaptureFixture[str],
    db_client: TestClient,
    admin: dict[str, str],
) -> None:
    source_id = new_source(db_client, admin, "cli source")
    assert cli.main(["issue-ingest-key", "--source", "cli source"]) == 0
    key = capsys.readouterr().out.strip().splitlines()[-1]
    assert key.startswith("sxk_")
    assert ship(db_client, source_id, key).status_code == 201
    assert cli.main(["issue-ingest-key", "--source", "no such source"]) == 1


# ---------- request body limit ----------


def test_bodies_over_the_limit_are_refused_before_they_are_read(
    db_client: TestClient, viewer: dict[str, str]
) -> None:
    big = b'{"time_range": {"last": "24h"}, "filters": [], "pad": "' + b"x" * (1024 * 1024) + b'"}'
    response = db_client.post(
        "/api/hunt/query", content=big, headers={**viewer, "Content-Type": "application/json"}
    )
    assert response.status_code == 413
    error = response.json()["error"]
    assert error["code"] == "payload_too_large" and error["request_id"]
    assert response.headers["X-Request-ID"] == error["request_id"]

    def chunks() -> Iterator[bytes]:  # no Content-Length: counted as it streams
        yield b'{"time_range": {"last": "24h"}, "pad": "'
        for _ in range(20):
            yield b"x" * 65536
        yield b'"}'

    response = db_client.post(
        "/api/hunt/query", content=chunks(), headers={**viewer, "Content-Type": "application/json"}
    )
    assert response.status_code == 413


def test_anonymous_requests_cannot_send_large_bodies_either(db_client: TestClient) -> None:
    response = db_client.post(
        "/api/auth/login",
        content=b"x" * (2 * 1024 * 1024),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413


def test_ingest_keeps_its_own_larger_limit(db_client: TestClient, admin: dict[str, str]) -> None:
    source_id = new_source(db_client, admin, "big batch")
    key = issue(db_client, admin, source_id)
    lines = "\n".join(f"{LINE} n{i:06d}" for i in range(12_000))  # about 1.5 MB, under 5 MB
    assert len(lines.encode()) > 1024 * 1024
    response = ship(db_client, source_id, key, lines)
    # Over 1 MiB but within the ingest limit: not refused by size (5,000 records is the
    # per-request record limit, so this is refused for its record count instead).
    assert response.status_code == 413
    assert "records" in response.json()["error"]["message"]


# ---------- host allowlist ----------


def test_a_source_only_speaks_for_its_allowed_hosts(
    db_client: TestClient, db_session: Session, admin: dict[str, str]
) -> None:
    response = db_client.post(
        "/api/sources",
        json={
            "name": "web tier",
            "source_type": "linux_auth",
            "allowed_hosts": ["WEB-01", "web-01"],
        },
        headers=admin,
    )
    assert response.status_code == 201, response.text
    source = response.json()
    assert source["allowed_hosts"] == ["web-01"]  # canonical and de-duplicated
    key = issue(db_client, admin, source["id"])
    forged = LINE.replace("web-01", "dc-01")  # a compromised shipper speaking for another host
    batch = ship(db_client, source["id"], key, f"{LINE}\n{forged}").json()
    assert (batch["parsed_count"], batch["failed_count"]) == (1, 1)
    assert batch["issues"] == [{"index": 1, "status": "FAILED", "code": "host_not_allowed"}]
    stored = db_session.scalars(select(RawEvent).where(RawEvent.batch_id == batch["id"])).all()
    assert sorted(r.parse_status for r in stored) == ["FAILED", "PARSED"]  # kept as evidence

    # An admin can widen the list; the change is audited.
    response = db_client.patch(
        f"/api/sources/{source['id']}", json={"allowed_hosts": ["web-01", "dc-01"]}, headers=admin
    )
    assert response.json()["allowed_hosts"] == ["dc-01", "web-01"]
    (changed,) = audit_entries(db_session, "SOURCE_UPDATED")
    assert changed.details["changes"]["allowed_hosts"]["to"] == ["dc-01", "web-01"]
    batch = ship(db_client, source["id"], key, forged.replace("50412", "50413")).json()
    assert batch["parsed_count"] == 1
