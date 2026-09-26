"""Ingestion end to end against a real PostgreSQL: sources, the ingest endpoint, batch reports,
the events it produced, enrichment, duplicates, limits and the CLI."""

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import cli
from app.core.config import get_settings
from app.demo.scenarios import brute_force
from app.models.context import Asset, Identity
from app.models.event import Event, IngestionBatch, RawEvent
from app.models.user import Role
from tests.helpers import audit_entries, bearer, make_user

pytestmark = pytest.mark.integration

NOW = datetime.now(UTC).replace(microsecond=0)


def syslog(
    moment: datetime, message: str, host: str = "web-01", program: str = "sshd[4122]"
) -> str:
    return f"{moment.isoformat()} {host} {program}: {message}"


FAILED = "Failed password for root from 203.0.113.45 port 50412 ssh2"
ACCEPTED = "Accepted publickey for alice from 10.0.2.42 port 52000 ssh2"


@pytest.fixture
def admin(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.ADMIN, email="admin@example.com"))


@pytest.fixture
def analyst(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.ANALYST, email="analyst@example.com"))


@pytest.fixture
def viewer(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.VIEWER))


def create_source(client: TestClient, admin: dict[str, str], **fields: Any) -> dict[str, Any]:
    body = {"name": "web-01 auth.log", "source_type": "linux_auth", **fields}
    response = client.post("/api/sources", json=body, headers=admin)
    assert response.status_code == 201, response.text
    return dict(response.json())


def send(client: TestClient, headers: dict[str, str], source_id: str, records: list[str]) -> Any:
    return client.post(f"/api/ingest/{source_id}", json={"records": records}, headers=headers)


# ---------- sources ----------


def test_source_lifecycle_is_audited(
    db_client: TestClient, db_session: Session, admin: dict[str, str]
) -> None:
    source = create_source(db_client, admin, timezone="Asia/Kolkata", default_host="WEB-01")
    assert (source["timezone"], source["default_host"], source["enabled"]) == (
        "Asia/Kolkata",
        "web-01",
        True,
    )
    response = db_client.patch(
        f"/api/sources/{source['id']}", json={"enabled": False}, headers=admin
    )
    assert response.json()["enabled"] is False
    assert len(audit_entries(db_session, "SOURCE_CREATED")) == 1
    (updated,) = audit_entries(db_session, "SOURCE_UPDATED")
    assert updated.details["changes"] == {"enabled": {"from": True, "to": False}}


@pytest.mark.parametrize(
    "body",
    [
        {"name": "x", "source_type": "syslog"},
        {"name": "x", "source_type": "linux_auth", "timezone": "Mars/Olympus"},
        {"name": "x", "source_type": "linux_auth", "default_host": "not a host"},
        {"name": "   ", "source_type": "linux_auth"},
        {"name": "x", "source_type": "linux_auth", "parser": "custom"},
    ],
    ids=["type", "timezone", "host", "blank-name", "unknown-field"],
)
def test_invalid_sources_are_rejected(
    db_client: TestClient, admin: dict[str, str], body: dict[str, str]
) -> None:
    assert db_client.post("/api/sources", json=body, headers=admin).status_code == 422


def test_source_type_cannot_change_and_names_are_unique(
    db_client: TestClient, admin: dict[str, str]
) -> None:
    source = create_source(db_client, admin)
    changed = db_client.patch(
        f"/api/sources/{source['id']}", json={"source_type": "http_access"}, headers=admin
    )
    assert changed.status_code == 422
    again = db_client.post(
        "/api/sources", json={"name": "web-01 auth.log", "source_type": "app_json"}, headers=admin
    )
    assert again.status_code == 409


# ---------- ingesting ----------


def test_a_mixed_batch_is_counted_record_by_record(
    db_client: TestClient, db_session: Session, admin: dict[str, str], analyst: dict[str, str]
) -> None:
    source = create_source(db_client, admin)
    records = [
        syslog(NOW - timedelta(minutes=3), FAILED),
        syslog(NOW - timedelta(minutes=2), ACCEPTED),
        syslog(
            NOW - timedelta(minutes=2), "Connection closed by 203.0.113.45 port 50412 [preauth]"
        ),
        "garbage that is not syslog",
        syslog(NOW - timedelta(minutes=3), FAILED),  # same record again within the batch
    ]
    response = send(db_client, analyst, source["id"], records)
    assert response.status_code == 201
    batch = response.json()
    assert (
        batch["received_count"],
        batch["parsed_count"],
        batch["skipped_count"],
        batch["failed_count"],
        batch["duplicate_count"],
        batch["rejected_count"],
    ) == (5, 2, 1, 1, 1, 0)
    assert batch["issues"] == [{"index": 3, "status": "FAILED", "code": "unrecognized_format"}]
    assert batch["channel"] == "api"
    assert batch["first_event_at"] < batch["last_event_at"]

    # Every stored record is kept, whatever its outcome: 4 raw rows, 2 events.
    assert db_session.scalar(select(func.count()).select_from(RawEvent)) == 4
    assert db_session.scalar(select(func.count()).select_from(Event)) == 2


def test_resending_the_same_records_stores_nothing_new(
    db_client: TestClient, admin: dict[str, str], analyst: dict[str, str]
) -> None:
    source = create_source(db_client, admin)
    records = [syslog(NOW - timedelta(minutes=1), FAILED), syslog(NOW, ACCEPTED)]
    send(db_client, analyst, source["id"], records)
    second = send(db_client, analyst, source["id"], records).json()
    assert (second["duplicate_count"], second["parsed_count"]) == (2, 0)


def test_enrichment_uses_the_inventory(
    db_client: TestClient, db_session: Session, admin: dict[str, str], analyst: dict[str, str]
) -> None:
    db_session.add(
        Asset(
            hostname="web-01.corp.example",
            asset_type="server",
            environment="production",
            criticality="critical",
        )
    )
    db_session.add(Identity(username="alice", privilege_level="privileged"))
    db_session.commit()
    source = create_source(db_client, admin)
    send(db_client, analyst, source["id"], [syslog(NOW, ACCEPTED), syslog(NOW, FAILED)])

    by_user = {e.username: e for e in db_session.scalars(select(Event))}
    alice, root = by_user["alice"], by_user["root"]
    assert (alice.source_ip_scope, alice.asset_criticality, alice.identity_privileged) == (
        "internal",
        "critical",  # "web-01" in the log matched "web-01.corp.example" in the inventory
        True,
    )
    assert (root.source_ip_scope, root.identity_id) == ("external", None)


def test_text_plain_bodies_are_one_record_per_line(
    db_client: TestClient, admin: dict[str, str], analyst: dict[str, str]
) -> None:
    source = create_source(db_client, admin)
    body = (syslog(NOW, FAILED) + "\r\n\r\n" + syslog(NOW, ACCEPTED) + "\n").encode()
    response = db_client.post(
        f"/api/ingest/{source['id']}",
        content=body,
        headers={**analyst, "Content-Type": "text/plain; charset=utf-8"},
    )
    assert response.status_code == 201
    assert (response.json()["received_count"], response.json()["channel"]) == (2, "text")


def test_bytes_that_are_not_utf8_are_stored_and_reported(
    db_client: TestClient, db_session: Session, admin: dict[str, str], analyst: dict[str, str]
) -> None:
    source = create_source(db_client, admin)
    response = db_client.post(
        f"/api/ingest/{source['id']}",
        content=b"Sep 25 10:31:02 web-01 sshd[1]: caf\xe9\n",
        headers={**analyst, "Content-Type": "text/plain"},
    )
    assert response.json()["issues"] == [{"index": 0, "status": "FAILED", "code": "not_utf8"}]
    raw = db_session.scalar(select(RawEvent))
    assert raw is not None and raw.raw_data.endswith(b"caf\xe9")


def test_disabled_source_refuses_records_and_audits_it(
    db_client: TestClient, db_session: Session, admin: dict[str, str], analyst: dict[str, str]
) -> None:
    source = create_source(db_client, admin)
    db_client.patch(f"/api/sources/{source['id']}", json={"enabled": False}, headers=admin)
    response = send(db_client, analyst, source["id"], [syslog(NOW, FAILED)])
    assert response.status_code == 409
    (entry,) = audit_entries(db_session, "INGEST_REJECTED")
    assert entry.details == {"reason": "source_disabled"}
    assert db_session.scalar(select(func.count()).select_from(IngestionBatch)) == 0


@pytest.fixture
def small_limits(app: FastAPI) -> None:
    limited = get_settings().model_copy(update={"ingest_max_bytes": 2048, "ingest_max_records": 3})
    app.dependency_overrides[get_settings] = lambda: limited


@pytest.mark.usefixtures("small_limits")
def test_limits_are_enforced_before_anything_is_stored(
    db_client: TestClient, db_session: Session, admin: dict[str, str], analyst: dict[str, str]
) -> None:
    source = create_source(db_client, admin)
    too_many = send(db_client, analyst, source["id"], [syslog(NOW, FAILED)] * 4)
    too_big = send(db_client, analyst, source["id"], ["x" * 3000])
    assert (too_many.status_code, too_big.status_code) == (413, 413)
    assert too_big.json()["error"]["code"] == "payload_too_large"
    reasons = [e.details["reason"] for e in audit_entries(db_session, "INGEST_REJECTED")]
    assert sorted(reasons) == ["payload_too_large", "too_many_records"]
    assert db_session.scalar(select(func.count()).select_from(RawEvent)) == 0


def test_a_record_too_large_to_store_is_rejected_on_its_own(
    db_client: TestClient, admin: dict[str, str], analyst: dict[str, str]
) -> None:
    source = create_source(db_client, admin)
    batch = send(db_client, analyst, source["id"], [syslog(NOW, FAILED), "y" * 70_000]).json()
    assert (batch["parsed_count"], batch["rejected_count"]) == (1, 1)
    assert batch["issues"] == [{"index": 1, "status": "REJECTED", "code": "record_too_large"}]


@pytest.mark.parametrize(
    ("content", "content_type", "status"),
    [
        (b'{"records": []}', "application/json", 422),
        (b'{"records": [1, 2]}', "application/json", 422),
        (b"not json", "application/json", 422),
        (b"<xml/>", "application/xml", 415),
    ],
    ids=["empty", "not-strings", "invalid-json", "wrong-type"],
)
def test_malformed_requests_are_refused(
    db_client: TestClient,
    admin: dict[str, str],
    analyst: dict[str, str],
    content: bytes,
    content_type: str,
    status: int,
) -> None:
    source = create_source(db_client, admin)
    response = db_client.post(
        f"/api/ingest/{source['id']}",
        content=content,
        headers={**analyst, "Content-Type": content_type},
    )
    assert response.status_code == status


def test_unknown_source_is_404(db_client: TestClient, analyst: dict[str, str]) -> None:
    response = send(db_client, analyst, "00000000-0000-0000-0000-000000000000", ["x"])
    assert response.status_code == 404


# ---------- batch reports and events ----------


def test_batch_report_lists_its_records_by_outcome(
    db_client: TestClient, admin: dict[str, str], analyst: dict[str, str], viewer: dict[str, str]
) -> None:
    source = create_source(db_client, admin)
    batch = send(
        db_client, analyst, source["id"], [syslog(NOW, FAILED), "<b>not syslog</b>"]
    ).json()
    listed = db_client.get("/api/ingest/batches", headers=viewer).json()
    assert [b["id"] for b in listed["items"]] == [batch["id"]]
    failed = db_client.get(
        f"/api/ingest/batches/{batch['id']}/records",
        params={"parse_status": "FAILED"},
        headers=viewer,
    ).json()
    (record,) = failed["items"]
    assert (record["text"], record["parse_detail"], record["truncated"]) == (
        "<b>not syslog</b>",  # shown as text; the UI never renders it as HTML
        "unrecognized_format",
        False,
    )


def test_events_list_filters_and_pages_with_a_cursor(
    db_client: TestClient, admin: dict[str, str], analyst: dict[str, str], viewer: dict[str, str]
) -> None:
    source = create_source(db_client, admin)
    lines = brute_force(NOW - timedelta(minutes=30), attempts=5)
    send(db_client, analyst, source["id"], [*lines, syslog(NOW - timedelta(minutes=1), ACCEPTED)])

    first = db_client.get(
        "/api/events", params={"source_ip": "203.0.113.45", "limit": 3}, headers=viewer
    ).json()
    assert len(first["items"]) == 3 and first["next_cursor"]
    second = db_client.get(
        "/api/events",
        params={"source_ip": "203.0.113.45", "limit": 3, "cursor": first["next_cursor"]},
        headers=viewer,
    ).json()
    assert len(second["items"]) == 2 and second["next_cursor"] is None
    times = [e["timestamp"] for e in first["items"] + second["items"]]
    assert times == sorted(times, reverse=True)  # newest first, no gaps, no repeats
    assert len({e["id"] for e in first["items"] + second["items"]}) == 5

    success = db_client.get(
        "/api/events", params={"outcome": "success", "username": "ALICE"}, headers=viewer
    ).json()
    assert [e["username"] for e in success["items"]] == ["alice"]


def test_events_default_to_the_last_24_hours(
    db_client: TestClient, admin: dict[str, str], analyst: dict[str, str], viewer: dict[str, str]
) -> None:
    source = create_source(db_client, admin)
    old = syslog(NOW - timedelta(days=3), FAILED)
    send(db_client, analyst, source["id"], [old, syslog(NOW - timedelta(hours=1), ACCEPTED)])
    recent = db_client.get("/api/events", headers=viewer).json()
    assert [e["username"] for e in recent["items"]] == ["alice"]
    earlier = db_client.get(
        "/api/events",
        params={"from": (NOW - timedelta(days=4)).isoformat(), "to": NOW.isoformat()},
        headers=viewer,
    ).json()
    assert len(earlier["items"]) == 2


@pytest.mark.parametrize(
    "params",
    [
        {"from": "2026-01-01T00:00:00Z", "to": "2026-03-01T00:00:00Z"},
        {"from": "2026-03-01T00:00:00Z", "to": "2026-01-01T00:00:00Z"},
        {"cursor": "not-a-cursor"},
        {"source_ip": "300.1.1.1"},
    ],
    ids=["range-too-long", "range-reversed", "bad-cursor", "bad-ip"],
)
def test_invalid_event_queries_are_400(
    db_client: TestClient, viewer: dict[str, str], params: dict[str, str]
) -> None:
    response = db_client.get("/api/events", params=params, headers=viewer)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "bad_request"


def test_event_detail_includes_the_raw_record(
    db_client: TestClient, admin: dict[str, str], analyst: dict[str, str], viewer: dict[str, str]
) -> None:
    source = create_source(db_client, admin)
    line = syslog(NOW, FAILED)
    send(db_client, analyst, source["id"], [line])
    (item,) = db_client.get("/api/events", headers=viewer).json()["items"]
    detail = db_client.get(f"/api/events/{item['id']}", headers=viewer).json()
    assert detail["raw"]["text"] == line
    assert detail["raw"]["parse_status"] == "PARSED"
    assert detail["source_name"] == "web-01 auth.log"
    assert detail["attributes"] == {"auth_method": "password", "invalid_user": False}
    missing = db_client.get("/api/events/00000000-0000-0000-0000-000000000000", headers=viewer)
    assert missing.status_code == 404


# ---------- CLI ----------


def test_cli_creates_a_source_ingests_a_file_and_a_simulated_scenario(
    cli_sessions: Session, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["create-source", "--name", "cli-auth", "--type", "linux_auth"]) == 0
    log = tmp_path / "auth.log"
    log.write_bytes((syslog(NOW, FAILED) + "\n" + syslog(NOW, ACCEPTED) + "\n").encode())
    assert cli.main(["ingest-file", "--source", "cli-auth", "--file", str(log)]) == 0
    assert "parsed 2" in capsys.readouterr().out

    start = (NOW - timedelta(hours=1)).isoformat()
    assert (
        cli.main(
            ["demo-ingest", "--scenario", "brute_force", "--source", "cli-auth", "--start", start]
        )
        == 0
    )
    assert "SIMULATED" in capsys.readouterr().out
    simulated = cli_sessions.scalars(select(Event).where(Event.simulated)).all()
    assert len(simulated) == 12
    batches = {b.channel: b for b in cli_sessions.scalars(select(IngestionBatch))}
    assert set(batches) == {"cli", "demo"} and batches["demo"].simulated


@pytest.mark.parametrize(
    "argv",
    [
        ["create-source", "--name", "x", "--type", "syslog"],
        ["ingest-file", "--source", "missing", "--file", "nope.log"],
        ["demo-ingest", "--scenario", "nope", "--source", "x"],
        ["demo-ingest", "--scenario", "benign", "--source", "x", "--start", "2026-09-25T09:00"],
    ],
    ids=["bad-type", "missing-file", "bad-scenario", "naive-start"],
)
def test_cli_errors_exit_non_zero(cli_sessions: Session, argv: list[str]) -> None:
    assert cli.main(argv) == 1


def test_json_sources_accept_ndjson(
    db_client: TestClient, admin: dict[str, str], analyst: dict[str, str]
) -> None:
    source = create_source(
        db_client, admin, name="billing", source_type="app_json", default_host="app-01"
    )
    lines = [
        json.dumps(
            {"ts": NOW.isoformat(), "event": "login_failure", "user": "bob", "ip": "203.0.113.9"}
        ),
        json.dumps({"ts": NOW.isoformat(), "event": "teleport", "user": "bob"}),
    ]
    response = db_client.post(
        f"/api/ingest/{source['id']}",
        content="\n".join(lines).encode(),
        headers={**analyst, "Content-Type": "text/plain"},
    )
    batch = response.json()
    assert (batch["parsed_count"], batch["failed_count"]) == (1, 1)
    assert batch["issues"][0]["code"] == "unknown_event_type"


def test_cli_demo_options_shape_the_simulated_data(
    cli_sessions: Session, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["create-source", "--name", "demo-src", "--type", "linux_auth"]) == 0
    start = (NOW - timedelta(hours=2)).isoformat()
    argv = ["demo-ingest", "--scenario", "brute_force", "--source", "demo-src", "--start", start]
    options = ["--host", "db-01", "--user", "oracle", "--source-ip", "192.0.2.10", "--count", "5"]
    assert cli.main(argv + options) == 0
    events = cli_sessions.scalars(select(Event).where(Event.simulated)).all()
    assert {(e.host, e.username, str(e.source_ip)) for e in events} == {
        ("db-01", "oracle", "192.0.2.10")
    }
    assert len(events) == 5
    # An option the scenario cannot use is refused, not silently ignored.
    assert (
        cli.main(["demo-ingest", "--scenario", "benign", "--source", "demo-src", "--user", "x"])
        == 1
    )
    assert "does not use --user" in capsys.readouterr().err


def test_cli_lists_the_demo_scenarios(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["demo-scenarios"]) == 0
    listing = capsys.readouterr().out
    assert "brute_force_success" in listing and "--count = accounts tried" in listing
