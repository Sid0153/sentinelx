"""Threat hunting over the stored events (docs/threat-hunting.md): the brief's example
questions answered from real ingested data, keyset paging that stays stable while events
arrive, the capped count, alert filters, every template against its scenario and against
benign activity, the statement timeout, and saved hunts with their object-level access."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError
from app.demo.scenarios import generate
from app.detection.library import Library
from app.hunting import service, templates
from app.models.audit_log import AuditLog
from app.models.hunt import SavedHunt
from app.models.user import Role
from tests.helpers import bearer, make_user

pytestmark = pytest.mark.integration

NOW = datetime.now(UTC).replace(microsecond=0)
START = NOW - timedelta(hours=2)
LAST_DAY = {"last": "24h"}


@pytest.fixture
def admin(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.ADMIN, email="admin@example.com"))


@pytest.fixture
def analyst(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.ANALYST, email="analyst@example.com"))


@pytest.fixture
def other_analyst(db_session: Session) -> dict[str, str]:
    return bearer(make_user(db_session, Role.ANALYST, email="other@example.com"))


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


def hunt(client: TestClient, headers: dict[str, str], **body: Any) -> dict[str, Any]:
    body.setdefault("time_range", LAST_DAY)
    response = client.post("/api/hunt/query", json=body, headers=headers)
    assert response.status_code == 200, response.text
    return dict(response.json())


def run_template(
    client: TestClient, headers: dict[str, str], template_id: str, **params: int
) -> dict[str, Any]:
    response = client.post(
        f"/api/hunt/templates/{template_id}/run",
        json={"params": params, "time_range": {"last": "31d"}},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return dict(response.json())


# ---------- queries ----------


def test_successful_logons_from_one_source_in_the_last_24_hours(
    db_client: TestClient, seeded_rules: Library, admin: dict[str, str], viewer: dict[str, str]
) -> None:
    """The brief's example question, on real ingested data."""
    ingest(db_client, admin, generate("brute_force_success", START))
    ingest(db_client, admin, generate("benign", START))
    result = hunt(
        db_client,
        viewer,
        filters=[
            {"field": "source_ip", "op": "eq", "value": "203.0.113.45"},
            {"field": "event_category", "op": "eq", "value": "authentication"},
            {"field": "event_action", "op": "eq", "value": "logon"},
            {"field": "event_outcome", "op": "eq", "value": "success"},
        ],
    )
    assert result["total"] == 1 and result["total_capped"] is False
    [event] = result["items"]
    assert (event["username"], event["source_ip"], event["host"]) == (
        "root",
        "203.0.113.45",
        "web-01",
    )

    # The same source has twelve failures before it, and none of the benign logons match.
    failures = hunt(
        db_client,
        viewer,
        filters=[
            {"field": "source_ip", "op": "eq", "value": "203.0.113.45"},
            {"field": "event_outcome", "op": "eq", "value": "failure"},
        ],
    )
    assert failures["total"] == 12
    internal = hunt(
        db_client,
        viewer,
        filters=[{"field": "source_ip", "op": "cidr", "value": "10.0.0.0/8"}],
    )
    assert internal["total"] > 0
    assert all(e["source_ip"].startswith("10.") for e in internal["items"])


@pytest.mark.parametrize(
    ("sort", "late_source"), [("newest", "198.51.100.9"), ("oldest", "198.51.100.10")]
)
def test_pages_are_stable_and_gap_free_while_events_arrive(
    db_client: TestClient,
    admin: dict[str, str],
    viewer: dict[str, str],
    sort: str,
    late_source: str,
) -> None:
    """12 events (sshd's preauth lines are skipped), paged 5 at a time. After the first page,
    2 newer events arrive inside the
    range: newest-first paging continues to older rows without repeating or skipping any;
    oldest-first paging reaches the new rows at the end."""
    ingest(db_client, admin, generate("brute_force", START))
    window = {"from": (START - timedelta(minutes=1)).isoformat(),
              "to": (START + timedelta(hours=1)).isoformat()}  # fmt: skip
    first = hunt(db_client, viewer, sort=sort, limit=5, time_range=window)
    assert first["total"] == 12
    late = generate("brute_force", START + timedelta(minutes=30), source_ip=late_source, count=2)
    ingest(db_client, admin, late)
    seen = [e["id"] for e in first["items"]]
    stamps = [e["timestamp"] for e in first["items"]]
    cursor = first["next_cursor"]
    while cursor:
        page = hunt(db_client, viewer, sort=sort, limit=5, time_range=window, cursor=cursor)
        seen += [e["id"] for e in page["items"]]
        stamps += [e["timestamp"] for e in page["items"]]
        cursor = page["next_cursor"]
    assert len(seen) == len(set(seen)), "a row appeared twice"
    assert stamps == sorted(stamps, reverse=sort == "newest")
    assert len(seen) == (12 if sort == "newest" else 14)


def test_the_count_stops_at_the_cap(
    db_client: TestClient,
    admin: dict[str, str],
    viewer: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ingest(db_client, admin, generate("brute_force", START))
    monkeypatch.setattr(service, "COUNT_CAP", 10)
    result = hunt(db_client, viewer, limit=3)
    assert (result["total"], result["total_capped"]) == (10, True)
    assert len(result["items"]) == 3 and result["next_cursor"]
    monkeypatch.setattr(service, "COUNT_CAP", 1000)
    assert hunt(db_client, viewer)["total"] == 12


def test_events_can_be_filtered_by_the_alerts_citing_them(
    db_client: TestClient, seeded_rules: Library, admin: dict[str, str], viewer: dict[str, str]
) -> None:
    ingest(db_client, admin, generate("brute_force_success", START))
    ingest(db_client, admin, generate("benign", START))
    cited = hunt(db_client, viewer, alert={"rule_ids": ["AUTH-002"]})
    assert cited["total"] > 0
    assert {e["source_ip"] for e in cited["items"]} == {"203.0.113.45"}
    none = hunt(db_client, viewer, alert={"in_alert": False},
                filters=[{"field": "source_ip", "op": "eq", "value": "203.0.113.45"},
                         {"field": "event_outcome", "op": "eq", "value": "success"}])  # fmt: skip
    assert none["total"] == 0  # the successful logon is evidence in AUTH-002
    benign = hunt(db_client, viewer, alert={"in_alert": False},
                  filters=[{"field": "username", "op": "eq", "value": "alice"}])  # fmt: skip
    assert benign["total"] > 0
    high = hunt(db_client, viewer, alert={"severities": ["critical"]})
    assert high["total"] == 0


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ({"filters": []}, 422),  # no time range
        ({"time_range": {"last": "60d"}}, 422),
        (
            {
                "time_range": LAST_DAY,
                "filters": [{"field": "password_hash", "op": "eq", "value": "x"}],
            },
            422,
        ),
        ({"time_range": LAST_DAY, "cursor": "not-a-cursor"}, 400),
    ],
)
def test_bad_queries_are_refused(
    db_client: TestClient, viewer: dict[str, str], body: dict[str, Any], status: int
) -> None:
    response = db_client.post("/api/hunt/query", json=body, headers=viewer)
    assert response.status_code == status, response.text
    assert "password_hash" not in response.text or status == 422


def test_the_field_list_describes_the_query_builder(
    db_client: TestClient, viewer: dict[str, str]
) -> None:
    data = db_client.get("/api/hunt/fields", headers=viewer).json()
    fields = {f["field"]: f for f in data["fields"]}
    assert fields["source_ip"]["kind"] == "ip" and "cidr" in fields["source_ip"]["operators"]
    assert "contains" not in fields["source_ip"]["operators"]
    assert fields["destination_port"]["kind"] == "number"
    assert "matches" not in fields["username"]["operators"]
    assert data["max_filters"] == 20 and data["max_range_days"] == 31


# ---------- templates ----------


def test_every_template_is_listed_with_its_parameters(
    db_client: TestClient, viewer: dict[str, str]
) -> None:
    listed = {t["id"]: t for t in db_client.get("/api/hunt/templates", headers=viewer).json()}
    assert set(listed) == set(templates.TEMPLATES)
    params = {p["name"]: p for p in listed["success_after_failures"]["params"]}
    assert params["min_failures"] == {
        "name": "min_failures", "description": "Failed logons before it",
        "default": 3, "minimum": 1, "maximum": 1000,
    }  # fmt: skip
    assert listed["first_seen_source_for_user"]["mirrors_rule"] == "AUTH-004"


def test_templates_find_their_scenario_and_nothing_in_benign_activity(
    db_client: TestClient, admin: dict[str, str], viewer: dict[str, str]
) -> None:
    # Benign: six working days on two hosts (same workstations every day).
    for host in ("web-01", "web-02"):
        ingest(db_client, admin, _benign_days(START - timedelta(days=6), host))
    for template_id in templates.TEMPLATES:
        assert run_template(db_client, viewer, template_id)["rows"] == [], template_id

    ingest(db_client, admin, generate("brute_force_success", START, user="alice"))
    ingest(db_client, admin, generate("password_spray", START))
    ingest(db_client, admin, generate("suspicious_process", START), kind="windows_security")

    [success] = run_template(db_client, viewer, "success_after_failures")["rows"]
    assert (success["username"], success["source_ip"], success["failures"]) == (
        "alice",
        "203.0.113.45",
        12,
    )
    assert success["event_id"]
    # A higher bar than the attack: nothing.
    assert run_template(db_client, viewer, "success_after_failures", min_failures=13)["rows"] == []

    [new_source] = run_template(db_client, viewer, "first_seen_source_for_user")["rows"]
    assert (new_source["username"], new_source["network"]) == ("alice", "203.0.113.0/24")
    assert new_source["history"] >= 5
    # An account needs history to be judged (AUTH-004's min_history).
    too_little = run_template(db_client, viewer, "first_seen_source_for_user", min_history=100)
    assert too_little["rows"] == []

    [spray] = run_template(db_client, viewer, "one_source_many_accounts")["rows"]
    assert (spray["source_ip"], spray["accounts"]) == ("198.51.100.23", 8)
    assert len(spray["sample_accounts"]) == 8

    rare = {
        r["process_name"] for r in run_template(db_client, viewer, "rare_process_on_host")["rows"]
    }
    assert "powershell.exe" in rare and "sshd" not in rare


def _benign_days(start: datetime, host: str) -> list[str]:
    lines: list[str] = []
    for day in range(6):
        lines += generate("benign", start + timedelta(days=day), host=host)
    return lines


@pytest.mark.parametrize(
    ("template_id", "params", "status"),
    [
        ("no_such_template", {}, 404),
        ("success_after_failures", {"min_failures": 0}, 422),
        ("success_after_failures", {"min_failures": "3; DROP TABLE events"}, 422),
        ("success_after_failures", {"unknown": 1}, 422),
    ],
)
def test_template_parameters_are_typed_and_bounded(
    db_client: TestClient,
    viewer: dict[str, str],
    template_id: str,
    params: dict[str, Any],
    status: int,
) -> None:
    response = db_client.post(
        f"/api/hunt/templates/{template_id}/run",
        json={"params": params, "time_range": LAST_DAY},
        headers=viewer,
    )
    assert response.status_code == status, response.text
    assert "DROP TABLE" not in response.text  # submitted values are never echoed


# ---------- statement timeout ----------


def test_a_slow_hunt_is_stopped_with_a_clear_error(
    db_client: TestClient,
    db_session: Session,
    viewer: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def slow(db: Session, *args: Any) -> tuple[list[dict[str, Any]], bool]:
        db.execute(text("SELECT pg_sleep(2)"))
        return [], False

    monkeypatch.setattr(templates, "run", slow)
    monkeypatch.setattr(get_settings(), "hunt_timeout_ms", 200)
    response = db_client.post(
        "/api/hunt/templates/rare_process_on_host/run",
        json={"params": {}, "time_range": LAST_DAY},
        headers=viewer,
    )
    assert response.status_code == 503, response.text
    error = response.json()["error"]
    assert error["code"] == "hunt_timeout"
    assert "longer than 0.2 s" in error["message"]


def test_the_timeout_applies_to_the_hunt_only(db_session: Session) -> None:
    with service.statement_timeout(db_session, 1234):
        assert db_session.scalar(text("SHOW statement_timeout")) == "1234ms"
    assert db_session.scalar(text("SHOW statement_timeout")) == "0"
    with pytest.raises(AppError) as caught, service.statement_timeout(db_session, 50):
        db_session.execute(text("SELECT pg_sleep(1)"))
    assert caught.value.status_code == 503


# ---------- saved hunts ----------

QUERY_DEFINITION = {
    "kind": "query",
    "query": {
        "time_range": {"last": "7d"},
        "filters": [{"field": "source_ip", "op": "eq", "value": "203.0.113.45"}],
    },
}


def save(
    client: TestClient, headers: dict[str, str], name: str = "Outside logons", **extra: Any
) -> Any:
    return client.post(
        "/api/hunt/saved",
        json={"name": name, "definition": QUERY_DEFINITION, **extra},
        headers=headers,
    )


def test_saved_hunts_are_private_until_shared(
    db_client: TestClient,
    analyst: dict[str, str],
    other_analyst: dict[str, str],
    viewer: dict[str, str],
) -> None:
    response = save(db_client, analyst)
    assert response.status_code == 201, response.text
    saved = response.json()
    assert saved["is_owner"] and saved["valid"] and not saved["shared"]
    assert saved["owner_email"] == "analyst@example.com"
    assert saved["definition"] == QUERY_DEFINITION  # as sent: no defaults added

    # Private: others do not see it, not even by ID.
    assert db_client.get("/api/hunt/saved", headers=other_analyst).json() == []
    assert db_client.get(f"/api/hunt/saved/{saved['id']}", headers=other_analyst).status_code == 404

    shared = db_client.patch(
        f"/api/hunt/saved/{saved['id']}", json={"shared": True}, headers=analyst
    )
    assert shared.status_code == 200 and shared.json()["shared"] is True
    for headers in (other_analyst, viewer):
        [listed] = db_client.get("/api/hunt/saved", headers=headers).json()
        assert listed["id"] == saved["id"] and listed["is_owner"] is False

    # Shared is read-only for everyone but the owner.
    assert (
        db_client.patch(
            f"/api/hunt/saved/{saved['id']}", json={"name": "x"}, headers=other_analyst
        ).status_code
        == 403
    )
    assert (
        db_client.delete(f"/api/hunt/saved/{saved['id']}", headers=other_analyst).status_code == 403
    )
    assert db_client.delete(f"/api/hunt/saved/{saved['id']}", headers=analyst).status_code == 204
    assert db_client.get("/api/hunt/saved", headers=analyst).json() == []


def test_viewers_hunt_but_do_not_save(db_client: TestClient, viewer: dict[str, str]) -> None:
    assert save(db_client, viewer).status_code == 403
    assert (
        db_client.post("/api/hunt/query", json={"time_range": LAST_DAY}, headers=viewer).status_code
        == 200
    )


def test_saved_hunt_names_are_unique_per_owner_and_definitions_validated(
    db_client: TestClient, analyst: dict[str, str], other_analyst: dict[str, str]
) -> None:
    assert save(db_client, analyst).status_code == 201
    assert save(db_client, analyst).status_code == 409
    assert save(db_client, other_analyst).status_code == 201  # another owner may reuse it
    for definition in (
        {"kind": "sql", "sql": "SELECT * FROM users"},
        {"kind": "template", "template_id": "nope", "time_range": {"last": "7d"}},
        {
            "kind": "template",
            "template_id": "success_after_failures",
            "params": {"min_failures": 0},
            "time_range": {"last": "7d"},
        },
        {"kind": "query", "query": {"filters": []}},
    ):
        response = db_client.post(
            "/api/hunt/saved", json={"name": "bad", "definition": definition}, headers=analyst
        )
        assert response.status_code == 422, definition
    template = {
        "kind": "template",
        "template_id": "one_source_many_accounts",
        "params": {"min_accounts": 3},
        "time_range": {"last": "7d"},
    }
    assert (
        db_client.post(
            "/api/hunt/saved", json={"name": "Spray", "definition": template}, headers=analyst
        ).status_code
        == 201
    )


def test_a_hunt_saved_by_an_older_version_is_flagged_not_run(
    db_client: TestClient, db_session: Session, analyst: dict[str, str]
) -> None:
    saved = save(db_client, analyst).json()
    row = db_session.get(SavedHunt, uuid.UUID(saved["id"]))
    assert row is not None
    row.definition = {
        "kind": "query",
        "query": {
            "time_range": {"last": "7d"},
            "filters": [{"field": "removed_field", "op": "eq", "value": "x"}],
        },
    }
    db_session.flush()
    [listed] = db_client.get("/api/hunt/saved", headers=analyst).json()
    assert listed["valid"] is False and "no longer matches" in listed["problem"]


def test_saved_hunt_changes_are_audited_without_filter_values(
    db_client: TestClient, db_session: Session, analyst: dict[str, str]
) -> None:
    saved = save(db_client, analyst).json()
    db_client.patch(
        f"/api/hunt/saved/{saved['id']}",
        json={"shared": True, "description": "for the team"},
        headers=analyst,
    )
    db_client.delete(f"/api/hunt/saved/{saved['id']}", headers=analyst)
    entries = {
        e.action: e
        for e in db_session.scalars(select(AuditLog).where(AuditLog.entity_id == saved["id"]))
    }
    assert set(entries) == {"HUNT_SAVED", "HUNT_UPDATED", "HUNT_DELETED"}
    assert entries["HUNT_UPDATED"].details["changed"] == ["description", "shared"]
    assert entries["HUNT_UPDATED"].details["shared"] is True
    for entry in entries.values():
        assert entry.actor_label == "analyst@example.com"
        assert "203.0.113.45" not in str(entry.details)


def test_saved_hunts_per_user_are_capped(
    db_client: TestClient,
    analyst: dict[str, str],
    other_analyst: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The saved-hunt list is not paged, so each user may keep a bounded number (Phase 14)."""
    monkeypatch.setattr("app.hunting.service.MAX_SAVED_PER_USER", 2)
    assert save(db_client, analyst, "one").status_code == 201
    assert save(db_client, analyst, "two").status_code == 201
    refused = save(db_client, analyst, "three")
    assert refused.status_code == 409
    assert "Delete one first" in refused.json()["error"]["message"]
    # The cap is per user, and deleting frees a place.
    assert save(db_client, other_analyst, "mine").status_code == 201
    first = db_client.get("/api/hunt/saved", headers=analyst).json()[0]
    assert db_client.delete(f"/api/hunt/saved/{first['id']}", headers=analyst).status_code == 204
    assert save(db_client, analyst, "three").status_code == 201
