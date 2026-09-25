"""Request IDs, security headers, the error shape and the request log, without a database."""

import json
import logging
from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.core.errors import AppError


class Payload(BaseModel):
    password: str
    count: int


@pytest.fixture
def probe_client(app: FastAPI) -> Iterator[TestClient]:
    """The real app plus a few routes that exercise error paths."""

    @app.post("/api/_probe/validate")
    def validate(payload: Payload) -> dict[str, int]:
        return {"count": payload.count}

    @app.get("/api/_probe/conflict")
    def conflict() -> None:
        raise AppError(409, "Alert is already resolved", headers={"X-Probe": "1"})

    @app.get("/api/_probe/crash")
    def crash() -> None:
        raise RuntimeError("database password=hunter2 exploded")

    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


def test_request_id_is_generated_and_returned(client: TestClient) -> None:
    response = client.get("/api/health")
    assert len(response.headers["X-Request-ID"]) == 36  # a UUID


def test_safe_caller_request_id_is_kept(client: TestClient) -> None:
    response = client.get("/api/health", headers={"X-Request-ID": "trace-0123456789"})
    assert response.headers["X-Request-ID"] == "trace-0123456789"


@pytest.mark.parametrize("unsafe", ["short", "has space-12345", "x" * 65, "evil;value123456"])
def test_unsafe_caller_request_id_is_replaced(client: TestClient, unsafe: str) -> None:
    response = client.get("/api/health", headers={"X-Request-ID": unsafe})
    assert response.headers["X-Request-ID"] != unsafe


def test_api_responses_carry_security_headers(client: TestClient) -> None:
    headers = client.get("/api/health").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["Cache-Control"] == "no-store"
    assert headers["Content-Security-Policy"] == "default-src 'none'; frame-ancestors 'none'"


def test_interactive_docs_are_not_given_the_strict_api_csp(client: TestClient) -> None:
    response = client.get("/api/docs")
    assert response.status_code == 200
    assert "Content-Security-Policy" not in response.headers


def test_unknown_route_uses_the_error_shape(client: TestClient) -> None:
    response = client.get("/api/does-not-exist", headers={"X-Request-ID": "trace-0123456789"})
    assert response.status_code == 404
    assert response.json() == {
        "error": {"code": "not_found", "message": "Not Found", "request_id": "trace-0123456789"}
    }


def test_wrong_method_uses_the_error_shape(client: TestClient) -> None:
    response = client.delete("/api/health")
    assert response.status_code == 405
    assert response.json()["error"]["code"] == "method_not_allowed"


def test_validation_error_lists_problems_without_echoing_input(probe_client: TestClient) -> None:
    response = probe_client.post(
        "/api/_probe/validate", json={"password": "hunter2-secret", "count": "not-a-number"}
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert error["details"][0]["loc"] == ["body", "count"]
    assert "hunter2-secret" not in response.text
    assert "not-a-number" not in response.text


def test_app_error_keeps_status_code_message_and_headers(probe_client: TestClient) -> None:
    response = probe_client.get("/api/_probe/conflict")
    assert response.status_code == 409
    assert response.headers["X-Probe"] == "1"
    assert response.json()["error"]["code"] == "conflict"
    assert response.json()["error"]["message"] == "Alert is already resolved"


def test_unhandled_error_is_generic_logged_and_keeps_headers(
    probe_client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.ERROR, logger="sentinelx.http"):
        response = probe_client.get("/api/_probe/crash")
    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == "internal_error"
    assert body["error"]["request_id"] == response.headers["X-Request-ID"]
    assert "hunter2" not in response.text
    assert response.headers["X-Frame-Options"] == "DENY"
    assert any(record.message == "http.unhandled_error" for record in caplog.records)


def test_each_request_is_logged_once_with_status_and_duration(
    capsys: pytest.CaptureFixture[str], client: TestClient
) -> None:
    capsys.readouterr()
    client.get("/api/nothing-here?q=secret-search-value")
    lines = [json.loads(line) for line in capsys.readouterr().err.strip().splitlines()]
    # Only the app's own lines: the test client (httpx2) logs full URLs itself.
    app_lines = [line for line in lines if line["logger"].startswith(("app", "sentinelx"))]
    requests = [line for line in app_lines if line["msg"] == "http.request"]
    assert len(requests) == 1
    fields = requests[0]["fields"]
    assert fields["method"] == "GET"
    assert fields["path"] == "/api/nothing-here"
    assert fields["status"] == 404
    assert fields["duration_ms"] >= 0
    assert "secret-search-value" not in json.dumps(app_lines)


def test_health_checks_are_not_logged_at_info(
    capsys: pytest.CaptureFixture[str], client: TestClient
) -> None:
    capsys.readouterr()
    client.get("/api/health")
    assert "http.request" not in capsys.readouterr().err


def test_cors_allows_only_configured_origins(client: TestClient) -> None:
    allowed = client.options(
        "/api/health",
        headers={"Origin": "http://localhost:5174", "Access-Control-Request-Method": "GET"},
    )
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:5174"
    denied = client.options(
        "/api/health",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in denied.headers
