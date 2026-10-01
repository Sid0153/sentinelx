"""Phase 13 security review, kept as tests so the findings cannot come back.

- Input validation: every request body model refuses unknown fields, and every free-text
  string in it has a maximum length (read from the OpenAPI schema, so nested models count).
- Authorization: every route that changes something needs ANALYST or above, except a short,
  explained list.
- Errors and API docs: no stack traces or framework details in error bodies; the interactive
  docs are off in production.
"""

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import create_app
from app.models.user import ROLE_RANK, Role
from tests.api.test_rbac import EXPECTED_ACCESS, PUBLIC_ROUTES

pytestmark = pytest.mark.integration

# State-changing routes a VIEWER (or anyone) may call, and why.
WRITE_EXCEPTIONS = {
    ("POST", "/api/auth/login"): "signing in",
    ("POST", "/api/auth/refresh"): "renewing a session from its cookie",
    ("POST", "/api/auth/logout"): "ending one's own session",
    ("POST", "/api/auth/change-password"): "one's own password (docs/security.md)",
    ("POST", "/api/auth/mfa/setup"): "one's own two-factor sign-in",
    ("POST", "/api/auth/mfa/enable"): "one's own two-factor sign-in",
    ("POST", "/api/auth/mfa/disable"): "one's own two-factor sign-in (password + code)",
    ("POST", "/api/hunt/query"): "a read: the query is too structured for a URL",
    ("POST", "/api/hunt/templates/{template_id}/run"): "a read: runs a reviewed template",
}


def test_every_write_needs_an_analyst_or_has_a_reason() -> None:
    unexplained = []
    for route in PUBLIC_ROUTES | set(EXPECTED_ACCESS):
        method, _ = route
        if method == "GET" or route in WRITE_EXCEPTIONS:
            continue
        required = EXPECTED_ACCESS.get(route)
        if required is None or ROLE_RANK[required] < ROLE_RANK[Role.ANALYST]:
            unexplained.append(route)
    assert unexplained == []


def _problems(spec: dict[str, Any]) -> set[str]:
    schemas = spec["components"]["schemas"]
    problems: set[str] = set()
    seen: set[str] = set()

    def resolve(node: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
        ref = node.get("$ref")
        if ref:
            name = ref.rsplit("/", 1)[1]
            return name, schemas[name]
        return None, node

    def check_string(node: dict[str, Any], where: str) -> None:
        _, schema = resolve(node)
        for option in schema.get("anyOf", [schema]):
            if option.get("type") == "string" and not option.get("format"):
                bounded = {"maxLength", "pattern", "const", "enum"} & set(option)
                if not bounded:
                    problems.add(f"{where}: string without maxLength")
            if option.get("type") == "array":
                check_string(option.get("items", {}), f"{where}[]")

    def check(node: dict[str, Any], where: str) -> None:
        name, schema = resolve(node)
        if name:
            if name in seen:
                return
            seen.add(name)
            where = name
        for key in ("anyOf", "oneOf", "allOf"):
            for option in schema.get(key, []):
                check(option, where)
        if schema.get("type") == "array" and "items" in schema:
            check(schema["items"], f"{where}[]")
        if schema.get("type") == "object" and "properties" in schema:
            if schema.get("additionalProperties") is not False:
                problems.add(f"{where}: unknown fields are not refused")
            for prop, sub in schema["properties"].items():
                check_string(sub, f"{where}.{prop}")
                check(sub, f"{where}.{prop}")

    for operations in spec["paths"].values():
        for op in operations.values():
            for media in op.get("requestBody", {}).get("content", {}).values():
                check(media.get("schema", {}), "body")
    assert len(seen) > 40  # the walk reached the models, not an empty schema
    return problems


def test_request_bodies_refuse_unknown_fields_and_bound_every_string(app: FastAPI) -> None:
    assert _problems(app.openapi()) == set()


def test_errors_do_not_leak_internals(db_client: TestClient) -> None:
    for response in (
        db_client.get("/api/no-such-route"),
        db_client.post(
            "/api/auth/login", content=b"{not json", headers={"Content-Type": "application/json"}
        ),
        db_client.get("/api/alerts/not-a-uuid"),
    ):
        text = response.text
        assert "Traceback" not in text and "sqlalchemy" not in text.lower()
        assert "error" in response.json()
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_api_docs_are_off_in_production() -> None:
    settings = get_settings().model_copy(update={"app_env": "production"})
    client = TestClient(create_app(settings))
    assert client.get("/api/docs").status_code == 404
    assert client.get("/api/openapi.json").status_code == 404
