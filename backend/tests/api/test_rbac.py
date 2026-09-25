"""Authorization tests that fail loudly when a route is added without an access decision.

EXPECTED_ACCESS is the single source of truth for who may call what (ADR-0007). Every API route
must appear either there or in PUBLIC_ROUTES, and every entry is exercised for every role.
"""

import re
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import ROLE_RANK, Role, User
from tests.helpers import access_token_for, make_user

pytestmark = pytest.mark.integration

Route = tuple[str, str]  # (HTTP method, path)

PUBLIC_ROUTES: set[Route] = {
    ("GET", "/api/health"),
    ("GET", "/api/ready"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/refresh"),
    ("POST", "/api/auth/logout"),  # works from the refresh cookie alone
}

# Minimum role required. VIEWER means "any signed-in user".
EXPECTED_ACCESS: dict[Route, Role] = {
    ("GET", "/api/auth/me"): Role.VIEWER,
    ("POST", "/api/auth/change-password"): Role.VIEWER,
    ("GET", "/api/users"): Role.ADMIN,
    ("POST", "/api/users"): Role.ADMIN,
    ("PATCH", "/api/users/{user_id}"): Role.ADMIN,
    ("GET", "/api/audit"): Role.ADMIN,
    ("GET", "/api/assets"): Role.VIEWER,
    ("POST", "/api/assets"): Role.ADMIN,
    ("GET", "/api/assets/{asset_id}"): Role.VIEWER,
    ("PATCH", "/api/assets/{asset_id}"): Role.ADMIN,
    ("GET", "/api/identities"): Role.VIEWER,
    ("POST", "/api/identities"): Role.ADMIN,
    ("GET", "/api/identities/{identity_id}"): Role.VIEWER,
    ("PATCH", "/api/identities/{identity_id}"): Role.ADMIN,
}

_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}


def _api_routes(app: FastAPI) -> set[Route]:
    """Every (method, path) the app serves, read from its OpenAPI schema."""
    paths = app.openapi()["paths"]
    return {
        (method.upper(), path)
        for path, operations in paths.items()
        for method in operations
        if method.upper() in _HTTP_METHODS
    }


def test_every_route_has_a_declared_access_rule(app: FastAPI) -> None:
    routes = _api_routes(app)
    declared = PUBLIC_ROUTES | set(EXPECTED_ACCESS)
    assert routes - declared == set(), "route added without an access rule in this file"
    assert declared - routes == set(), "access rule refers to a route that no longer exists"


def _url(path: str) -> str:
    """Fills every path parameter with a random UUID (the target need not exist)."""
    return re.sub(r"\{[^}]+\}", str(uuid.uuid4()), path)


@pytest.fixture
def users_by_role(db_session: Session) -> dict[Role, User]:
    return {role: make_user(db_session, role) for role in Role}


@pytest.mark.parametrize(("method", "path"), sorted(EXPECTED_ACCESS))
def test_anonymous_requests_are_rejected(db_client: TestClient, method: str, path: str) -> None:
    response = db_client.request(method, _url(path))
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


@pytest.mark.parametrize(
    ("method", "path", "minimum", "role"),
    [(m, p, minimum, role) for (m, p), minimum in sorted(EXPECTED_ACCESS.items()) for role in Role],
)
def test_role_matrix(
    db_client: TestClient,
    users_by_role: dict[Role, User],
    method: str,
    path: str,
    minimum: Role,
    role: Role,
) -> None:
    headers = {"Authorization": f"Bearer {access_token_for(users_by_role[role])}"}
    # Requests carry no body. Authorization runs before body validation, so a permitted role
    # gets 200/404/422 (anything but 401/403) and a forbidden role is stopped with 403.
    response = db_client.request(method, _url(path), headers=headers)
    if ROLE_RANK[role] >= ROLE_RANK[minimum]:
        assert response.status_code not in (401, 403)
    else:
        assert response.status_code == 403
