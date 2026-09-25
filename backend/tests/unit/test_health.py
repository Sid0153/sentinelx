from collections.abc import Iterator

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app import __version__
from app.database.session import get_db


def test_liveness_does_not_need_the_database(app: FastAPI) -> None:
    def no_database() -> Iterator[Session]:
        raise AssertionError("liveness must not open a database session")
        yield  # pragma: no cover

    app.dependency_overrides[get_db] = no_database
    with TestClient(app) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__}


def test_readiness_reports_an_unreachable_database_without_details(app: FastAPI) -> None:
    engine = create_engine(
        "postgresql+psycopg://u:p@127.0.0.1:1/closed", connect_args={"connect_timeout": 2}
    )

    def closed_database() -> Iterator[Session]:
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_db] = closed_database
    with TestClient(app) as client:
        response = client.get("/api/ready")
    engine.dispose()
    assert response.status_code == 503
    assert response.json() == {
        "status": "unavailable",
        "checks": {"database": "down", "migrations": "unknown"},
    }
    # The connection target must not leak through a public endpoint.
    assert "127.0.0.1" not in response.text
