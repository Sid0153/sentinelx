import logging
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app import __version__
from app.database.migrations import current_revision, expected_revision
from app.database.session import get_db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: Literal["ok"]
    version: str


class ReadinessChecks(BaseModel):
    database: Literal["up", "down"]
    # current: schema matches this code. pending: migrations not applied (or the database is
    # newer than the code). unknown: the database could not be asked.
    migrations: Literal["current", "pending", "unknown"]


class ReadinessResponse(BaseModel):
    status: Literal["ok", "unavailable"]
    checks: ReadinessChecks


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Liveness: the process is up. Never touches the database."""
    return HealthResponse(status="ok", version=__version__)


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    responses={503: {"model": ReadinessResponse, "description": "Not ready"}},
)
def ready(response: Response, db: Annotated[Session, Depends(get_db)]) -> ReadinessResponse:
    """Readiness: the database is reachable and its schema matches this code."""
    try:
        db.execute(text("SELECT 1"))
        revision = current_revision(db)
    except SQLAlchemyError:
        # Details (host, reason) go to the server log only, never to this public endpoint.
        logger.exception("health.database_unreachable")
        response.status_code = 503
        return ReadinessResponse(
            status="unavailable", checks=ReadinessChecks(database="down", migrations="unknown")
        )
    if revision != expected_revision():
        logger.warning(
            "health.migrations_pending",
            extra={"fields": {"database": revision, "expected": expected_revision()}},
        )
        response.status_code = 503
        return ReadinessResponse(
            status="unavailable", checks=ReadinessChecks(database="up", migrations="pending")
        )
    return ReadinessResponse(
        status="ok", checks=ReadinessChecks(database="up", migrations="current")
    )
