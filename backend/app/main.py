import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.router import api_router
from app.core.config import Settings, get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import RequestContextMiddleware
from app.core.rate_limit import SlidingWindowRateLimiter

logger = logging.getLogger(__name__)

API_DESCRIPTION = """
Security operations platform: ingestion, detection, correlation, investigation.

**Authentication.** `POST /api/auth/login` returns a short-lived access token; send it as
`Authorization: Bearer <token>`. A refresh token is set as an httpOnly cookie and exchanged at
`POST /api/auth/refresh`. Roles: VIEWER (read only), ANALYST (+ investigation work), ADMIN
(+ users, rules, settings, audit log). The role each route needs is in docs/api.md.

**Lists** return `{"items", "total", "limit", "offset"}`.

**Errors** always have the shape
`{"error": {"code", "message", "request_id", "details"?}}`. Validation errors (422) never echo
submitted values.
"""

OPENAPI_TAGS = [
    {"name": "health", "description": "Liveness and readiness checks (no sign-in needed)."},
    {"name": "auth", "description": "Sign in, refresh and end sessions, change your password."},
    {"name": "users", "description": "User administration (ADMIN)."},
    {"name": "audit", "description": "Append-only log of security-relevant actions (ADMIN)."},
]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info("app.starting", extra={"fields": {"version": __version__}})
    yield
    logger.info("app.stopping")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory. Run with: uvicorn app.main:create_app --factory"""
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_format)

    app = FastAPI(
        title="SentinelX API",
        version=__version__,
        description=API_DESCRIPTION,
        openapi_tags=OPENAPI_TAGS,
        lifespan=lifespan,
        docs_url="/api/docs" if settings.docs_enabled else None,
        openapi_url="/api/openapi.json" if settings.docs_enabled else None,
        redoc_url=None,
    )

    # Middleware added last is outermost, so request IDs and security headers wrap CORS
    # responses and errors too.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
    )
    app.add_middleware(RequestContextMiddleware, trusted_networks=settings.trusted_networks)

    # One limiter per app instance (so tests are isolated); keyed by client IP.
    app.state.login_limiter = SlidingWindowRateLimiter(settings.login_rate_limit_per_minute)

    register_exception_handlers(app)
    app.include_router(api_router, prefix="/api")
    return app
