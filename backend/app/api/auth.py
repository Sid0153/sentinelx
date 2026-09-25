import logging

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse

from app.api.deps import DbSession, SettingsDep
from app.audit.events import AuditAction, AuditResult, EntityType
from app.audit.service import record
from app.auth.deps import CurrentUser
from app.auth.passwords import hash_password, verify_password
from app.auth.service import (
    InvalidCredentialsError,
    InvalidRefreshTokenError,
    authenticate,
    revoke_all_for_user,
    revoke_refresh_token,
    rotate_session,
    start_session,
)
from app.core.config import Settings
from app.core.errors import AppError, error_body
from app.core.middleware import client_ip
from app.core.rate_limit import SlidingWindowRateLimiter
from app.models.refresh_token import RevokedReason
from app.models.user import User
from app.schemas.auth import ChangePasswordRequest, LoginRequest, TokenResponse
from app.schemas.common import error_responses
from app.schemas.users import UserPublic

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

REFRESH_COOKIE = "sx_refresh"
# The cookie is only sent to the auth endpoints, not to every API call.
_COOKIE_PATH = "/api/auth"


def _set_refresh_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=token,
        max_age=settings.refresh_token_expire_days * 86400,
        httponly=True,  # not readable by JavaScript, which limits what an XSS bug can steal
        secure=settings.cookie_secure,
        samesite="strict",  # not sent on cross-site requests, which blocks CSRF on these routes
        path=_COOKIE_PATH,
    )


def _clear_refresh_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=REFRESH_COOKIE,
        path=_COOKIE_PATH,
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )


def _token_response(access_token: str, user: User, settings: Settings) -> TokenResponse:
    return TokenResponse(
        access_token=access_token,
        expires_in=settings.access_token_expire_minutes * 60,
        user=UserPublic.model_validate(user),
    )


def _check_login_rate(request: Request, db: DbSession) -> None:
    limiter: SlidingWindowRateLimiter = request.app.state.login_limiter
    if not limiter.allow(client_ip(request)):
        logger.warning("auth.login_rate_limited")
        record(db, AuditAction.LOGIN_RATE_LIMITED, result=AuditResult.FAILURE)
        db.commit()
        raise AppError(
            429, "Too many login attempts. Try again in a minute.", headers={"Retry-After": "60"}
        )


@router.post("/login", response_model=TokenResponse, responses=error_responses(401, 429))
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: DbSession,
    settings: SettingsDep,
) -> TokenResponse:
    """Email + password → short-lived access token (body) and refresh token (httpOnly cookie)."""
    _check_login_rate(request, db)
    try:
        user = authenticate(db, payload.email, payload.password, settings)
    except InvalidCredentialsError:
        # Same message for unknown email, wrong password, locked and disabled accounts.
        # The email is not logged: people sometimes type their password into that field.
        logger.warning("auth.login_failed")
        raise AppError(
            401, "Invalid email or password", headers={"WWW-Authenticate": "Bearer"}
        ) from None

    access_token, refresh_token = start_session(db, user, settings)
    _set_refresh_cookie(response, refresh_token, settings)
    logger.info("auth.login_succeeded", extra={"fields": {"user_id": str(user.id)}})
    return _token_response(access_token, user, settings)


@router.post("/refresh", response_model=TokenResponse, responses=error_responses(401))
def refresh(
    request: Request, response: Response, db: DbSession, settings: SettingsDep
) -> TokenResponse | JSONResponse:
    """Exchanges the refresh cookie for a new access token and a new (rotated) cookie."""
    presented = request.cookies.get(REFRESH_COOKIE)
    if not presented:
        raise AppError(401, "No session")
    try:
        user, access_token, new_refresh_token = rotate_session(db, presented, settings)
    except InvalidRefreshTokenError:
        rejected = JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=error_body(request, "unauthorized", "Invalid or expired session"),
        )
        _clear_refresh_cookie(rejected, settings)
        return rejected

    _set_refresh_cookie(response, new_refresh_token, settings)
    return _token_response(access_token, user, settings)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, db: DbSession, settings: SettingsDep) -> Response:
    """Public on purpose: it works from the cookie alone, even after the access token expired."""
    presented = request.cookies.get(REFRESH_COOKIE)
    if presented:
        revoke_refresh_token(db, presented)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_refresh_cookie(response, settings)
    return response


@router.get("/me", response_model=UserPublic, responses=error_responses(401))
def me(user: CurrentUser) -> UserPublic:
    return UserPublic.model_validate(user)


@router.post(
    "/change-password",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=error_responses(400, 401),
)
def change_password(
    payload: ChangePasswordRequest, user: CurrentUser, db: DbSession, settings: SettingsDep
) -> Response:
    """Ends every session of the user, including this one: all devices sign in again."""
    if not verify_password(user.password_hash, payload.current_password):
        record(
            db,
            AuditAction.PASSWORD_CHANGED,
            result=AuditResult.FAILURE,
            actor=user,
            entity_type=EntityType.USER,
            entity_id=user.id,
            details={"reason": "wrong_current_password"},
        )
        db.commit()
        # 400, not 401: a 401 would make the frontend think the session expired.
        raise AppError(400, "Current password is incorrect")
    user.password_hash = hash_password(payload.new_password)
    revoke_all_for_user(db, user.id, RevokedReason.PASSWORD_CHANGED)
    record(
        db,
        AuditAction.PASSWORD_CHANGED,
        actor=user,
        entity_type=EntityType.USER,
        entity_id=user.id,
        details={"sessions_revoked": True},
    )
    db.commit()
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_refresh_cookie(response, settings)
    return response
