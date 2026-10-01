"""Login, refresh-token rotation and logout. All database work for sessions lives here."""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.audit.events import AuditAction, AuditResult, EntityType
from app.audit.service import record
from app.auth import mfa
from app.auth.passwords import verify_against_dummy, verify_password
from app.auth.tokens import create_access_token, generate_refresh_token, hash_refresh_token
from app.core.config import Settings
from app.models.refresh_token import RefreshToken, RevokedReason
from app.models.user import User


class InvalidCredentialsError(Exception):
    """Wrong email or password, locked or disabled account. Callers must not say which."""


class MfaRequiredError(Exception):
    """The password was right; the account has two-factor sign-in and no code was given."""


class InvalidRefreshTokenError(Exception):
    """The refresh token is unknown, expired, revoked or belongs to a disabled user."""


def _login_failed(db: Session, user: User | None, reason: str) -> InvalidCredentialsError:
    """Records the failure (and commits) and returns the error to raise.

    The audit record keeps the real reason for admins; the API caller gets one generic message.
    The submitted email is never stored: people sometimes type a password into that field.
    """
    record(
        db,
        AuditAction.LOGIN_FAILED,
        result=AuditResult.FAILURE,
        entity_type=EntityType.USER if user else None,
        entity_id=user.id if user else None,
        details={"reason": reason},
    )
    db.commit()
    return InvalidCredentialsError()


def _count_failure(db: Session, user: User, now: datetime, settings: Settings) -> None:
    """A wrong password or a wrong second-factor code: both count towards the lockout."""
    user.failed_login_count += 1
    if user.failed_login_count >= settings.max_failed_logins:
        user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
        user.failed_login_count = 0
        record(
            db,
            AuditAction.ACCOUNT_LOCKED,
            result=AuditResult.FAILURE,
            entity_type=EntityType.USER,
            entity_id=user.id,
            details={"minutes": settings.lockout_minutes},
        )


def check_second_factor(
    db: Session, user: User, otp: str | None, recovery_code: str | None, settings: Settings
) -> bool:
    """True when `otp` (a code from the app) or `recovery_code` is valid for the user; it is
    then used up (the TOTP step is remembered, the recovery code removed). The caller commits."""
    now = datetime.now(UTC)
    if otp and user.totp_salt:
        secret = mfa.derive_secret(settings.secret_key, user.totp_salt)
        step = mfa.verify_totp(secret, otp, now, user.totp_last_step)
        if step is not None:
            user.totp_last_step = step
            return True
    if recovery_code:
        remaining = mfa.use_recovery_code(list(user.mfa_recovery_hashes), recovery_code)
        if remaining is not None:
            user.mfa_recovery_hashes = remaining
            record(
                db,
                AuditAction.MFA_RECOVERY_CODE_USED,
                actor=user,
                entity_type=EntityType.USER,
                entity_id=user.id,
                details={"remaining": len(remaining)},
            )
            return True
    return False


def authenticate(
    db: Session,
    email: str,
    password: str,
    settings: Settings,
    otp: str | None = None,
    recovery_code: str | None = None,
) -> User:
    now = datetime.now(UTC)
    # FOR UPDATE serializes concurrent attempts, so the failure counter cannot be skipped.
    user = db.scalar(select(User).where(User.email == email).with_for_update())

    if user is None:
        verify_against_dummy(password)
        raise _login_failed(db, None, "unknown_email")

    if user.locked_until is not None and user.locked_until > now:
        verify_against_dummy(password)
        raise _login_failed(db, user, "account_locked")

    if not verify_password(user.password_hash, password):
        _count_failure(db, user, now, settings)
        raise _login_failed(db, user, "wrong_password")

    if not user.is_active:
        raise _login_failed(db, user, "account_disabled")

    if user.mfa_enabled:
        if not otp and not recovery_code:
            # Not a failure: the normal first step of a two-step sign-in.
            db.rollback()  # releases the row lock
            raise MfaRequiredError
        if not check_second_factor(db, user, otp, recovery_code, settings):
            _count_failure(db, user, now, settings)
            raise _login_failed(db, user, "wrong_mfa_code")

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    record(
        db, AuditAction.LOGIN_SUCCEEDED, actor=user, entity_type=EntityType.USER, entity_id=user.id
    )
    db.commit()
    return user


def _new_refresh_token(db: Session, user_id: uuid.UUID, settings: Settings) -> str:
    plain = generate_refresh_token()
    db.add(
        RefreshToken(
            user_id=user_id,
            token_hash=hash_refresh_token(plain),
            expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_token_expire_days),
        )
    )
    return plain


def access_token_for(user: User, settings: Settings) -> str:
    return create_access_token(
        user.id, settings.secret_key, timedelta(minutes=settings.access_token_expire_minutes)
    )


def start_session(db: Session, user: User, settings: Settings) -> tuple[str, str]:
    """Returns (access_token, refresh_token)."""
    refresh_token = _new_refresh_token(db, user.id, settings)
    db.commit()
    return access_token_for(user, settings), refresh_token


def revoke_all_for_user(
    db: Session, user_id: uuid.UUID, reason: RevokedReason, now: datetime | None = None
) -> None:
    """Marks every active refresh token of the user as revoked. The caller commits."""
    db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now or datetime.now(UTC), revoked_reason=str(reason))
    )


def rotate_session(db: Session, presented_token: str, settings: Settings) -> tuple[User, str, str]:
    """Exchanges a refresh token for a new pair. Returns (user, access_token, refresh_token)."""
    now = datetime.now(UTC)
    row = db.scalar(
        select(RefreshToken)
        .where(RefreshToken.token_hash == hash_refresh_token(presented_token))
        .with_for_update()
    )
    if row is None:
        raise InvalidRefreshTokenError

    if row.revoked_at is not None and row.revoked_reason == RevokedReason.ROTATED:
        # A token that was already exchanged is being presented again: two parties hold a
        # copy. Assume it was stolen and end every session of this user.
        revoke_all_for_user(db, row.user_id, RevokedReason.REUSE_DETECTED, now)
        record(
            db,
            AuditAction.REFRESH_TOKEN_REUSED,
            result=AuditResult.FAILURE,
            entity_type=EntityType.USER,
            entity_id=row.user_id,
            details={"sessions_revoked": True},
        )
        db.commit()
        raise InvalidRefreshTokenError

    # Ended by logout, password change or deactivation: simply no longer valid (an old
    # browser tab after a logout is normal, not an attack).
    if row.revoked_at is not None or row.expires_at <= now:
        raise InvalidRefreshTokenError

    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        raise InvalidRefreshTokenError

    row.revoked_at = now
    row.revoked_reason = str(RevokedReason.ROTATED)
    new_refresh_token = _new_refresh_token(db, user.id, settings)
    db.commit()
    return user, access_token_for(user, settings), new_refresh_token


def revoke_refresh_token(db: Session, presented_token: str) -> None:
    """Logout: ends the session this refresh token belongs to."""
    row = db.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(presented_token))
    )
    if row is not None and row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)
        row.revoked_reason = str(RevokedReason.LOGOUT)
        record(
            db,
            AuditAction.LOGOUT,
            actor=db.get(User, row.user_id),
            entity_type=EntityType.USER,
            entity_id=row.user_id,
        )
        db.commit()
