"""Two-factor enrolment by the user, and the admin resets for someone locked out (Phase 13).

Each function records its audit event and commits.
"""

import secrets
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.audit.events import AuditAction, AuditResult, EntityType
from app.audit.service import record
from app.auth import mfa
from app.auth.passwords import hash_password, verify_password
from app.auth.service import check_second_factor, revoke_all_for_user
from app.core.config import Settings
from app.core.errors import AppError
from app.models.refresh_token import RevokedReason
from app.models.user import User


def start_mfa_setup(db: Session, user: User, settings: Settings) -> tuple[str, str]:
    """A new pending secret; (base32 secret, otpauth URI). Nothing changes for sign-in until
    `enable_mfa` confirms a code from it, so an abandoned setup is harmless."""
    if user.mfa_enabled:
        raise AppError(409, "Two-factor sign-in is already on")
    user.totp_pending_salt = mfa.new_salt()
    db.commit()
    return mfa.setup_details(
        mfa.derive_secret(settings.secret_key, user.totp_pending_salt), user.email
    )


def enable_mfa(db: Session, user: User, code: str, settings: Settings) -> list[str]:
    """Confirms the pending secret with a code from the app; returns the recovery codes."""
    if user.mfa_enabled:
        raise AppError(409, "Two-factor sign-in is already on")
    if not user.totp_pending_salt:
        raise AppError(400, "Start the setup first")
    secret = mfa.derive_secret(settings.secret_key, user.totp_pending_salt)
    step = mfa.verify_totp(secret, code, datetime.now(UTC), None)
    if step is None:
        record(
            db,
            AuditAction.MFA_ENABLED,
            result=AuditResult.FAILURE,
            actor=user,
            entity_type=EntityType.USER,
            entity_id=user.id,
            details={"reason": "wrong_code"},
        )
        db.commit()
        raise AppError(400, "That code is not correct. Check the time on your device.")
    codes, hashes = mfa.new_recovery_codes()
    user.totp_salt = user.totp_pending_salt
    user.totp_pending_salt = None
    user.totp_last_step = step
    user.mfa_recovery_hashes = hashes
    user.mfa_enabled = True
    record(db, AuditAction.MFA_ENABLED, actor=user, entity_type=EntityType.USER, entity_id=user.id)
    db.commit()
    return codes


def _clear_mfa(user: User) -> None:
    user.mfa_enabled = False
    user.totp_salt = None
    user.totp_pending_salt = None
    user.totp_last_step = None
    user.mfa_recovery_hashes = []


def disable_mfa(db: Session, user: User, password: str, code: str, settings: Settings) -> None:
    """Needs both the password and a current code (or a recovery code): a stolen access token
    alone cannot turn two-factor sign-in off."""
    if not user.mfa_enabled:
        raise AppError(409, "Two-factor sign-in is not on")
    if not verify_password(user.password_hash, password) or not check_second_factor(
        db, user, code, code, settings
    ):
        db.rollback()
        record(
            db,
            AuditAction.MFA_DISABLED,
            result=AuditResult.FAILURE,
            actor=user,
            entity_type=EntityType.USER,
            entity_id=user.id,
            details={"reason": "wrong_password_or_code"},
        )
        db.commit()
        raise AppError(400, "The password or the code is not correct")
    _clear_mfa(user)
    record(db, AuditAction.MFA_DISABLED, actor=user, entity_type=EntityType.USER, entity_id=user.id)
    db.commit()


def _other_user(db: Session, admin: User, user_id: object) -> User:
    if admin.id == user_id:
        # Your own account goes through the normal flows, which need the password/code.
        raise AppError(400, "Use your own settings for your own account")
    user = db.get(User, user_id)
    if user is None:
        raise AppError(404, "User not found")
    return user


def reset_mfa(db: Session, admin: User, user_id: object) -> User:
    """For a user who lost their device and their recovery codes. Ends their sessions."""
    user = _other_user(db, admin, user_id)
    _clear_mfa(user)
    revoke_all_for_user(db, user.id, RevokedReason.PASSWORD_CHANGED)
    record(
        db,
        AuditAction.MFA_RESET,
        actor=admin,
        entity_type=EntityType.USER,
        entity_id=user.id,
        details={"email": user.email, "sessions_revoked": True},
    )
    db.commit()
    return user


def reset_password(db: Session, admin: User, user_id: object) -> str:
    """Sets a random temporary password (returned once, never stored or logged), unlocks the
    account and ends its sessions. The user must choose a new password at next sign-in.
    Two-factor sign-in stays on: a reset password alone does not open the account."""
    user = _other_user(db, admin, user_id)
    temporary = secrets.token_urlsafe(15)  # 20 characters, about 120 bits
    user.password_hash = hash_password(temporary)
    user.must_change_password = True
    user.failed_login_count = 0
    user.locked_until = None
    revoke_all_for_user(db, user.id, RevokedReason.PASSWORD_CHANGED)
    record(
        db,
        AuditAction.PASSWORD_RESET,
        actor=admin,
        entity_type=EntityType.USER,
        entity_id=user.id,
        details={"email": user.email, "sessions_revoked": True},
    )
    db.commit()
    return temporary
