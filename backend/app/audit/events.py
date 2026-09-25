"""Every kind of audit event SentinelX records. Later phases add their own actions here."""

import enum


class AuditAction(enum.StrEnum):
    # Authentication
    LOGIN_SUCCEEDED = "LOGIN_SUCCEEDED"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGIN_RATE_LIMITED = "LOGIN_RATE_LIMITED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    LOGOUT = "LOGOUT"
    # FAILURE when the current password was wrong. (Event names, not secrets: S105.)
    PASSWORD_CHANGED = "PASSWORD_CHANGED"  # noqa: S105
    # A used refresh token was presented again: possible theft; all sessions revoked.
    REFRESH_TOKEN_REUSED = "REFRESH_TOKEN_REUSED"  # noqa: S105
    # Authorization: a signed-in user called a route their role forbids.
    ACCESS_DENIED = "ACCESS_DENIED"
    # User administration
    USER_CREATED = "USER_CREATED"
    USER_ROLE_CHANGED = "USER_ROLE_CHANGED"
    USER_DEACTIVATED = "USER_DEACTIVATED"
    USER_REACTIVATED = "USER_REACTIVATED"


class AuditResult(enum.StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"  # attempted and failed (wrong password, rate limit)
    DENIED = "DENIED"  # not permitted for this role


class EntityType(enum.StrEnum):
    USER = "USER"
    ROUTE = "ROUTE"
