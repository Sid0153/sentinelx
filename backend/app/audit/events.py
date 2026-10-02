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
    # Two-factor sign-in (Phase 13). FAILURE when the confirming code or password was wrong.
    MFA_ENABLED = "MFA_ENABLED"
    MFA_DISABLED = "MFA_DISABLED"
    MFA_RECOVERY_CODE_USED = "MFA_RECOVERY_CODE_USED"
    # By an admin, for another user: two-factor removed / temporary password issued.
    MFA_RESET = "MFA_RESET"
    PASSWORD_RESET = "PASSWORD_RESET"  # noqa: S105
    # A used refresh token was presented again: possible theft; all sessions revoked.
    REFRESH_TOKEN_REUSED = "REFRESH_TOKEN_REUSED"  # noqa: S105
    # Authorization: a signed-in user called a route their role forbids.
    ACCESS_DENIED = "ACCESS_DENIED"
    # User administration
    USER_CREATED = "USER_CREATED"
    USER_ROLE_CHANGED = "USER_ROLE_CHANGED"
    USER_DEACTIVATED = "USER_DEACTIVATED"
    USER_REACTIVATED = "USER_REACTIVATED"
    # Context inventory: criticality and privilege change how alerts are prioritized.
    ASSET_CREATED = "ASSET_CREATED"
    ASSET_UPDATED = "ASSET_UPDATED"
    IDENTITY_CREATED = "IDENTITY_CREATED"
    IDENTITY_UPDATED = "IDENTITY_UPDATED"
    # Ingestion: sources are configuration; refused requests are worth an admin's attention.
    # Accepted batches are recorded in ingestion_batches (who, when, what), not here.
    SOURCE_CREATED = "SOURCE_CREATED"
    SOURCE_UPDATED = "SOURCE_UPDATED"
    INGEST_REJECTED = "INGEST_REJECTED"
    # Per-source ingest keys (Phase 13): the prefix only, never the key.
    INGEST_KEY_ISSUED = "INGEST_KEY_ISSUED"
    INGEST_KEY_REVOKED = "INGEST_KEY_REVOKED"
    # Detection rules: the library changing them, admins tuning them, manual runs.
    RULE_ADDED = "RULE_ADDED"
    RULE_LIBRARY_UPDATED = "RULE_LIBRARY_UPDATED"
    RULE_RETIRED = "RULE_RETIRED"
    RULE_UPDATED = "RULE_UPDATED"
    DETECTION_RUN_REQUESTED = "DETECTION_RUN_REQUESTED"
    # Alerts (Phase 7)
    ALERT_STATUS_CHANGED = "ALERT_STATUS_CHANGED"
    # Incidents and settings (Phase 8)
    INCIDENT_CREATED = "INCIDENT_CREATED"  # by an analyst (escalation); the engine's are activity
    INCIDENT_STATUS_CHANGED = "INCIDENT_STATUS_CHANGED"
    INCIDENT_ASSIGNED = "INCIDENT_ASSIGNED"
    INCIDENT_NOTE_ADDED = "INCIDENT_NOTE_ADDED"
    INCIDENT_EVIDENCE_CHANGED = "INCIDENT_EVIDENCE_CHANGED"
    INCIDENT_ALERT_LINKED = "INCIDENT_ALERT_LINKED"
    INCIDENT_ALERT_UNLINKED = "INCIDENT_ALERT_UNLINKED"
    INCIDENT_RENAMED = "INCIDENT_RENAMED"
    SETTINGS_CHANGED = "SETTINGS_CHANGED"
    # Threat hunting (Phase 10): saved hunts. Running a hunt is a read and is not audited.
    HUNT_SAVED = "HUNT_SAVED"
    HUNT_UPDATED = "HUNT_UPDATED"
    HUNT_DELETED = "HUNT_DELETED"
    # Demo environment (Phase 16): loaded by an operator; a reset replaces the database, and the
    # new audit log's first entry records the newest entry of the one it replaced.
    DEMO_LOADED = "DEMO_LOADED"
    DEMO_RESET = "DEMO_RESET"


class AuditResult(enum.StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"  # attempted and failed (wrong password, rate limit)
    DENIED = "DENIED"  # not permitted for this role


class EntityType(enum.StrEnum):
    USER = "USER"
    ROUTE = "ROUTE"
    ASSET = "ASSET"
    IDENTITY = "IDENTITY"
    LOG_SOURCE = "LOG_SOURCE"
    DETECTION_RULE = "DETECTION_RULE"
    DETECTION_RUN = "DETECTION_RUN"
    ALERT = "ALERT"
    INCIDENT = "INCIDENT"
    SETTINGS = "SETTINGS"
    SAVED_HUNT = "SAVED_HUNT"
