"""SQLAlchemy models. Import every model module here so Alembic sees all tables."""

from app.models.alert import Alert, AlertEvent
from app.models.audit_log import AuditLog
from app.models.context import Asset, Identity
from app.models.detection import (
    DetectionRule,
    DetectionRuleTechnique,
    DetectionRuleVersion,
    DetectionRun,
    MitreTechnique,
)
from app.models.event import Event, IngestionBatch, LogSource, RawEvent
from app.models.incident import (
    AppSetting,
    Incident,
    IncidentActivity,
    IncidentAlert,
    IncidentEvidence,
    IncidentNote,
)
from app.models.refresh_token import RefreshToken
from app.models.user import Role, User

__all__ = [
    "Alert",
    "AlertEvent",
    "AppSetting",
    "Asset",
    "DetectionRule",
    "DetectionRuleTechnique",
    "DetectionRuleVersion",
    "DetectionRun",
    "AuditLog",
    "Event",
    "Identity",
    "Incident",
    "IncidentActivity",
    "IncidentAlert",
    "IncidentEvidence",
    "IncidentNote",
    "IngestionBatch",
    "LogSource",
    "MitreTechnique",
    "RawEvent",
    "RefreshToken",
    "Role",
    "User",
]
