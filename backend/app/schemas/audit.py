import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditLogPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    occurred_at: datetime
    action: str
    result: str
    actor_id: uuid.UUID | None  # None: anonymous (failed login) or the system
    actor_label: str | None
    entity_type: str | None
    entity_id: str | None
    client_ip: str | None
    request_id: str | None
    details: dict[str, Any]
