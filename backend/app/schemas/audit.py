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
    seq: int | None = None  # its place in the hash chain


class AuditIntegrity(BaseModel):
    """The hash chain checked end to end (app/audit/chain.py)."""

    intact: bool
    chained: int  # entries covered by the chain
    legacy: int  # written before the chain existed: not covered
    first_broken_seq: int | None  # the first entry whose hash or link does not match
    head_seq: int | None  # the newest entry: compare with the `audit.chained` log line
    head_hash: str | None
