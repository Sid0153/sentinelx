import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class AuditLog(Base):
    """One security-relevant action. Append-only: database triggers (migration 0002) reject
    UPDATE, DELETE and TRUNCATE on this table.

    The actor reference has no ON DELETE action on purpose: a user who appears in the audit log
    cannot be deleted, only deactivated.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        sa.CheckConstraint("result IN ('SUCCESS', 'FAILURE', 'DENIED')", name="result_valid"),
        sa.Index("ix_audit_logs_entity", "entity_type", "entity_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    occurred_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )
    action: Mapped[str] = mapped_column(sa.String(64), index=True)
    # SUCCESS: done. FAILURE: attempted and failed (wrong password). DENIED: not allowed (role).
    result: Mapped[str] = mapped_column(sa.String(16))
    # None: nobody signed in (a failed login) or the system itself.
    actor_id: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("users.id"), index=True)
    actor_label: Mapped[str | None] = mapped_column(sa.String(254))  # email at the time
    entity_type: Mapped[str | None] = mapped_column(sa.String(32))
    entity_id: Mapped[str | None] = mapped_column(sa.String(64))
    client_ip: Mapped[str | None] = mapped_column(sa.String(45))
    request_id: Mapped[str | None] = mapped_column(sa.String(64))
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=sa.text("'{}'::jsonb")
    )
