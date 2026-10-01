import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class SavedHunt(Base):
    """A hunt an analyst saved (docs/threat-hunting.md). Private to its owner unless shared;
    a shared hunt is readable by every signed-in user and changed only by its owner. The
    definition is validated again whenever it is loaded, so a hunt saved by an older version
    fails cleanly instead of running something different."""

    __tablename__ = "saved_hunts"
    __table_args__ = (
        sa.UniqueConstraint("owner_id", "name"),  # uq_saved_hunts_owner_id
        sa.CheckConstraint("kind IN ('query', 'template')", name="kind_valid"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(sa.String(100))
    description: Mapped[str | None] = mapped_column(sa.String(500))
    kind: Mapped[str] = mapped_column(sa.String(16))
    definition: Mapped[dict[str, Any]] = mapped_column(JSONB)
    shared: Mapped[bool] = mapped_column(default=False, server_default=sa.false(), index=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()
    )
