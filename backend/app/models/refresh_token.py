import enum
import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class RevokedReason(enum.StrEnum):
    # Exchanged for a new token. Presenting it again means someone else has a copy: theft.
    ROTATED = "ROTATED"
    LOGOUT = "LOGOUT"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"  # noqa: S105  (a reason, not a password)
    DEACTIVATED = "DEACTIVATED"
    REUSE_DETECTED = "REUSE_DETECTED"  # revoked because another token of the user was replayed


class RefreshToken(Base):
    """One row per issued refresh token. Only a SHA-256 hash of the token is stored."""

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(sa.String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    revoked_reason: Mapped[str | None] = mapped_column(sa.String(24))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )
