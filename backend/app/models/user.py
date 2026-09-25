import enum
import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class Role(enum.StrEnum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


ROLE_RANK = {Role.VIEWER: 1, Role.ANALYST: 2, Role.ADMIN: 3}


class User(Base):
    """A person who signs in to SentinelX. Users are never deleted, only deactivated, so the
    audit log and investigation records keep pointing at a real row."""

    __tablename__ = "users"
    __table_args__ = (
        sa.CheckConstraint("role IN ('ADMIN', 'ANALYST', 'VIEWER')", name="role_valid"),
        sa.CheckConstraint("email = lower(email)", name="email_lowercase"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(sa.String(254), unique=True)
    password_hash: Mapped[str] = mapped_column(sa.String(255))
    # A plain VARCHAR with a check constraint, not a PostgreSQL enum type: simpler migrations.
    role: Mapped[Role] = mapped_column(sa.Enum(Role, native_enum=False, length=16))
    is_active: Mapped[bool] = mapped_column(default=True, server_default=sa.true())
    failed_login_count: Mapped[int] = mapped_column(default=0, server_default="0")
    locked_until: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )
