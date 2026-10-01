from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class RateLimitCounter(Base):
    """One fixed window of a rate-limited key (app/core/rate_limit.py). Shared by every
    backend process, so limits survive restarts and hold across replicas (Phase 13)."""

    __tablename__ = "rate_limit_counters"

    key: Mapped[str] = mapped_column(sa.String(200), primary_key=True)  # "login:203.0.113.9"
    window_start: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), primary_key=True, index=True
    )
    count: Mapped[int] = mapped_column()
