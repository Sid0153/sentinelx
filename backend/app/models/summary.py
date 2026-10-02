"""Per-day summaries maintained by database triggers (migration 0014). Read-only for the
application: the triggers on `events` and `raw_events` write them, in the same statement as
the insert, so they always agree with the stored evidence."""

from datetime import date, datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class EventDailyCount(Base):
    """Events per UTC day of their own time (`kind` 'event'), raw records per UTC day of
    receipt (`kind` 'raw')."""

    __tablename__ = "event_daily_counts"
    __table_args__ = (
        sa.CheckConstraint("kind IN ('event', 'raw')", name="kind_valid"),
        sa.CheckConstraint("records >= 0", name="records_not_negative"),
    )

    kind: Mapped[str] = mapped_column(sa.String(8), primary_key=True)
    day: Mapped[date] = mapped_column(sa.Date, primary_key=True)
    records: Mapped[int] = mapped_column(sa.BigInteger)


class LogonSuccessDaily(Base):
    """Successful logons per (account, source address, UTC day) and the latest one: the
    history AUTH-004 needs, without reading every logon (engine._history)."""

    __tablename__ = "logon_success_daily"
    __table_args__ = (sa.CheckConstraint("logons > 0", name="logons_positive"),)

    username: Mapped[str] = mapped_column(sa.String(256), primary_key=True)
    source_ip: Mapped[str] = mapped_column(INET, primary_key=True)
    day: Mapped[date] = mapped_column(sa.Date, primary_key=True)
    logons: Mapped[int] = mapped_column(sa.BigInteger)
    last_logon: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
