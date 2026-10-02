"""Performance (Phase 14): per-day summaries kept by the database itself.

- `event_daily_counts`: events per UTC day of their own time, raw records per UTC day of
  receipt. The dashboard reads totals and trends from here instead of counting every row.
- `logon_success_daily`: successful logons per (account, source address, UTC day), with the
  latest one. AUTH-004 reads an account's 14-day history from here instead of from events.

Both are maintained by statement-level AFTER INSERT triggers on `events` and `raw_events`, in
the same statement as the insert, so they cannot drift from the evidence whichever code path
inserts it. `events` and `raw_events` are append-only (no UPDATE or DELETE), so counting
inserts is exact. Rows are written in a fixed order so two concurrent batches lock them in
the same order (no deadlock). The existing data is counted once here.

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-02 18:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

COUNT_EVENTS = """
CREATE FUNCTION count_inserted_events() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO event_daily_counts (kind, day, records)
    SELECT 'event', (timezone('UTC', timestamp))::date, count(*)
    FROM inserted GROUP BY 2 ORDER BY 2
    ON CONFLICT (kind, day)
        DO UPDATE SET records = event_daily_counts.records + EXCLUDED.records;

    INSERT INTO logon_success_daily (username, source_ip, day, logons, last_logon)
    SELECT username, source_ip, (timezone('UTC', timestamp))::date, count(*), max(timestamp)
    FROM inserted
    WHERE event_category = 'authentication'
      AND event_action = 'logon'
      AND event_outcome = 'success'
      AND username IS NOT NULL AND username <> ''
      AND source_ip IS NOT NULL
    GROUP BY 1, 2, 3 ORDER BY 1, 2, 3
    ON CONFLICT (username, source_ip, day)
        DO UPDATE SET logons = logon_success_daily.logons + EXCLUDED.logons,
                      last_logon = greatest(logon_success_daily.last_logon, EXCLUDED.last_logon);
    RETURN NULL;
END;
$$
"""

COUNT_RAW = """
CREATE FUNCTION count_inserted_raw_events() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO event_daily_counts (kind, day, records)
    SELECT 'raw', (timezone('UTC', received_at))::date, count(*)
    FROM inserted GROUP BY 2 ORDER BY 2
    ON CONFLICT (kind, day)
        DO UPDATE SET records = event_daily_counts.records + EXCLUDED.records;
    RETURN NULL;
END;
$$
"""


def upgrade() -> None:
    op.create_table(
        "event_daily_counts",
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("records", sa.BigInteger(), nullable=False),
        sa.CheckConstraint(
            "kind IN ('event', 'raw')", name=op.f("ck_event_daily_counts_kind_valid")
        ),
        sa.CheckConstraint("records >= 0", name=op.f("ck_event_daily_counts_records_not_negative")),
        sa.PrimaryKeyConstraint("kind", "day", name=op.f("pk_event_daily_counts")),
    )
    op.create_table(
        "logon_success_daily",
        sa.Column("username", sa.String(length=256), nullable=False),
        sa.Column("source_ip", postgresql.INET(), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("logons", sa.BigInteger(), nullable=False),
        sa.Column("last_logon", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("logons > 0", name=op.f("ck_logon_success_daily_logons_positive")),
        sa.PrimaryKeyConstraint(
            "username", "source_ip", "day", name=op.f("pk_logon_success_daily")
        ),
    )
    op.execute(COUNT_EVENTS)
    op.execute(COUNT_RAW)
    op.execute(
        "CREATE TRIGGER events_daily_summaries AFTER INSERT ON events "
        "REFERENCING NEW TABLE AS inserted FOR EACH STATEMENT "
        "EXECUTE FUNCTION count_inserted_events()"
    )
    op.execute(
        "CREATE TRIGGER raw_events_daily_counts AFTER INSERT ON raw_events "
        "REFERENCING NEW TABLE AS inserted FOR EACH STATEMENT "
        "EXECUTE FUNCTION count_inserted_raw_events()"
    )
    # The data stored before this migration, counted once.
    op.execute(
        "INSERT INTO event_daily_counts (kind, day, records) "
        "SELECT 'event', (timezone('UTC', timestamp))::date, count(*) FROM events GROUP BY 2"
    )
    op.execute(
        "INSERT INTO event_daily_counts (kind, day, records) "
        "SELECT 'raw', (timezone('UTC', received_at))::date, count(*) FROM raw_events GROUP BY 2"
    )
    op.execute(
        "INSERT INTO logon_success_daily (username, source_ip, day, logons, last_logon) "
        "SELECT username, source_ip, (timezone('UTC', timestamp))::date, count(*), max(timestamp) "
        "FROM events WHERE event_category = 'authentication' AND event_action = 'logon' "
        "AND event_outcome = 'success' AND username IS NOT NULL AND username <> '' "
        "AND source_ip IS NOT NULL GROUP BY 1, 2, 3"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER raw_events_daily_counts ON raw_events")
    op.execute("DROP TRIGGER events_daily_summaries ON events")
    op.execute("DROP FUNCTION count_inserted_raw_events()")
    op.execute("DROP FUNCTION count_inserted_events()")
    op.drop_table("logon_success_daily")
    op.drop_table("event_daily_counts")
