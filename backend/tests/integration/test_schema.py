"""The schema as a whole: models match migrations, and the planned queries can use indexes."""

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from app.database.base import Base

pytestmark = pytest.mark.integration


def test_models_and_migrations_describe_the_same_schema(db_engine: Engine) -> None:
    """Fails when a model changes without a migration (or the other way round)."""
    with db_engine.connect() as connection:
        differences = compare_metadata(MigrationContext.configure(connection), Base.metadata)
    assert differences == []


# (query shape, index it must be able to use). Each is a question the product will ask:
# docs/database-schema.md, "Indexes (from the queries we know we will run)".
WINDOW = "timestamp BETWEEN now() - interval '1 day' AND now()"
QUERIES = [
    (
        f"SELECT id FROM events WHERE {WINDOW} ORDER BY timestamp DESC, id DESC LIMIT 50",
        "ix_events_timestamp_id",
    ),
    (
        "SELECT id FROM events WHERE event_category = 'authentication' "
        f"AND event_action = 'logon' AND {WINDOW}",
        "ix_events_category_action_ts",
    ),
    (
        f"SELECT id FROM events WHERE source_ip = '203.0.113.45' AND {WINDOW}",
        "ix_events_source_ip_ts",
    ),
    (
        f"SELECT id FROM events WHERE destination_ip = '10.0.0.5' AND {WINDOW}",
        "ix_events_destination_ip_ts",
    ),
    (f"SELECT id FROM events WHERE username = 'root' AND {WINDOW}", "ix_events_username_ts"),
    (f"SELECT id FROM events WHERE host = 'web-01' AND {WINDOW}", "ix_events_host_ts"),
    (
        "SELECT id FROM events WHERE command_line ILIKE '%certutil%'",
        "ix_events_command_line_trgm",
    ),
    ("SELECT id FROM events WHERE message ILIKE '%Failed password%'", "ix_events_message_trgm"),
    ("SELECT id FROM raw_events WHERE fingerprint = 'abc'", "uq_raw_events_fingerprint"),
    ("SELECT id FROM audit_logs ORDER BY occurred_at DESC LIMIT 50", "ix_audit_logs_occurred_at"),
    (
        "SELECT id FROM assets WHERE ip_addresses @> ARRAY['10.0.0.5'::inet]",
        "ix_assets_ip_addresses",
    ),
]


@pytest.mark.parametrize(("query", "index"), QUERIES, ids=[index for _, index in QUERIES])
def test_query_shape_can_use_its_index(db_session: Session, query: str, index: str) -> None:
    """The index fits the query: the planner can use it for the whole condition.

    On an empty table every plan costs about the same, so the planner may pick a sequential
    scan, or any other index scanned in full with the time range as a filter (it did pick
    ix_events_username_ts for a category query once). The alternatives are taken away inside
    this test's transaction, which is rolled back: sequential scans are disabled and every
    other index on the table is dropped. The plan must then use `index`, with the time range
    inside its index condition rather than as a separate filter. This proves fit, not choice
    at every table size; Phase 14 checks real plans with EXPLAIN ANALYZE on generated data.
    """
    db_session.execute(text("SET LOCAL enable_seqscan = off"))
    table = query.split(" FROM ", 1)[1].split()[0]
    others = db_session.scalars(
        text(
            "SELECT indexname FROM pg_indexes WHERE tablename = :table AND indexname != :index "
            "AND indexname NOT IN (SELECT conname FROM pg_constraint)"
        ),
        {"table": table, "index": index},
    ).all()
    for other in others:
        db_session.execute(text(f'DROP INDEX "{other}"'))
    plan = "\n".join(row[0] for row in db_session.execute(text(f"EXPLAIN {query}")))
    assert index in plan, plan
    if "BETWEEN" in query:
        index_condition = next(line for line in plan.splitlines() if "Index Cond" in line)
        assert '"timestamp" >=' in index_condition, plan
