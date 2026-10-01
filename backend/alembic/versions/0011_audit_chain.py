"""Security hardening (Phase 13): a tamper-evident hash chain over the audit log.

Every new audit entry stores `prev_hash` (the previous entry's hash) and `entry_hash`
(SHA-256 of the previous hash and the entry's content, as a JSON array). A trigger computes
both inside the database, whatever the writer sends, under an advisory lock so concurrent
writers form one chain. Changing, removing or reordering an entry breaks every link after it
(`cli verify-audit`, `GET /api/audit/integrity`). Entries written before this migration keep
no hash: rewriting them would mean editing evidence, so the verifier reports them as not
covered.

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-02 11:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DIGEST_FUNCTION = """
CREATE FUNCTION audit_entry_digest(
    prev_hash text, entry_id uuid, occurred_at timestamptz, action text, result text,
    actor_id uuid, actor_label text, entity_type text, entity_id text, client_ip text,
    request_id text, details jsonb
) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
    SELECT encode(sha256(convert_to(jsonb_build_array(
        prev_hash, entry_id::text,
        to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'),
        action, result, actor_id::text, actor_label, entity_type, entity_id, client_ip,
        request_id, details
    )::text, 'UTF8')), 'hex')
$$;

CREATE FUNCTION audit_chain() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- The order number is drawn after the lock, so chain order and seq order always agree
    -- (a value drawn before waiting could be overtaken by another writer).
    PERFORM pg_advisory_xact_lock(1578606801);  -- 0x5E17A0D1: the chain's lock
    NEW.seq := nextval('audit_logs_seq');
    SELECT entry_hash INTO NEW.prev_hash
        FROM audit_logs WHERE entry_hash IS NOT NULL ORDER BY seq DESC LIMIT 1;
    NEW.prev_hash := coalesce(NEW.prev_hash, repeat('0', 64));  -- the first link
    NEW.entry_hash := audit_entry_digest(
        NEW.prev_hash, NEW.id, NEW.occurred_at, NEW.action, NEW.result, NEW.actor_id,
        NEW.actor_label, NEW.entity_type, NEW.entity_id, NEW.client_ip, NEW.request_id,
        NEW.details
    );
    RETURN NEW;
END;
$$;
"""


def upgrade() -> None:
    # The table is append-only (triggers reject UPDATE): adding columns rewrites no rows
    # through those triggers, and existing entries keep NULL hashes (not covered).
    # Existing entries get numbers in their current order; new ones from the chain trigger.
    op.execute("CREATE SEQUENCE audit_logs_seq AS bigint")
    op.add_column(
        "audit_logs",
        sa.Column(
            "seq",
            sa.BigInteger(),
            server_default=sa.text("nextval('audit_logs_seq')"),
            nullable=False,
        ),
    )
    op.alter_column("audit_logs", "seq", server_default=None)
    op.add_column("audit_logs", sa.Column("prev_hash", sa.String(length=64), nullable=True))
    op.add_column("audit_logs", sa.Column("entry_hash", sa.String(length=64), nullable=True))
    op.create_index(op.f("ix_audit_logs_seq"), "audit_logs", ["seq"], unique=True)
    op.execute(DIGEST_FUNCTION)
    op.execute(
        "CREATE TRIGGER audit_logs_chain BEFORE INSERT ON audit_logs "
        "FOR EACH ROW EXECUTE FUNCTION audit_chain()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER audit_logs_chain ON audit_logs")
    op.execute("DROP FUNCTION audit_chain()")
    op.execute(
        "DROP FUNCTION audit_entry_digest(text, uuid, timestamptz, text, text, uuid, text, "
        "text, text, text, text, jsonb)"
    )
    op.drop_index(op.f("ix_audit_logs_seq"), table_name="audit_logs")
    op.drop_column("audit_logs", "entry_hash")
    op.drop_column("audit_logs", "prev_hash")
    op.drop_column("audit_logs", "seq")
    op.execute("DROP SEQUENCE audit_logs_seq")
