"""Incidents (Phase 8): incidents, their alert links, notes, pinned evidence, activity, and
admin settings. Notes, evidence and activity are append-only (database triggers).

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-26 23:08:12.075726
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APPEND_ONLY = ("incident_notes", "incident_evidence", "incident_activity")


def upgrade() -> None:
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(
            ["updated_by"], ["users.id"], name=op.f("fk_app_settings_updated_by_users")
        ),
        sa.PrimaryKeyConstraint("key", name=op.f("pk_app_settings")),
    )
    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("number", sa.Integer(), sa.Identity(always=True), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("title_edited", sa.Boolean(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("created_reason", sa.String(length=500), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("risk_band", sa.String(length=16), nullable=False),
        sa.Column("risk_breakdown", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("risk_model_version", sa.String(length=16), nullable=False),
        sa.Column("assigned_to", sa.Uuid(), nullable=True),
        sa.Column("hosts", postgresql.ARRAY(sa.String(length=253)), nullable=False),
        sa.Column("usernames", postgresql.ARRAY(sa.String(length=256)), nullable=False),
        sa.Column("source_ips", postgresql.ARRAY(sa.String(length=45)), nullable=False),
        sa.Column("tactics", postgresql.ARRAY(sa.String(length=64)), nullable=False),
        sa.Column("techniques", postgresql.ARRAY(sa.String(length=16)), nullable=False),
        sa.Column("alert_count", sa.Integer(), nullable=False),
        sa.Column("first_activity_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("simulated", sa.Boolean(), nullable=False),
        sa.Column("disposition", sa.String(length=32), nullable=True),
        sa.Column("resolution", sa.String(length=4000), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.Uuid(), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("related_incident_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "(disposition IS NULL OR disposition IN ('confirmed_malicious', 'benign_expected', 'false_positive'))",
            name=op.f("ck_incidents_disposition_valid"),
        ),
        sa.CheckConstraint(
            "(status IN ('RESOLVED', 'CLOSED')) = (disposition IS NOT NULL AND resolution IS NOT NULL)",
            name=op.f("ck_incidents_resolution_when_resolved"),
        ),
        sa.CheckConstraint(
            "risk_band IN ('low', 'medium', 'high', 'critical')",
            name=op.f("ck_incidents_risk_band_valid"),
        ),
        sa.CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name=op.f("ck_incidents_severity_valid"),
        ),
        sa.CheckConstraint(
            "status IN ('OPEN', 'TRIAGED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED')",
            name=op.f("ck_incidents_status_valid"),
        ),
        sa.CheckConstraint(
            "first_activity_at <= last_activity_at", name=op.f("ck_incidents_activity_ordered")
        ),
        sa.CheckConstraint(
            "risk_score BETWEEN 0 AND 100", name=op.f("ck_incidents_risk_score_range")
        ),
        sa.ForeignKeyConstraint(
            ["assigned_to"], ["users.id"], name=op.f("fk_incidents_assigned_to_users")
        ),
        sa.ForeignKeyConstraint(
            ["related_incident_id"],
            ["incidents.id"],
            name=op.f("fk_incidents_related_incident_id_incidents"),
        ),
        sa.ForeignKeyConstraint(
            ["resolved_by"], ["users.id"], name=op.f("fk_incidents_resolved_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incidents")),
        sa.UniqueConstraint("number", name=op.f("uq_incidents_number")),
    )
    op.create_index(op.f("ix_incidents_assigned_to"), "incidents", ["assigned_to"], unique=False)
    op.create_index(
        "ix_incidents_hosts", "incidents", ["hosts"], unique=False, postgresql_using="gin"
    )
    op.create_index(
        "ix_incidents_last_activity_at", "incidents", ["last_activity_at"], unique=False
    )
    op.create_index(
        "ix_incidents_source_ips", "incidents", ["source_ips"], unique=False, postgresql_using="gin"
    )
    op.create_index(
        "ix_incidents_status_risk",
        "incidents",
        ["status", sa.literal_column("risk_score DESC")],
        unique=False,
    )
    op.create_index(
        "ix_incidents_usernames", "incidents", ["usernames"], unique=False, postgresql_using="gin"
    )
    op.create_table(
        "incident_activity",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("seq", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "kind IN ('CREATED', 'LINK', 'UNLINK', 'STATUS', 'ASSIGN', 'NOTE', 'EVIDENCE', 'RENAME')",
            name=op.f("ck_incident_activity_kind_valid"),
        ),
        sa.UniqueConstraint("seq", name=op.f("uq_incident_activity_seq")),
        sa.ForeignKeyConstraint(
            ["actor_id"], ["users.id"], name=op.f("fk_incident_activity_actor_id_users")
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_incident_activity_incident_id_incidents"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_activity")),
    )
    op.create_index(
        op.f("ix_incident_activity_incident_id"), "incident_activity", ["incident_id"], unique=False
    )
    op.create_table(
        "incident_alerts",
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("alert_id", sa.Uuid(), nullable=False),
        sa.Column("link_strength", sa.String(length=8), nullable=False),
        sa.Column("shared_entities", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column("link_source", sa.String(length=8), nullable=False),
        sa.Column("linked_by", sa.Uuid(), nullable=True),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "link_source IN ('engine', 'analyst')",
            name=op.f("ck_incident_alerts_link_source_valid"),
        ),
        sa.CheckConstraint(
            "link_strength IN ('STRONG', 'MEDIUM', 'WEAK', 'MANUAL', 'ORIGIN')",
            name=op.f("ck_incident_alerts_link_strength_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"], ["alerts.id"], name=op.f("fk_incident_alerts_alert_id_alerts")
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"], ["incidents.id"], name=op.f("fk_incident_alerts_incident_id_incidents")
        ),
        sa.ForeignKeyConstraint(
            ["linked_by"], ["users.id"], name=op.f("fk_incident_alerts_linked_by_users")
        ),
        sa.PrimaryKeyConstraint("incident_id", "alert_id", name=op.f("pk_incident_alerts")),
        sa.UniqueConstraint("alert_id", name=op.f("uq_incident_alerts_alert_id")),
    )
    op.create_table(
        "incident_notes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("author_id", sa.Uuid(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "char_length(body) BETWEEN 1 AND 10000", name=op.f("ck_incident_notes_body_length")
        ),
        sa.ForeignKeyConstraint(
            ["author_id"], ["users.id"], name=op.f("fk_incident_notes_author_id_users")
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"], ["incidents.id"], name=op.f("fk_incident_notes_incident_id_incidents")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_notes")),
    )
    op.create_index(
        op.f("ix_incident_notes_incident_id"), "incident_notes", ["incident_id"], unique=False
    )
    op.create_table(
        "incident_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=True),
        sa.Column("alert_id", sa.Uuid(), nullable=True),
        sa.Column("tag", sa.String(length=16), nullable=False),
        sa.Column("comment", sa.String(length=1000), nullable=True),
        sa.Column("action", sa.String(length=8), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "action IN ('PIN', 'UNPIN')", name=op.f("ck_incident_evidence_action_valid")
        ),
        sa.CheckConstraint(
            "tag IN ('initial_access', 'privilege', 'persistence', 'benign', 'needs_review')",
            name=op.f("ck_incident_evidence_tag_valid"),
        ),
        sa.CheckConstraint(
            "(event_id IS NULL) <> (alert_id IS NULL)",
            name=op.f("ck_incident_evidence_event_or_alert"),
        ),
        sa.ForeignKeyConstraint(
            ["actor_id"], ["users.id"], name=op.f("fk_incident_evidence_actor_id_users")
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"], ["alerts.id"], name=op.f("fk_incident_evidence_alert_id_alerts")
        ),
        sa.ForeignKeyConstraint(
            ["event_id"], ["events.id"], name=op.f("fk_incident_evidence_event_id_events")
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_incident_evidence_incident_id_incidents"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_evidence")),
    )
    op.create_index(
        op.f("ix_incident_evidence_incident_id"), "incident_evidence", ["incident_id"], unique=False
    )

    for table, default in (("detection_runs", "0"), ("ingestion_batches", None)):
        for column in ("incidents_created", "incidents_updated"):
            op.add_column(
                table,
                sa.Column(column, sa.Integer(), server_default=default, nullable=default is None),
            )

    # The investigation record cannot be rewritten: the same guard as the audit log and the
    # event store (reject_modification() comes from migration 0002).
    for table in APPEND_ONLY:
        op.execute(
            f"CREATE TRIGGER {table}_no_update_delete BEFORE UPDATE OR DELETE "
            f"ON {table} FOR EACH ROW EXECUTE FUNCTION reject_modification()"
        )
        op.execute(
            f"CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE "
            f"ON {table} FOR EACH STATEMENT EXECUTE FUNCTION reject_modification()"
        )


def downgrade() -> None:
    for table in ("detection_runs", "ingestion_batches"):
        for column in ("incidents_created", "incidents_updated"):
            op.drop_column(table, column)
    op.drop_index(op.f("ix_incident_evidence_incident_id"), table_name="incident_evidence")
    op.drop_table("incident_evidence")
    op.drop_index(op.f("ix_incident_notes_incident_id"), table_name="incident_notes")
    op.drop_table("incident_notes")
    op.drop_table("incident_alerts")
    op.drop_index(op.f("ix_incident_activity_incident_id"), table_name="incident_activity")
    op.drop_table("incident_activity")
    op.drop_index("ix_incidents_usernames", table_name="incidents", postgresql_using="gin")
    op.drop_index("ix_incidents_status_risk", table_name="incidents")
    op.drop_index("ix_incidents_source_ips", table_name="incidents", postgresql_using="gin")
    op.drop_index("ix_incidents_last_activity_at", table_name="incidents")
    op.drop_index("ix_incidents_hosts", table_name="incidents", postgresql_using="gin")
    op.drop_index(op.f("ix_incidents_assigned_to"), table_name="incidents")
    op.drop_table("incidents")
    op.drop_table("app_settings")
