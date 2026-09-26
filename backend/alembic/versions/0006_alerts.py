"""Alerts (Phase 7): alerts, their evidence links, and alert counts on runs and batches.

One open alert per deduplication key is a database guarantee (partial unique index).

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-26 19:01:00.272825
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(length=16), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("indicator", sa.String(length=40), nullable=True),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("disposition", sa.String(length=32), nullable=True),
        sa.Column("priority_score", sa.Integer(), nullable=False),
        sa.Column("priority_band", sa.String(length=16), nullable=False),
        sa.Column("priority_breakdown", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("risk_model_version", sa.String(length=16), nullable=False),
        sa.Column("dedup_key", sa.String(length=64), nullable=False),
        sa.Column("group_values", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("host", sa.String(length=253), nullable=True),
        sa.Column("username", sa.String(length=256), nullable=True),
        sa.Column("target_username", sa.String(length=256), nullable=True),
        sa.Column("source_ip", postgresql.INET(), nullable=True),
        sa.Column("destination_ip", postgresql.INET(), nullable=True),
        sa.Column("asset_id", sa.Uuid(), nullable=True),
        sa.Column("identity_id", sa.Uuid(), nullable=True),
        sa.Column("first_event_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("evidence_truncated", sa.Boolean(), nullable=False),
        sa.Column("peak_count", sa.Integer(), nullable=False),
        sa.Column("detection_count", sa.Integer(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("facts", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("entities", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("investigation", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("response", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("mitre", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("history", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("previous_alert_id", sa.Uuid(), nullable=True),
        sa.Column("simulated", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status_changed_by", sa.Uuid(), nullable=True),
        sa.Column("triaged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.Uuid(), nullable=True),
        sa.Column("status_note", sa.String(length=2000), nullable=True),
        sa.CheckConstraint(
            "(disposition IS NULL OR disposition IN ('confirmed_malicious', 'benign_expected'))",
            name=op.f("ck_alerts_disposition_valid"),
        ),
        sa.CheckConstraint(
            "(status = 'RESOLVED') = (disposition IS NOT NULL)",
            name=op.f("ck_alerts_disposition_when_resolved"),
        ),
        sa.CheckConstraint(
            "confidence IN ('low', 'medium', 'high')", name=op.f("ck_alerts_confidence_valid")
        ),
        sa.CheckConstraint(
            "priority_band IN ('low', 'medium', 'high', 'critical')",
            name=op.f("ck_alerts_priority_band_valid"),
        ),
        sa.CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name=op.f("ck_alerts_severity_valid"),
        ),
        sa.CheckConstraint(
            "status IN ('NEW', 'TRIAGED', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE')",
            name=op.f("ck_alerts_status_valid"),
        ),
        sa.CheckConstraint("event_count >= 1", name=op.f("ck_alerts_event_count_positive")),
        sa.CheckConstraint(
            "first_event_at <= last_event_at", name=op.f("ck_alerts_event_times_ordered")
        ),
        sa.CheckConstraint(
            "priority_score BETWEEN 0 AND 100", name=op.f("ck_alerts_priority_score_range")
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name=op.f("fk_alerts_asset_id_assets")
        ),
        sa.ForeignKeyConstraint(
            ["identity_id"], ["identities.id"], name=op.f("fk_alerts_identity_id_identities")
        ),
        sa.ForeignKeyConstraint(
            ["previous_alert_id"], ["alerts.id"], name=op.f("fk_alerts_previous_alert_id_alerts")
        ),
        sa.ForeignKeyConstraint(
            ["resolved_by"], ["users.id"], name=op.f("fk_alerts_resolved_by_users")
        ),
        sa.ForeignKeyConstraint(
            ["rule_id"], ["detection_rules.rule_id"], name=op.f("fk_alerts_rule_id_detection_rules")
        ),
        sa.ForeignKeyConstraint(
            ["status_changed_by"], ["users.id"], name=op.f("fk_alerts_status_changed_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alerts")),
    )
    op.create_index(op.f("ix_alerts_asset_id"), "alerts", ["asset_id"], unique=False)
    op.create_index(op.f("ix_alerts_host"), "alerts", ["host"], unique=False)
    op.create_index(op.f("ix_alerts_identity_id"), "alerts", ["identity_id"], unique=False)
    op.create_index("ix_alerts_last_event_at", "alerts", ["last_event_at"], unique=False)
    op.create_index("ix_alerts_rule_created", "alerts", ["rule_id", "created_at"], unique=False)
    op.create_index(op.f("ix_alerts_source_ip"), "alerts", ["source_ip"], unique=False)
    op.create_index(
        "ix_alerts_status_priority",
        "alerts",
        ["status", sa.literal_column("priority_score DESC")],
        unique=False,
    )
    op.create_index(op.f("ix_alerts_username"), "alerts", ["username"], unique=False)
    op.create_index(
        "uq_alerts_dedup_key_active",
        "alerts",
        ["dedup_key"],
        unique=True,
        postgresql_where=sa.text("status IN ('NEW', 'TRIAGED', 'IN_PROGRESS')"),
    )
    op.create_table(
        "alert_events",
        sa.Column("alert_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["alert_id"], ["alerts.id"], name=op.f("fk_alert_events_alert_id_alerts")
        ),
        sa.ForeignKeyConstraint(
            ["event_id"], ["events.id"], name=op.f("fk_alert_events_event_id_events")
        ),
        sa.PrimaryKeyConstraint("alert_id", "event_id", name=op.f("pk_alert_events")),
    )
    op.create_index(op.f("ix_alert_events_event_id"), "alert_events", ["event_id"], unique=False)
    op.add_column(
        "detection_runs",
        sa.Column("alerts_created", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column(
        "detection_runs",
        sa.Column("alerts_updated", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column("ingestion_batches", sa.Column("alerts_created", sa.Integer(), nullable=True))
    op.add_column("ingestion_batches", sa.Column("alerts_updated", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("ingestion_batches", "alerts_updated")
    op.drop_column("ingestion_batches", "alerts_created")
    op.drop_column("detection_runs", "alerts_updated")
    op.drop_column("detection_runs", "alerts_created")
    op.drop_index(op.f("ix_alert_events_event_id"), table_name="alert_events")
    op.drop_table("alert_events")
    op.drop_index(
        "uq_alerts_dedup_key_active",
        table_name="alerts",
        postgresql_where=sa.text("status IN ('NEW', 'TRIAGED', 'IN_PROGRESS')"),
    )
    op.drop_index(op.f("ix_alerts_username"), table_name="alerts")
    op.drop_index("ix_alerts_status_priority", table_name="alerts")
    op.drop_index(op.f("ix_alerts_source_ip"), table_name="alerts")
    op.drop_index("ix_alerts_rule_created", table_name="alerts")
    op.drop_index("ix_alerts_last_event_at", table_name="alerts")
    op.drop_index(op.f("ix_alerts_identity_id"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_host"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_asset_id"), table_name="alerts")
    op.drop_table("alerts")
