"""Initial production schema.

Revision ID: 20260513_0001
Revises:
Create Date: 2026-05-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260513_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "raw_items",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("source_name", sa.String(length=128), nullable=False),
        sa.Column("external_id", sa.String(length=512), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("raw_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("source_name", "external_id", name="uq_raw_source_external"),
    )
    op.create_index("ix_raw_items_source_name", "raw_items", ["source_name"])
    op.create_index("ix_raw_items_published_at", "raw_items", ["published_at"])

    op.create_table(
        "trend_items",
        sa.Column("item_id", sa.String(length=128), primary_key=True),
        sa.Column("dedupe_key", sa.String(length=256), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("source_name", sa.String(length=128), nullable=False),
        sa.Column("community", sa.String(length=128)),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("what_went_wrong", sa.Text(), nullable=False, server_default=""),
        sa.Column("why_this_matters_now", sa.Text(), nullable=False, server_default=""),
        sa.Column("cves", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("cvss_base", sa.Float()),
        sa.Column("epss_probability", sa.Float()),
        sa.Column("epss_percentile", sa.Float()),
        sa.Column("kev_flag", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("tenable_vpr", sa.Float()),
        sa.Column("exploit_evidence", sa.Text()),
        sa.Column("engagement_metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("criticality_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("severity_label", sa.String(length=16), nullable=False),
        sa.Column("score_breakdown", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("raw", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_trend_items_dedupe_key", "trend_items", ["dedupe_key"])
    op.create_index("ix_trend_items_source_name", "trend_items", ["source_name"])
    op.create_index("ix_trend_items_published_at", "trend_items", ["published_at"])
    op.create_index("ix_trend_items_severity_label", "trend_items", ["severity_label"])

    op.create_table(
        "cve_enrichments",
        sa.Column("cve", sa.String(length=32), primary_key=True),
        sa.Column("cvss_base", sa.Float()),
        sa.Column("cvss_severity", sa.String(length=32)),
        sa.Column("epss_probability", sa.Float()),
        sa.Column("epss_percentile", sa.Float()),
        sa.Column("kev", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("tenable_vpr", sa.Float()),
        sa.Column("exploit_maturity", sa.String(length=128)),
        sa.Column("vendor_project", sa.String(length=256)),
        sa.Column("product", sa.String(length=256)),
        sa.Column("vulnerability_name", sa.Text()),
        sa.Column("required_action", sa.Text()),
        sa.Column("references", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("raw", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "source_policies",
        sa.Column("source_name", sa.String(length=128), primary_key=True),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("trust_tier", sa.Float(), nullable=False, server_default="0.7"),
        sa.Column("weight", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("allowlist", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("denylist", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "source_health",
        sa.Column("source_name", sa.String(length=128), primary_key=True),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("last_error_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        sa.Column("lag_seconds", sa.Integer()),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rate_limited_until", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "alert_deliveries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("item_id", sa.String(length=128), nullable=False),
        sa.Column("delivery_type", sa.String(length=32), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("provider_message_id", sa.String(length=256)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("item_id", "delivery_type", name="uq_alert_item_type"),
    )
    op.create_index("ix_alert_deliveries_item_id", "alert_deliveries", ["item_id"])

    op.create_table(
        "digest_runs",
        sa.Column("digest_date", sa.Date(), primary_key=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "source_quality_metrics",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_name", sa.String(length=128), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signal_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duplicate_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("useful_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("noisy_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("computed_weight", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index(
        "ix_source_quality_metrics_source_name", "source_quality_metrics", ["source_name"]
    )


def downgrade() -> None:
    op.drop_index("ix_source_quality_metrics_source_name", table_name="source_quality_metrics")
    op.drop_table("source_quality_metrics")
    op.drop_table("digest_runs")
    op.drop_index("ix_alert_deliveries_item_id", table_name="alert_deliveries")
    op.drop_table("alert_deliveries")
    op.drop_table("source_health")
    op.drop_table("source_policies")
    op.drop_table("cve_enrichments")
    op.drop_index("ix_trend_items_severity_label", table_name="trend_items")
    op.drop_index("ix_trend_items_published_at", table_name="trend_items")
    op.drop_index("ix_trend_items_source_name", table_name="trend_items")
    op.drop_index("ix_trend_items_dedupe_key", table_name="trend_items")
    op.drop_table("trend_items")
    op.drop_index("ix_raw_items_published_at", table_name="raw_items")
    op.drop_index("ix_raw_items_source_name", table_name="raw_items")
    op.drop_table("raw_items")
