"""Add llm_analysis column to trend_items.

Revision ID: 20260513_0002
Revises: 20260513_0001
Create Date: 2026-05-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "20260513_0002"
down_revision = "20260513_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("trend_items", sa.Column("llm_analysis", JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column("trend_items", "llm_analysis")
