"""add shared rate limit buckets

Revision ID: 20260508_0013
Revises: 20260508_0012
Create Date: 2026-05-08 12:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260508_0013"
down_revision = "20260508_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rate_limit_bucket",
        sa.Column("bucket_key", sa.String(length=255), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("bucket_key"),
    )
    op.create_index(
        "ix_rate_limit_bucket_window_started_at",
        "rate_limit_bucket",
        ["window_started_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_rate_limit_bucket_window_started_at", table_name="rate_limit_bucket")
    op.drop_table("rate_limit_bucket")
