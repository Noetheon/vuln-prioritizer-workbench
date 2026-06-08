"""
Add runtime service heartbeat table.

Revision ID: 20260608_0002
Revises: 20260512_0001
Create Date: 2026-06-08 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op

revision = "20260608_0002"
down_revision = "20260512_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade function."""
    op.create_table(
        "runtime_service_heartbeat",
        sa.Column("service_name", sqlmodel.sql.sqltypes.AutoString(length=120), nullable=False),
        sa.Column("instance_id", sqlmodel.sql.sqltypes.AutoString(length=160), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("service_name", "instance_id"),
    )
    op.create_index(
        "ix_runtime_service_heartbeat_service_last_seen",
        "runtime_service_heartbeat",
        ["service_name", "last_seen_at"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade function."""
    op.drop_index(
        "ix_runtime_service_heartbeat_service_last_seen",
        table_name="runtime_service_heartbeat",
    )
    op.drop_table("runtime_service_heartbeat")
