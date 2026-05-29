"""
Add DB-backed workflow queue runtime fields.

Revision ID: 20260529_0003
Revises: 20260528_0002
Create Date: 2026-05-29 09:15:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op

revision = "20260529_0003"
down_revision = "20260528_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add queue payload and worker lease columns."""
    op.add_column(
        "workflow_run",
        sa.Column(
            "queue_name",
            sqlmodel.sql.sqltypes.AutoString(length=80),
            nullable=False,
            server_default="default",
        ),
    )
    op.add_column(
        "workflow_run",
        sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "workflow_run",
        sa.Column("payload_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )
    op.add_column(
        "workflow_run",
        sa.Column("locked_by", sqlmodel.sql.sqltypes.AutoString(length=120), nullable=True),
    )
    op.add_column(
        "workflow_run",
        sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "workflow_run",
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "workflow_run",
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "workflow_run",
        sa.Column("attempt_started_at", sa.DateTime(timezone=True), nullable=True),
    )
    if op.get_bind().dialect.name != "sqlite":
        op.alter_column("workflow_run", "queue_name", server_default=None)
        op.alter_column("workflow_run", "priority", server_default=None)
        op.alter_column("workflow_run", "payload_json", server_default=None)
    op.create_index(
        "ix_workflow_run_queue_ready",
        "workflow_run",
        ["queue_name", "status", "next_retry_at"],
        unique=False,
    )


def downgrade() -> None:
    """Remove queue payload and worker lease columns."""
    op.drop_index("ix_workflow_run_queue_ready", table_name="workflow_run")
    op.drop_column("workflow_run", "attempt_started_at")
    op.drop_column("workflow_run", "last_heartbeat_at")
    op.drop_column("workflow_run", "lease_expires_at")
    op.drop_column("workflow_run", "locked_at")
    op.drop_column("workflow_run", "locked_by")
    op.drop_column("workflow_run", "payload_json")
    op.drop_column("workflow_run", "priority")
    op.drop_column("workflow_run", "queue_name")
