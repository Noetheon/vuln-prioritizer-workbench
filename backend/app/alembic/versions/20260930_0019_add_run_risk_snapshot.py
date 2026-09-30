"""
Record the project's absolute open-risk figures when each run completes.

Revision ID: 20260930_0019
Revises: 20260929_0018
Create Date: 2026-09-30 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260930_0019"
down_revision = "20260929_0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Earlier runs keep only their average risk index and get no snapshot."""
    op.create_table(
        "analysis_run_risk_snapshot",
        sa.Column("analysis_run_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("snapshot_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["analysis_run_id"], ["analysis_run.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("analysis_run_id"),
    )
    op.create_index(
        op.f("ix_analysis_run_risk_snapshot_project_id"),
        "analysis_run_risk_snapshot",
        ["project_id"],
        unique=False,
    )


def downgrade() -> None:
    """Drop the absolute open-risk snapshots."""
    op.drop_index(
        op.f("ix_analysis_run_risk_snapshot_project_id"),
        table_name="analysis_run_risk_snapshot",
    )
    op.drop_table("analysis_run_risk_snapshot")
