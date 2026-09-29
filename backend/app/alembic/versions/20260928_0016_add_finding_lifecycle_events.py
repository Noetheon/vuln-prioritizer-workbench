"""
Record finding status transitions with their cause and reason.

Revision ID: 20260928_0016
Revises: 20260923_0015
Create Date: 2026-09-28 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op

revision = "20260928_0016"
down_revision = "20260923_0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add the append-only finding lifecycle history."""
    op.create_table(
        "finding_lifecycle_event",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("analysis_run_id", sa.Uuid(), nullable=True),
        sa.Column("from_status", sa.String(length=40), nullable=False),
        sa.Column("to_status", sa.String(length=40), nullable=False),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("actor", sqlmodel.sql.sqltypes.AutoString(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["analysis_run_id"], ["analysis_run.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_finding_lifecycle_event_finding_created",
        "finding_lifecycle_event",
        ["finding_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_finding_lifecycle_event_project_created",
        "finding_lifecycle_event",
        ["project_id", "created_at"],
        unique=False,
    )


CLOSED_WORKFLOW_STATUSES = ("resolved", "false_positive")


def downgrade() -> None:
    """Drop the lifecycle history once no finding depends on the new statuses."""
    closed = (
        op.get_bind()
        .execute(
            sa.text("SELECT COUNT(*) FROM finding WHERE status IN (:resolved, :false_positive)"),
            {
                "resolved": CLOSED_WORKFLOW_STATUSES[0],
                "false_positive": CLOSED_WORKFLOW_STATUSES[1],
            },
        )
        .scalar_one()
    )
    if closed:
        # Earlier releases cannot read these statuses in finding rows or in the
        # current-decision overlays. Refuse instead of silently reopening work.
        raise RuntimeError(
            f"{closed} finding(s) are resolved or false positive. Reopen them before "
            "downgrading below revision 20260928_0016."
        )
    op.drop_index(
        "ix_finding_lifecycle_event_project_created",
        table_name="finding_lifecycle_event",
    )
    op.drop_index(
        "ix_finding_lifecycle_event_finding_created",
        table_name="finding_lifecycle_event",
    )
    op.drop_table("finding_lifecycle_event")
