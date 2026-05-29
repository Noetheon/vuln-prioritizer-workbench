"""
Add durable workflow run and event tables.

Revision ID: 20260528_0002
Revises: 20260512_0001
Create Date: 2026-05-28 18:52:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op

revision = "20260528_0002"
down_revision = "20260512_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create durable workflow tables."""
    op.create_table(
        "workflow_run",
        sa.Column("kind", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("title", sqlmodel.sql.sqltypes.AutoString(length=240), nullable=False),
        sa.Column("handler", sqlmodel.sql.sqltypes.AutoString(length=240), nullable=False),
        sa.Column("execution_mode", sqlmodel.sql.sqltypes.AutoString(length=40), nullable=False),
        sa.Column("idempotency_key", sqlmodel.sql.sqltypes.AutoString(length=160), nullable=True),
        sa.Column("current_stage", sqlmodel.sql.sqltypes.AutoString(length=120), nullable=True),
        sa.Column("progress_current", sa.Integer(), nullable=False),
        sa.Column("progress_total", sa.Integer(), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=False),
        sa.Column("max_retries", sa.Integer(), nullable=False),
        sa.Column("cancellation_requested", sa.Boolean(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("error_details_json", sa.JSON(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=True),
        sa.Column("analysis_run_id", sa.Uuid(), nullable=True),
        sa.Column("report_id", sa.Uuid(), nullable=True),
        sa.Column("parent_workflow_run_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["analysis_run_id"], ["analysis_run.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["parent_workflow_run_id"],
            ["workflow_run.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["report_id"], ["report.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_workflow_run_analysis_run_id",
        "workflow_run",
        ["analysis_run_id"],
        unique=False,
    )
    op.create_index(
        "ix_workflow_run_analysis_run_kind",
        "workflow_run",
        ["analysis_run_id", "kind"],
        unique=False,
    )
    op.create_index(
        "ix_workflow_run_idempotency_key",
        "workflow_run",
        ["idempotency_key"],
        unique=False,
    )
    op.create_index(
        "ix_workflow_run_parent_workflow_run_id",
        "workflow_run",
        ["parent_workflow_run_id"],
        unique=False,
    )
    op.create_index("ix_workflow_run_project_id", "workflow_run", ["project_id"], unique=False)
    op.create_index(
        "ix_workflow_run_project_created_at",
        "workflow_run",
        ["project_id", "created_at"],
        unique=False,
    )
    op.create_index("ix_workflow_run_report_id", "workflow_run", ["report_id"], unique=False)
    op.create_index("ix_workflow_run_status", "workflow_run", ["status"], unique=False)
    op.create_table(
        "workflow_event",
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("stage", sqlmodel.sql.sqltypes.AutoString(length=120), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("progress_current", sa.Integer(), nullable=True),
        sa.Column("progress_total", sa.Integer(), nullable=True),
        sa.Column("artifact_kind", sqlmodel.sql.sqltypes.AutoString(length=80), nullable=True),
        sa.Column("artifact_id", sqlmodel.sql.sqltypes.AutoString(length=120), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("workflow_run_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["workflow_run_id"], ["workflow_run.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("workflow_run_id", "sequence", name="uq_workflow_event_sequence"),
    )
    op.create_index(
        "ix_workflow_event_workflow_created_at",
        "workflow_event",
        ["workflow_run_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_workflow_event_workflow_run_id",
        "workflow_event",
        ["workflow_run_id"],
        unique=False,
    )


def downgrade() -> None:
    """Drop durable workflow tables."""
    op.drop_index("ix_workflow_event_workflow_run_id", table_name="workflow_event")
    op.drop_index("ix_workflow_event_workflow_created_at", table_name="workflow_event")
    op.drop_table("workflow_event")
    op.drop_index("ix_workflow_run_status", table_name="workflow_run")
    op.drop_index("ix_workflow_run_report_id", table_name="workflow_run")
    op.drop_index("ix_workflow_run_project_created_at", table_name="workflow_run")
    op.drop_index("ix_workflow_run_project_id", table_name="workflow_run")
    op.drop_index("ix_workflow_run_parent_workflow_run_id", table_name="workflow_run")
    op.drop_index("ix_workflow_run_idempotency_key", table_name="workflow_run")
    op.drop_index("ix_workflow_run_analysis_run_kind", table_name="workflow_run")
    op.drop_index("ix_workflow_run_analysis_run_id", table_name="workflow_run")
    op.drop_table("workflow_run")
