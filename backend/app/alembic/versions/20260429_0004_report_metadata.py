"""add template report metadata table

Revision ID: 20260429_0004
Revises: 20260428_0003
Create Date: 2026-04-29 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op

revision = "20260429_0004"
down_revision = "20260428_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "report",
        sa.Column("kind", sqlmodel.sql.sqltypes.AutoString(length=80), nullable=False),
        sa.Column("format", sqlmodel.sql.sqltypes.AutoString(length=40), nullable=False),
        sa.Column("filename", sqlmodel.sql.sqltypes.AutoString(length=500), nullable=False),
        sa.Column("content_type", sqlmodel.sql.sqltypes.AutoString(length=120), nullable=False),
        sa.Column("sha256", sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("analysis_run_id", sa.Uuid(), nullable=False),
        sa.Column("path", sa.String(length=1000), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["analysis_run_id"], ["analysis_run.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_report_analysis_run_id"),
        "report",
        ["analysis_run_id"],
        unique=False,
    )
    op.create_index(
        "ix_report_analysis_run_created_at",
        "report",
        ["analysis_run_id", "created_at"],
        unique=False,
    )
    op.create_index(op.f("ix_report_project_id"), "report", ["project_id"], unique=False)
    op.create_index(
        "ix_report_project_created_at",
        "report",
        ["project_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_report_project_created_at", table_name="report")
    op.drop_index(op.f("ix_report_project_id"), table_name="report")
    op.drop_index("ix_report_analysis_run_created_at", table_name="report")
    op.drop_index(op.f("ix_report_analysis_run_id"), table_name="report")
    op.drop_table("report")
