"""add analysis run provider snapshot models

Revision ID: 20260428_0003
Revises: 20260428_0002
Create Date: 2026-04-28 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op

revision = "20260428_0003"
down_revision = "20260428_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "provider_snapshot",
        sa.Column("nvd_last_sync", sqlmodel.sql.sqltypes.AutoString(length=64), nullable=True),
        sa.Column("epss_date", sqlmodel.sql.sqltypes.AutoString(length=32), nullable=True),
        sa.Column(
            "kev_catalog_version",
            sqlmodel.sql.sqltypes.AutoString(length=128),
            nullable=True,
        ),
        sa.Column("content_hash", sqlmodel.sql.sqltypes.AutoString(length=128), nullable=True),
        sa.Column("source_hashes_json", sa.JSON(), nullable=False),
        sa.Column("source_metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_provider_snapshot_content_hash"),
        "provider_snapshot",
        ["content_hash"],
        unique=True,
    )
    op.create_table(
        "analysis_run",
        sa.Column("input_type", sqlmodel.sql.sqltypes.AutoString(length=80), nullable=False),
        sa.Column("filename", sqlmodel.sql.sqltypes.AutoString(length=500), nullable=True),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("error_json", sa.JSON(), nullable=False),
        sa.Column("summary_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("provider_snapshot_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["provider_snapshot_id"],
            ["provider_snapshot.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_analysis_run_project_started_at",
        "analysis_run",
        ["project_id", "started_at"],
        unique=False,
    )
    op.create_index(
        "ix_analysis_run_project_status",
        "analysis_run",
        ["project_id", "status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_analysis_run_project_id"), "analysis_run", ["project_id"], unique=False
    )
    op.create_index(
        op.f("ix_analysis_run_provider_snapshot_id"),
        "analysis_run",
        ["provider_snapshot_id"],
        unique=False,
    )
    op.create_table(
        "finding_occurrence",
        sa.Column("source", sqlmodel.sql.sqltypes.AutoString(length=120), nullable=True),
        sa.Column("scanner", sqlmodel.sql.sqltypes.AutoString(length=120), nullable=True),
        sa.Column("raw_reference", sqlmodel.sql.sqltypes.AutoString(length=1000), nullable=True),
        sa.Column("fix_version", sqlmodel.sql.sqltypes.AutoString(length=300), nullable=True),
        sa.Column("evidence_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("analysis_run_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["analysis_run_id"], ["analysis_run.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_finding_occurrence_analysis_run_id"),
        "finding_occurrence",
        ["analysis_run_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_occurrence_finding_id"),
        "finding_occurrence",
        ["finding_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_finding_occurrence_finding_id"), table_name="finding_occurrence")
    op.drop_index(op.f("ix_finding_occurrence_analysis_run_id"), table_name="finding_occurrence")
    op.drop_table("finding_occurrence")
    op.drop_index(op.f("ix_analysis_run_provider_snapshot_id"), table_name="analysis_run")
    op.drop_index(op.f("ix_analysis_run_project_id"), table_name="analysis_run")
    op.drop_index("ix_analysis_run_project_status", table_name="analysis_run")
    op.drop_index("ix_analysis_run_project_started_at", table_name="analysis_run")
    op.drop_table("analysis_run")
    op.drop_index(op.f("ix_provider_snapshot_content_hash"), table_name="provider_snapshot")
    op.drop_table("provider_snapshot")
