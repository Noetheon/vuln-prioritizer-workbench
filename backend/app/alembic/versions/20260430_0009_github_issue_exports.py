"""add Workbench GitHub issue export idempotency

Revision ID: 20260430_0009
Revises: 20260430_0008
Create Date: 2026-04-30 21:20:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op

revision = "20260430_0009"
down_revision = "20260430_0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "github_issue_export",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=True),
        sa.Column(
            "repository",
            sqlmodel.sql.sqltypes.AutoString(length=200),
            nullable=False,
        ),
        sa.Column(
            "duplicate_key",
            sqlmodel.sql.sqltypes.AutoString(length=512),
            nullable=False,
        ),
        sa.Column("title", sqlmodel.sql.sqltypes.AutoString(length=500), nullable=False),
        sa.Column("issue_url", sqlmodel.sql.sqltypes.AutoString(length=1000), nullable=True),
        sa.Column("issue_number", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"]),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "project_id",
            "repository",
            "duplicate_key",
            name="uq_github_issue_export_project_repository_duplicate",
        ),
    )
    op.create_index(
        "ix_github_issue_export_created_at",
        "github_issue_export",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        "ix_github_issue_export_finding",
        "github_issue_export",
        ["finding_id"],
        unique=False,
    )
    op.create_index(
        "ix_github_issue_export_project",
        "github_issue_export",
        ["project_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_github_issue_export_project", table_name="github_issue_export")
    op.drop_index("ix_github_issue_export_finding", table_name="github_issue_export")
    op.drop_index("ix_github_issue_export_created_at", table_name="github_issue_export")
    op.drop_table("github_issue_export")
