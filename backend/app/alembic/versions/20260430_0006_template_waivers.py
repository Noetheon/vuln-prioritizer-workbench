"""add template waiver risk acceptance models

Revision ID: 20260430_0006
Revises: 20260429_0005
Create Date: 2026-04-30 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260430_0006"
down_revision = "20260429_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "waiver",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=True),
        sa.Column("asset_id", sa.Uuid(), nullable=True),
        sa.Column("cve_id", sa.String(length=64), nullable=True),
        sa.Column("asset_key", sa.String(length=200), nullable=True),
        sa.Column("service", sa.String(length=200), nullable=True),
        sa.Column("owner", sa.String(length=200), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.Date(), nullable=False),
        sa.Column("review_at", sa.Date(), nullable=True),
        sa.Column("approval_ref", sa.String(length=300), nullable=True),
        sa.Column("ticket_url", sa.String(length=1000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["asset.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_waiver_project_id"), "waiver", ["project_id"], unique=False)
    op.create_index(op.f("ix_waiver_cve_id"), "waiver", ["cve_id"], unique=False)
    op.create_index(op.f("ix_waiver_finding_id"), "waiver", ["finding_id"], unique=False)
    op.create_index(op.f("ix_waiver_asset_id"), "waiver", ["asset_id"], unique=False)
    op.create_index("ix_waiver_finding", "waiver", ["finding_id"], unique=False)
    op.create_index("ix_waiver_project_asset", "waiver", ["project_id", "asset_id"], unique=False)
    op.create_index(
        "ix_waiver_project_asset_key",
        "waiver",
        ["project_id", "asset_key"],
        unique=False,
    )
    op.create_index("ix_waiver_project_cve", "waiver", ["project_id", "cve_id"], unique=False)
    op.create_index("ix_waiver_project_service", "waiver", ["project_id", "service"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_waiver_project_service", table_name="waiver")
    op.drop_index("ix_waiver_project_cve", table_name="waiver")
    op.drop_index("ix_waiver_project_asset_key", table_name="waiver")
    op.drop_index("ix_waiver_project_asset", table_name="waiver")
    op.drop_index("ix_waiver_finding", table_name="waiver")
    op.drop_index(op.f("ix_waiver_asset_id"), table_name="waiver")
    op.drop_index(op.f("ix_waiver_finding_id"), table_name="waiver")
    op.drop_index(op.f("ix_waiver_cve_id"), table_name="waiver")
    op.drop_index(op.f("ix_waiver_project_id"), table_name="waiver")
    op.drop_table("waiver")
