"""
Add the project waiver-freshness marker.

Revision ID: 20260904_0006
Revises: 20260904_0005
Create Date: 2026-09-04 00:30:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260904_0006"
down_revision = "20260904_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add a nullable marker so legacy projects are refreshed on first access."""
    op.add_column(
        "project",
        sa.Column("waiver_evaluated_on", sa.Date(), nullable=True),
    )


def downgrade() -> None:
    """Remove the project waiver-freshness marker."""
    op.drop_column("project", "waiver_evaluated_on")
