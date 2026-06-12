"""
Add persisted risk index to analysis runs.

Revision ID: 20260612_0003
Revises: 20260608_0002
Create Date: 2026-06-12 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260612_0003"
down_revision = "20260608_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade function."""
    op.add_column(
        "analysis_run",
        sa.Column("risk_index", sa.Float(), nullable=True),
    )


def downgrade() -> None:
    """Downgrade function."""
    op.drop_column("analysis_run", "risk_index")
