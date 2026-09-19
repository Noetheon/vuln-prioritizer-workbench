"""Add the project decision publication revision without rewriting evidence."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260906_0010"
down_revision = "20260904_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Backfill every existing project with the initial revision."""
    op.add_column(
        "project", sa.Column("decision_revision", sa.Integer(), nullable=False, server_default="0")
    )


def downgrade() -> None:
    """Remove only the publication precondition, preserving decision history."""
    op.drop_column("project", "decision_revision")
