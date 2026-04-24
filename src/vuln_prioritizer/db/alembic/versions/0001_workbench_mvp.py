"""Create Workbench MVP tables.

Revision ID: 0001_workbench_mvp
Revises:
Create Date: 2026-04-24
"""

from __future__ import annotations

from alembic import op

from vuln_prioritizer.db.base import target_metadata

revision = "0001_workbench_mvp"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the initial Workbench schema from ORM metadata."""
    target_metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    """Drop the initial Workbench schema."""
    target_metadata.drop_all(bind=op.get_bind())
