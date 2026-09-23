"""Add compact governance invalidation state for scope-local evaluation."""

import sqlalchemy as sa
from alembic import op

revision = "20260923_0012"
down_revision = "20260923_0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Mark existing rows for one bounded hydration at their next synchronization."""
    op.add_column(
        "finding_current_projection", sa.Column("governance_sync_json", sa.JSON(), nullable=True)
    )


def downgrade() -> None:
    """Remove only disposable governance invalidation state."""
    op.drop_column("finding_current_projection", "governance_sync_json")
