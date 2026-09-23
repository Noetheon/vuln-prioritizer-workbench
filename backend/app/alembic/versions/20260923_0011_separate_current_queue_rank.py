"""Separate current queue ordering from immutable decision evidence."""

import sqlalchemy as sa
from alembic import op

revision = "20260923_0011"
down_revision = "20260906_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add disposable sort keys without rewriting historical decisions."""
    # NULL keys are hydrated once by the queue owner. This keeps migration memory
    # bounded and leaves immutable historical payloads and their hashes untouched.
    op.add_column(
        "finding_current_projection",
        sa.Column("operational_sort_key_json", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    """Remove compact keys while retaining decisions and current rank columns."""
    op.drop_column("finding_current_projection", "operational_sort_key_json")
