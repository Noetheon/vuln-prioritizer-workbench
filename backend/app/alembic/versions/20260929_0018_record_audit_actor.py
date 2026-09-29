"""
Record who triggered each audit event.

Revision ID: 20260929_0018
Revises: 20260928_0017
Create Date: 2026-09-29 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op

revision = "20260929_0018"
down_revision = "20260928_0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add the acting user; earlier events keep no actor."""
    op.add_column(
        "audit_event",
        sa.Column("actor", sqlmodel.sql.sqltypes.AutoString(length=320), nullable=True),
    )


def downgrade() -> None:
    """Drop the acting user from audit events."""
    with op.batch_alter_table("audit_event") as batch_op:
        batch_op.drop_column("actor")
