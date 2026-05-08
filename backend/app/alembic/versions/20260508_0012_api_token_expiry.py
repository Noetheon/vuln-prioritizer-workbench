"""add expiry to scoped api tokens

Revision ID: 20260508_0012
Revises: 20260506_0011
Create Date: 2026-05-08 10:00:00.000000
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import sqlalchemy as sa
from alembic import op

revision = "20260508_0012"
down_revision = "20260506_0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    expires_at = datetime.now(UTC) + timedelta(days=90)
    with op.batch_alter_table("api_token") as batch_op:
        batch_op.add_column(sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))

    op.execute(
        sa.text(
            "UPDATE api_token SET expires_at = :expires_at WHERE expires_at IS NULL"
        ).bindparams(expires_at=expires_at)
    )

    with op.batch_alter_table("api_token") as batch_op:
        batch_op.alter_column(
            "expires_at",
            existing_type=sa.DateTime(timezone=True),
            nullable=False,
        )
        batch_op.create_index("ix_api_token_expires_at", ["expires_at"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("api_token") as batch_op:
        batch_op.drop_index("ix_api_token_expires_at")
        batch_op.drop_column("expires_at")
