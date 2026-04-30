"""add scoped template api tokens

Revision ID: 20260430_0008
Revises: 20260430_0007
Create Date: 2026-04-30 17:30:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op

revision = "20260430_0008"
down_revision = "20260430_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "api_token",
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(length=200), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("scopes_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_api_token_active", "api_token", ["revoked_at"], unique=False)
    op.create_index("ix_api_token_created_at", "api_token", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_api_token_created_at", table_name="api_token")
    op.drop_index("ix_api_token_active", table_name="api_token")
    op.drop_table("api_token")
