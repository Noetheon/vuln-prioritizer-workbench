"""Add scoped API tokens.

Revision ID: 0008_api_token_scopes
Revises: 0007_jobs_retention
Create Date: 2026-04-30
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008_api_token_scopes"
down_revision = "0007_jobs_retention"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add canonical scope metadata to legacy Workbench API tokens."""
    if not _column_exists("api_tokens", "scopes_json"):
        op.add_column(
            "api_tokens",
            sa.Column("scopes_json", sa.JSON(), nullable=False, server_default='["admin"]'),
        )


def downgrade() -> None:
    """Remove API token scope metadata."""
    if _column_exists("api_tokens", "scopes_json"):
        op.drop_column("api_tokens", "scopes_json")


def _table_exists(table_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table_name in inspector.get_table_names()


def _column_exists(table_name: str, column_name: str) -> bool:
    if not _table_exists(table_name):
        return False
    inspector = sa.inspect(op.get_bind())
    return column_name in {column["name"] for column in inspector.get_columns(table_name)}
