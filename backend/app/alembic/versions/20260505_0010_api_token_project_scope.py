"""add project scope to template api tokens

Revision ID: 20260505_0010
Revises: 20260430_0009
Create Date: 2026-05-05 10:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260505_0010"
down_revision = "20260430_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("api_token", recreate="always") as batch_op:
        batch_op.add_column(sa.Column("project_id", sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            "fk_api_token_project_id_project",
            "project",
            ["project_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_index("ix_api_token_project_id", ["project_id"], unique=False)
    op.execute(
        sa.text(
            """
            UPDATE api_token
            SET revoked_at = CURRENT_TIMESTAMP
            WHERE revoked_at IS NULL
              AND CAST(scopes_json AS TEXT) NOT LIKE '%"admin"%'
            """
        )
    )


def downgrade() -> None:
    with op.batch_alter_table("api_token", recreate="always") as batch_op:
        batch_op.drop_index("ix_api_token_project_id")
        batch_op.drop_constraint("fk_api_token_project_id_project", type_="foreignkey")
        batch_op.drop_column("project_id")
