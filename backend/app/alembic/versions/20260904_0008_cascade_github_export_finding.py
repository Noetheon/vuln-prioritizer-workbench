"""
Cascade GitHub export links when their finding is deleted.

Revision ID: 20260904_0008
Revises: 20260904_0007
Create Date: 2026-09-04 02:00:00.000000
"""

from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "20260904_0008"
down_revision = "20260904_0007"
branch_labels = None
depends_on = None

_FINDING_FK_NAME = "fk_github_issue_export_finding_id_finding"
_BATCH_NAMING_CONVENTION = {
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
}


def upgrade() -> None:
    """Cascade finding-linked export history during intentional project deletion."""
    _replace_finding_foreign_key(ondelete="CASCADE")


def downgrade() -> None:
    """Restore the legacy non-cascading finding foreign key."""
    _replace_finding_foreign_key(ondelete=None)


def _replace_finding_foreign_key(*, ondelete: str | None) -> None:
    connection = op.get_bind()
    existing_name = _finding_foreign_key_name(connection)
    _start_portable_write_transaction(connection)
    with op.batch_alter_table(
        "github_issue_export",
        naming_convention=_BATCH_NAMING_CONVENTION,
    ) as batch_op:
        batch_op.drop_constraint(existing_name, type_="foreignkey")
        batch_op.create_foreign_key(
            _FINDING_FK_NAME,
            "finding",
            ["finding_id"],
            ["id"],
            ondelete=ondelete,
        )


def _start_portable_write_transaction(connection: Any) -> None:
    """Start SQLite's transaction before the batch DDL can replace the table."""
    metadata = sa.MetaData()
    export = sa.Table(
        "github_issue_export",
        metadata,
        autoload_with=connection,
        resolve_fks=False,
    )
    connection.execute(sa.update(export).where(sa.false()).values(id=export.c.id))


def _finding_foreign_key_name(connection: Any) -> str:
    foreign_keys = sa.inspect(connection).get_foreign_keys("github_issue_export")
    matches = [
        item
        for item in foreign_keys
        if item.get("constrained_columns") == ["finding_id"]
        and item.get("referred_table") == "finding"
    ]
    if len(matches) != 1:
        raise RuntimeError(
            "Expected exactly one github_issue_export.finding_id foreign key; "
            f"found {len(matches)}."
        )
    return str(matches[0].get("name") or _FINDING_FK_NAME)
