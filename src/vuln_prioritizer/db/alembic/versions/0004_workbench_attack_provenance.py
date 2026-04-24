"""Add Workbench ATT&CK artifact provenance fields.

Revision ID: 0004_workbench_attack_provenance
Revises: 0003_workbench_governance_context
Create Date: 2026-04-24
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004_workbench_attack_provenance"
down_revision = "0003_workbench_governance_context"
branch_labels = None
depends_on = None

ATTACK_PROVENANCE_COLUMNS: tuple[tuple[str, int], ...] = (
    ("source_hash", 128),
    ("source_path", 1000),
    ("metadata_hash", 128),
    ("metadata_path", 1000),
)


def upgrade() -> None:
    """Persist ATT&CK mapping and technique metadata file provenance."""
    for table_name in ("attack_mappings", "finding_attack_contexts"):
        existing = _existing_columns(table_name)
        for name, length in ATTACK_PROVENANCE_COLUMNS:
            if name not in existing:
                op.add_column(table_name, sa.Column(name, sa.String(length=length), nullable=True))


def downgrade() -> None:
    """Remove ATT&CK artifact provenance fields."""
    for table_name in ("attack_mappings", "finding_attack_contexts"):
        existing = _existing_columns(table_name)
        for name, _length in reversed(ATTACK_PROVENANCE_COLUMNS):
            if name in existing:
                op.drop_column(table_name, name)


def _existing_columns(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    return {column["name"] for column in inspector.get_columns(table_name)}
