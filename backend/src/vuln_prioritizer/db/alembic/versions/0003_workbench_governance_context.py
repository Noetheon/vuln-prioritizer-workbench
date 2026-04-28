"""Add Workbench governance context fields.

Revision ID: 0003_workbench_governance
Revises: 0002_workbench_attack_core
Create Date: 2026-04-24
"""

from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "0003_workbench_governance"
down_revision = "0002_workbench_attack_core"
branch_labels = None
depends_on = None

FINDING_COLUMNS: tuple[tuple[str, sa.Column[Any]], ...] = (
    (
        "under_investigation",
        sa.Column("under_investigation", sa.Boolean(), nullable=False, server_default=sa.false()),
    ),
    ("waiver_status", sa.Column("waiver_status", sa.String(length=80), nullable=True)),
    ("waiver_reason", sa.Column("waiver_reason", sa.Text(), nullable=True)),
    ("waiver_owner", sa.Column("waiver_owner", sa.String(length=200), nullable=True)),
    ("waiver_expires_on", sa.Column("waiver_expires_on", sa.String(length=32), nullable=True)),
    ("waiver_review_on", sa.Column("waiver_review_on", sa.String(length=32), nullable=True)),
    ("waiver_days_remaining", sa.Column("waiver_days_remaining", sa.Integer(), nullable=True)),
    ("waiver_scope", sa.Column("waiver_scope", sa.String(length=120), nullable=True)),
    ("waiver_id", sa.Column("waiver_id", sa.String(length=200), nullable=True)),
    (
        "waiver_matched_scope",
        sa.Column("waiver_matched_scope", sa.String(length=120), nullable=True),
    ),
    ("waiver_approval_ref", sa.Column("waiver_approval_ref", sa.String(length=300), nullable=True)),
    ("waiver_ticket_url", sa.Column("waiver_ticket_url", sa.String(length=1000), nullable=True)),
)


def upgrade() -> None:
    """Persist VEX and waiver lifecycle fields on Workbench findings."""
    existing = _existing_columns("findings")
    for name, column in FINDING_COLUMNS:
        if name not in existing:
            op.add_column("findings", column)


def downgrade() -> None:
    """Remove persisted governance fields from Workbench findings."""
    existing = _existing_columns("findings")
    for name, _column in reversed(FINDING_COLUMNS):
        if name in existing:
            op.drop_column("findings", name)


def _existing_columns(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    return {column["name"] for column in inspector.get_columns(table_name)}
