"""Add Workbench finding lifecycle and audit tables.

Revision ID: 0006_workbench_lifecycle_audit
Revises: 0005_workbench_integrations
Create Date: 2026-04-25
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006_workbench_lifecycle_audit"
down_revision = "0005_workbench_integrations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create additive lifecycle and audit tables."""
    if not _table_exists("finding_status_history"):
        op.create_table(
            "finding_status_history",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("project_id", sa.String(length=32), nullable=False),
            sa.Column("finding_id", sa.String(length=32), nullable=False),
            sa.Column("previous_status", sa.String(length=40), nullable=True),
            sa.Column("new_status", sa.String(length=40), nullable=False),
            sa.Column("actor", sa.String(length=200), nullable=True),
            sa.Column("reason", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_finding_status_history_finding",
            "finding_status_history",
            ["finding_id", "created_at"],
        )
        op.create_index(
            "ix_finding_status_history_project",
            "finding_status_history",
            ["project_id", "created_at"],
        )

    if not _table_exists("audit_events"):
        op.create_table(
            "audit_events",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("project_id", sa.String(length=32), nullable=True),
            sa.Column("event_type", sa.String(length=120), nullable=False),
            sa.Column("target_type", sa.String(length=120), nullable=True),
            sa.Column("target_id", sa.String(length=120), nullable=True),
            sa.Column("actor", sa.String(length=200), nullable=True),
            sa.Column("message", sa.Text(), nullable=True),
            sa.Column("metadata_json", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_audit_events_project_created",
            "audit_events",
            ["project_id", "created_at"],
        )
        op.create_index("ix_audit_events_event_type", "audit_events", ["event_type"])
        op.create_index("ix_audit_events_target", "audit_events", ["target_type", "target_id"])


def downgrade() -> None:
    """Drop lifecycle and audit tables."""
    for index_name, table_name in (
        ("ix_audit_events_target", "audit_events"),
        ("ix_audit_events_event_type", "audit_events"),
        ("ix_audit_events_project_created", "audit_events"),
        ("ix_finding_status_history_project", "finding_status_history"),
        ("ix_finding_status_history_finding", "finding_status_history"),
    ):
        if _table_exists(table_name):
            op.drop_index(index_name, table_name=table_name)
    for table_name in ("audit_events", "finding_status_history"):
        if _table_exists(table_name):
            op.drop_table(table_name)


def _table_exists(table_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table_name in inspector.get_table_names()
