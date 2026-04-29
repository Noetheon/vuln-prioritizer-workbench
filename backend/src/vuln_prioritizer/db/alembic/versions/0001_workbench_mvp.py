"""Create Workbench MVP tables.

Revision ID: 0001_workbench_mvp
Revises:
Create Date: 2026-04-24
"""

from __future__ import annotations

from alembic import op

from vuln_prioritizer.db.base import target_metadata

revision = "0001_workbench_mvp"
down_revision = None
branch_labels = None
depends_on = None

MVP_TABLES = (
    "projects",
    "provider_snapshots",
    "analysis_runs",
    "assets",
    "components",
    "vulnerabilities",
    "findings",
    "finding_occurrences",
    "reports",
    "evidence_bundles",
)


def upgrade() -> None:
    """Create the initial Workbench schema from the v0.5 table set."""
    target_metadata.create_all(
        bind=op.get_bind(),
        tables=[target_metadata.tables[name] for name in MVP_TABLES],
    )


def downgrade() -> None:
    """Drop the initial Workbench schema."""
    target_metadata.drop_all(
        bind=op.get_bind(),
        tables=[target_metadata.tables[name] for name in reversed(MVP_TABLES)],
    )
