"""Add Workbench ATT&CK context tables.

Revision ID: 0002_workbench_attack_core
Revises: 0001_workbench_mvp
Create Date: 2026-04-24
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_workbench_attack_core"
down_revision = "0001_workbench_mvp"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create explicit ATT&CK mapping and finding context tables."""
    op.create_table(
        "attack_mappings",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("vulnerability_id", sa.String(length=32), nullable=False),
        sa.Column("cve_id", sa.String(length=64), nullable=False),
        sa.Column("attack_object_id", sa.String(length=64), nullable=False),
        sa.Column("attack_object_name", sa.String(length=300), nullable=True),
        sa.Column("mapping_type", sa.String(length=120), nullable=True),
        sa.Column("source", sa.String(length=80), nullable=False),
        sa.Column("source_version", sa.String(length=120), nullable=True),
        sa.Column("attack_version", sa.String(length=80), nullable=True),
        sa.Column("domain", sa.String(length=80), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("review_status", sa.String(length=80), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("references_json", sa.JSON(), nullable=False),
        sa.Column("mapping_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"],
            ["vulnerabilities.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_attack_mappings_cve_id", "attack_mappings", ["cve_id"])
    op.create_index(
        "ix_attack_mappings_technique",
        "attack_mappings",
        ["attack_object_id"],
    )
    op.create_index(
        "uq_attack_mappings_source_cve_technique_type",
        "attack_mappings",
        ["source", "cve_id", "attack_object_id", "mapping_type"],
        unique=True,
    )

    op.create_table(
        "finding_attack_contexts",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("finding_id", sa.String(length=32), nullable=False),
        sa.Column("analysis_run_id", sa.String(length=32), nullable=False),
        sa.Column("cve_id", sa.String(length=64), nullable=False),
        sa.Column("mapped", sa.Boolean(), nullable=False),
        sa.Column("source", sa.String(length=80), nullable=False),
        sa.Column("source_version", sa.String(length=120), nullable=True),
        sa.Column("attack_version", sa.String(length=80), nullable=True),
        sa.Column("domain", sa.String(length=80), nullable=True),
        sa.Column("attack_relevance", sa.String(length=40), nullable=False),
        sa.Column("threat_context_rank", sa.Integer(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("review_status", sa.String(length=80), nullable=False),
        sa.Column("techniques_json", sa.JSON(), nullable=False),
        sa.Column("tactics_json", sa.JSON(), nullable=False),
        sa.Column("mappings_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["analysis_run_id"],
            ["analysis_runs.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_finding_attack_contexts_finding_run",
        "finding_attack_contexts",
        ["finding_id", "analysis_run_id"],
        unique=True,
    )
    op.create_index(
        "ix_finding_attack_contexts_run_rank",
        "finding_attack_contexts",
        ["analysis_run_id", "threat_context_rank"],
    )
    op.create_index(
        "ix_finding_attack_contexts_technique_source",
        "finding_attack_contexts",
        ["source", "attack_relevance"],
    )


def downgrade() -> None:
    """Drop ATT&CK context tables."""
    op.drop_index(
        "ix_finding_attack_contexts_technique_source",
        table_name="finding_attack_contexts",
    )
    op.drop_index(
        "ix_finding_attack_contexts_run_rank",
        table_name="finding_attack_contexts",
    )
    op.drop_index(
        "uq_finding_attack_contexts_finding_run",
        table_name="finding_attack_contexts",
    )
    op.drop_table("finding_attack_contexts")
    op.drop_index("uq_attack_mappings_source_cve_technique_type", table_name="attack_mappings")
    op.drop_index("ix_attack_mappings_technique", table_name="attack_mappings")
    op.drop_index("ix_attack_mappings_cve_id", table_name="attack_mappings")
    op.drop_table("attack_mappings")
