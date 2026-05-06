"""add Workbench ATT&CK Lite models

Revision ID: 20260429_0005
Revises: 20260429_0004
Create Date: 2026-04-29 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op

revision = "20260429_0005"
down_revision = "20260429_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "attack_tactic",
        sa.Column("tactic_id", sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False),
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(length=200), nullable=False),
        sa.Column("short_name", sqlmodel.sql.sqltypes.AutoString(length=120), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("attack_version", sqlmodel.sql.sqltypes.AutoString(length=40), nullable=True),
        sa.Column("url", sqlmodel.sql.sqltypes.AutoString(length=500), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_attack_tactic_tactic_id"),
        "attack_tactic",
        ["tactic_id"],
        unique=True,
    )

    op.create_table(
        "attack_technique",
        sa.Column("technique_id", sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False),
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(length=300), nullable=False),
        sa.Column("tactic_ids_json", sa.JSON(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("attack_version", sqlmodel.sql.sqltypes.AutoString(length=40), nullable=True),
        sa.Column("url", sqlmodel.sql.sqltypes.AutoString(length=500), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("deprecated", sa.Boolean(), nullable=False),
        sa.Column("defensive_note", sa.Text(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_attack_technique_technique_id"),
        "attack_technique",
        ["technique_id"],
        unique=True,
    )

    op.create_table(
        "cve_attack_mapping",
        sa.Column("cve_id", sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column("technique_id", sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False),
        sa.Column("technique_name", sqlmodel.sql.sqltypes.AutoString(length=300), nullable=True),
        sa.Column("tactic_ids_json", sa.JSON(), nullable=False),
        sa.Column("mapping_type", sa.String(length=80), nullable=False),
        sa.Column("source", sqlmodel.sql.sqltypes.AutoString(length=200), nullable=False),
        sa.Column("source_url", sqlmodel.sql.sqltypes.AutoString(length=500), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("review_status", sa.String(length=80), nullable=False),
        sa.Column("defensive_note", sa.Text(), nullable=False),
        sa.Column("references_json", sa.JSON(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("vulnerability_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["technique_id"], ["attack_technique.technique_id"]),
        sa.ForeignKeyConstraint(["vulnerability_id"], ["vulnerability.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "source",
            "cve_id",
            "technique_id",
            "mapping_type",
            name="uq_cve_attack_mapping_source_cve_technique_type",
        ),
    )
    op.create_index(
        "ix_cve_attack_mapping_cve_id",
        "cve_attack_mapping",
        ["cve_id"],
        unique=False,
    )
    op.create_index(
        "ix_cve_attack_mapping_review_status",
        "cve_attack_mapping",
        ["review_status"],
        unique=False,
    )
    op.create_index(
        "ix_cve_attack_mapping_technique_id",
        "cve_attack_mapping",
        ["technique_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_cve_attack_mapping_vulnerability_id"),
        "cve_attack_mapping",
        ["vulnerability_id"],
        unique=False,
    )

    op.create_table(
        "finding_attack_context",
        sa.Column("cve_id", sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column("mapped", sa.Boolean(), nullable=False),
        sa.Column("source", sqlmodel.sql.sqltypes.AutoString(length=200), nullable=False),
        sa.Column("review_status", sa.String(length=80), nullable=False),
        sa.Column("defensive_note", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("technique_ids_json", sa.JSON(), nullable=False),
        sa.Column("tactic_ids_json", sa.JSON(), nullable=False),
        sa.Column("mappings_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("analysis_run_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["analysis_run_id"], ["analysis_run.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "finding_id",
            "analysis_run_id",
            name="uq_finding_attack_context_finding_run",
        ),
    )
    op.create_index(
        op.f("ix_finding_attack_context_analysis_run_id"),
        "finding_attack_context",
        ["analysis_run_id"],
        unique=False,
    )
    op.create_index(
        "ix_finding_attack_context_cve_id",
        "finding_attack_context",
        ["cve_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_attack_context_finding_id"),
        "finding_attack_context",
        ["finding_id"],
        unique=False,
    )
    op.create_index(
        "ix_finding_attack_context_run_review",
        "finding_attack_context",
        ["analysis_run_id", "review_status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_finding_attack_context_run_review", table_name="finding_attack_context")
    op.drop_index(op.f("ix_finding_attack_context_finding_id"), table_name="finding_attack_context")
    op.drop_index("ix_finding_attack_context_cve_id", table_name="finding_attack_context")
    op.drop_index(
        op.f("ix_finding_attack_context_analysis_run_id"),
        table_name="finding_attack_context",
    )
    op.drop_table("finding_attack_context")
    op.drop_index(op.f("ix_cve_attack_mapping_vulnerability_id"), table_name="cve_attack_mapping")
    op.drop_index("ix_cve_attack_mapping_technique_id", table_name="cve_attack_mapping")
    op.drop_index("ix_cve_attack_mapping_review_status", table_name="cve_attack_mapping")
    op.drop_index("ix_cve_attack_mapping_cve_id", table_name="cve_attack_mapping")
    op.drop_table("cve_attack_mapping")
    op.drop_index(op.f("ix_attack_technique_technique_id"), table_name="attack_technique")
    op.drop_table("attack_technique")
    op.drop_index(op.f("ix_attack_tactic_tactic_id"), table_name="attack_tactic")
    op.drop_table("attack_tactic")
