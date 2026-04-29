"""add core workbench domain tables

Revision ID: 20260428_0002
Revises: 20260428_0001
Create Date: 2026-04-28 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op

revision = "20260428_0002"
down_revision = "20260428_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "asset",
        sa.Column("asset_key", sqlmodel.sql.sqltypes.AutoString(length=200), nullable=False),
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(length=300), nullable=False),
        sa.Column("target_ref", sqlmodel.sql.sqltypes.AutoString(length=500), nullable=True),
        sa.Column("owner", sqlmodel.sql.sqltypes.AutoString(length=200), nullable=True),
        sa.Column("business_service", sqlmodel.sql.sqltypes.AutoString(length=200), nullable=True),
        sa.Column("environment", sa.String(length=80), nullable=False),
        sa.Column("exposure", sa.String(length=80), nullable=False),
        sa.Column("criticality", sa.String(length=80), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "asset_key", name="uq_asset_project_asset_key"),
    )
    op.create_index(
        "ix_asset_project_criticality", "asset", ["project_id", "criticality"], unique=False
    )
    op.create_index(
        "ix_asset_project_environment", "asset", ["project_id", "environment"], unique=False
    )
    op.create_index("ix_asset_project_exposure", "asset", ["project_id", "exposure"], unique=False)
    op.create_index(op.f("ix_asset_project_id"), "asset", ["project_id"], unique=False)
    op.create_table(
        "component",
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(length=300), nullable=False),
        sa.Column("version", sqlmodel.sql.sqltypes.AutoString(length=200), nullable=True),
        sa.Column("purl", sqlmodel.sql.sqltypes.AutoString(length=1000), nullable=True),
        sa.Column("ecosystem", sqlmodel.sql.sqltypes.AutoString(length=120), nullable=True),
        sa.Column("package_type", sqlmodel.sql.sqltypes.AutoString(length=120), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", "version", "ecosystem", name="uq_component_identity"),
        sa.UniqueConstraint("purl", name="uq_component_purl"),
    )
    op.create_table(
        "vulnerability",
        sa.Column("source_id", sqlmodel.sql.sqltypes.AutoString(length=120), nullable=True),
        sa.Column("title", sqlmodel.sql.sqltypes.AutoString(length=500), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sqlmodel.sql.sqltypes.AutoString(length=300), nullable=True),
        sa.Column("severity", sqlmodel.sql.sqltypes.AutoString(length=40), nullable=True),
        sa.Column("cwe", sqlmodel.sql.sqltypes.AutoString(length=200), nullable=True),
        sa.Column("published_at", sqlmodel.sql.sqltypes.AutoString(length=64), nullable=True),
        sa.Column("modified_at", sqlmodel.sql.sqltypes.AutoString(length=64), nullable=True),
        sa.Column("provider_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("cve_id", sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_vulnerability_cve_id"), "vulnerability", ["cve_id"], unique=True)
    op.create_table(
        "finding",
        sa.Column("cve_id", sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column("dedup_key", sqlmodel.sql.sqltypes.AutoString(length=512), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("priority", sa.String(length=40), nullable=False),
        sa.Column("priority_rank", sa.Integer(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("operational_rank", sa.Integer(), nullable=False),
        sa.Column("in_kev", sa.Boolean(), nullable=False),
        sa.Column("epss", sa.Float(), nullable=True),
        sa.Column("cvss_base_score", sa.Float(), nullable=True),
        sa.Column("attack_mapped", sa.Boolean(), nullable=False),
        sa.Column("suppressed_by_vex", sa.Boolean(), nullable=False),
        sa.Column("under_investigation", sa.Boolean(), nullable=False),
        sa.Column("waived", sa.Boolean(), nullable=False),
        sa.Column("recommended_action", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("rationale", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("explanation_json", sa.JSON(), nullable=False),
        sa.Column("data_quality_json", sa.JSON(), nullable=False),
        sa.Column("evidence_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("vulnerability_id", sa.Uuid(), nullable=False),
        sa.Column("component_id", sa.Uuid(), nullable=True),
        sa.Column("asset_id", sa.Uuid(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["asset.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["component_id"], ["component.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["vulnerability_id"], ["vulnerability.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "dedup_key", name="uq_finding_project_dedup_key"),
        sa.UniqueConstraint(
            "project_id",
            "vulnerability_id",
            "component_id",
            "asset_id",
            name="uq_finding_project_vulnerability_component_asset",
        ),
    )
    op.create_index(op.f("ix_finding_asset_id"), "finding", ["asset_id"], unique=False)
    op.create_index("ix_finding_cve_id", "finding", ["cve_id"], unique=False)
    op.create_index(op.f("ix_finding_component_id"), "finding", ["component_id"], unique=False)
    op.create_index("ix_finding_project_asset", "finding", ["project_id", "asset_id"], unique=False)
    op.create_index(op.f("ix_finding_project_id"), "finding", ["project_id"], unique=False)
    op.create_index(
        "ix_finding_project_priority", "finding", ["project_id", "priority_rank"], unique=False
    )
    op.create_index("ix_finding_project_status", "finding", ["project_id", "status"], unique=False)
    op.create_index(
        "ix_finding_project_vulnerability",
        "finding",
        ["project_id", "vulnerability_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_vulnerability_id"), "finding", ["vulnerability_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_finding_vulnerability_id"), table_name="finding")
    op.drop_index("ix_finding_project_vulnerability", table_name="finding")
    op.drop_index("ix_finding_project_status", table_name="finding")
    op.drop_index("ix_finding_project_priority", table_name="finding")
    op.drop_index(op.f("ix_finding_project_id"), table_name="finding")
    op.drop_index("ix_finding_project_asset", table_name="finding")
    op.drop_index(op.f("ix_finding_component_id"), table_name="finding")
    op.drop_index("ix_finding_cve_id", table_name="finding")
    op.drop_index(op.f("ix_finding_asset_id"), table_name="finding")
    op.drop_table("finding")
    op.drop_index(op.f("ix_vulnerability_cve_id"), table_name="vulnerability")
    op.drop_table("vulnerability")
    op.drop_table("component")
    op.drop_index(op.f("ix_asset_project_id"), table_name="asset")
    op.drop_index("ix_asset_project_exposure", table_name="asset")
    op.drop_index("ix_asset_project_environment", table_name="asset")
    op.drop_index("ix_asset_project_criticality", table_name="asset")
    op.drop_table("asset")
