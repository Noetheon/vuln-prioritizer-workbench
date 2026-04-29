"""Add governance, detection, and integration tables.

Revision ID: 0005_workbench_integrations
Revises: 0004_workbench_attack_provenance
Create Date: 2026-04-24
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005_workbench_integrations"
down_revision = "0004_workbench_attack_provenance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create additive Workbench tables for the post-v1.0 roadmap."""
    if not _table_exists("waivers"):
        op.create_table(
            "waivers",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("project_id", sa.String(length=32), nullable=False),
            sa.Column("cve_id", sa.String(length=64), nullable=True),
            sa.Column("finding_id", sa.String(length=32), nullable=True),
            sa.Column("asset_id", sa.String(length=200), nullable=True),
            sa.Column("component_name", sa.String(length=300), nullable=True),
            sa.Column("component_version", sa.String(length=200), nullable=True),
            sa.Column("service", sa.String(length=200), nullable=True),
            sa.Column("owner", sa.String(length=200), nullable=False),
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("expires_on", sa.String(length=32), nullable=False),
            sa.Column("review_on", sa.String(length=32), nullable=True),
            sa.Column("approval_ref", sa.String(length=300), nullable=True),
            sa.Column("ticket_url", sa.String(length=1000), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_waivers_project_cve", "waivers", ["project_id", "cve_id"])
        op.create_index("ix_waivers_project_asset", "waivers", ["project_id", "asset_id"])
        op.create_index("ix_waivers_finding", "waivers", ["finding_id"])

    if not _table_exists("detection_controls"):
        op.create_table(
            "detection_controls",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("project_id", sa.String(length=32), nullable=False),
            sa.Column("control_id", sa.String(length=120), nullable=True),
            sa.Column("name", sa.String(length=300), nullable=False),
            sa.Column("technique_id", sa.String(length=64), nullable=False),
            sa.Column("technique_name", sa.String(length=300), nullable=True),
            sa.Column("source_type", sa.String(length=120), nullable=True),
            sa.Column("coverage_level", sa.String(length=40), nullable=False),
            sa.Column("environment", sa.String(length=80), nullable=True),
            sa.Column("owner", sa.String(length=200), nullable=True),
            sa.Column("evidence_ref", sa.String(length=1000), nullable=True),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("last_verified_at", sa.String(length=64), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_detection_controls_project_technique",
            "detection_controls",
            ["project_id", "technique_id"],
        )
        op.create_index(
            "uq_detection_controls_project_identity",
            "detection_controls",
            ["project_id", "control_id", "technique_id"],
            unique=True,
        )

    if not _table_exists("api_tokens"):
        op.create_table(
            "api_tokens",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("name", sa.String(length=200), nullable=False),
            sa.Column("token_hash", sa.String(length=128), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("token_hash"),
        )
        op.create_index("ix_api_tokens_active", "api_tokens", ["revoked_at"])

    if not _table_exists("provider_update_jobs"):
        op.create_table(
            "provider_update_jobs",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("status", sa.String(length=40), nullable=False),
            sa.Column("requested_sources_json", sa.JSON(), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("metadata_json", sa.JSON(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_provider_update_jobs_started_at",
            "provider_update_jobs",
            ["started_at"],
        )

    if not _table_exists("project_config_snapshots"):
        op.create_table(
            "project_config_snapshots",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("project_id", sa.String(length=32), nullable=False),
            sa.Column("source", sa.String(length=80), nullable=False),
            sa.Column("config_json", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_project_config_snapshots_project",
            "project_config_snapshots",
            ["project_id", "created_at"],
        )

    if not _table_exists("github_issue_exports"):
        op.create_table(
            "github_issue_exports",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("project_id", sa.String(length=32), nullable=False),
            sa.Column("finding_id", sa.String(length=32), nullable=True),
            sa.Column("duplicate_key", sa.String(length=300), nullable=False),
            sa.Column("title", sa.String(length=500), nullable=False),
            sa.Column("html_url", sa.String(length=1000), nullable=True),
            sa.Column("issue_number", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "uq_github_issue_exports_project_duplicate",
            "github_issue_exports",
            ["project_id", "duplicate_key"],
            unique=True,
        )
        op.create_index(
            "ix_github_issue_exports_finding",
            "github_issue_exports",
            ["finding_id"],
        )


def downgrade() -> None:
    """Drop additive roadmap tables."""
    for index_name, table_name in (
        ("ix_github_issue_exports_finding", "github_issue_exports"),
        ("uq_github_issue_exports_project_duplicate", "github_issue_exports"),
        ("ix_project_config_snapshots_project", "project_config_snapshots"),
        ("ix_provider_update_jobs_started_at", "provider_update_jobs"),
        ("ix_api_tokens_active", "api_tokens"),
        ("uq_detection_controls_project_identity", "detection_controls"),
        ("ix_detection_controls_project_technique", "detection_controls"),
        ("ix_waivers_finding", "waivers"),
        ("ix_waivers_project_asset", "waivers"),
        ("ix_waivers_project_cve", "waivers"),
    ):
        if _table_exists(table_name):
            op.drop_index(index_name, table_name=table_name)
    for table_name in (
        "github_issue_exports",
        "project_config_snapshots",
        "provider_update_jobs",
        "api_tokens",
        "detection_controls",
        "waivers",
    ):
        if _table_exists(table_name):
            op.drop_table(table_name)


def _table_exists(table_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table_name in inspector.get_table_names()
