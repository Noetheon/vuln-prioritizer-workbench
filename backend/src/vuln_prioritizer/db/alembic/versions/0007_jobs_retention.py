"""Add durable Workbench jobs, artifact retention, and detection evidence.

Revision ID: 0007_jobs_retention
Revises: 0006_workbench_lifecycle_audit
Create Date: 2026-04-25
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007_jobs_retention"
down_revision = "0006_workbench_lifecycle_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create additive P1 Workbench operation tables."""
    if not _column_exists("detection_controls", "evidence_refs_json"):
        op.add_column(
            "detection_controls",
            sa.Column("evidence_refs_json", sa.JSON(), nullable=False, server_default="[]"),
        )
    if not _column_exists("detection_controls", "review_status"):
        op.add_column(
            "detection_controls",
            sa.Column(
                "review_status",
                sa.String(length=80),
                nullable=False,
                server_default="unreviewed",
            ),
        )

    if not _table_exists("detection_control_history"):
        op.create_table(
            "detection_control_history",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("project_id", sa.String(length=32), nullable=False),
            sa.Column("control_id", sa.String(length=32), nullable=False),
            sa.Column("event_type", sa.String(length=80), nullable=False),
            sa.Column("actor", sa.String(length=200), nullable=True),
            sa.Column("reason", sa.Text(), nullable=True),
            sa.Column("previous_json", sa.JSON(), nullable=False),
            sa.Column("current_json", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["control_id"], ["detection_controls.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_detection_control_history_control",
            "detection_control_history",
            ["control_id", "created_at"],
        )
        op.create_index(
            "ix_detection_control_history_project",
            "detection_control_history",
            ["project_id", "created_at"],
        )

    if not _table_exists("detection_control_attachments"):
        op.create_table(
            "detection_control_attachments",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("project_id", sa.String(length=32), nullable=False),
            sa.Column("control_id", sa.String(length=32), nullable=False),
            sa.Column("filename", sa.String(length=500), nullable=False),
            sa.Column("content_type", sa.String(length=200), nullable=True),
            sa.Column("path", sa.String(length=1000), nullable=False),
            sa.Column("sha256", sa.String(length=64), nullable=False),
            sa.Column("size_bytes", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["control_id"], ["detection_controls.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_detection_control_attachments_control",
            "detection_control_attachments",
            ["control_id", "created_at"],
        )
        op.create_index(
            "ix_detection_control_attachments_project",
            "detection_control_attachments",
            ["project_id", "created_at"],
        )

    if not _table_exists("workbench_jobs"):
        op.create_table(
            "workbench_jobs",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("project_id", sa.String(length=32), nullable=True),
            sa.Column("kind", sa.String(length=80), nullable=False),
            sa.Column("status", sa.String(length=40), nullable=False),
            sa.Column("target_type", sa.String(length=120), nullable=True),
            sa.Column("target_id", sa.String(length=120), nullable=True),
            sa.Column("progress", sa.Integer(), nullable=False),
            sa.Column("attempts", sa.Integer(), nullable=False),
            sa.Column("max_attempts", sa.Integer(), nullable=False),
            sa.Column("priority", sa.Integer(), nullable=False),
            sa.Column("idempotency_key", sa.String(length=200), nullable=True),
            sa.Column("payload_json", sa.JSON(), nullable=False),
            sa.Column("result_json", sa.JSON(), nullable=False),
            sa.Column("logs_json", sa.JSON(), nullable=False),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("queued_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("lease_owner", sa.String(length=200), nullable=True),
            sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("idempotency_key"),
        )
        op.create_index(
            "ix_workbench_jobs_status_priority",
            "workbench_jobs",
            ["status", "priority", "queued_at"],
        )
        op.create_index(
            "ix_workbench_jobs_project_created",
            "workbench_jobs",
            ["project_id", "created_at"],
        )
        op.create_index("ix_workbench_jobs_target", "workbench_jobs", ["target_type", "target_id"])
        op.create_index("ix_workbench_jobs_lease", "workbench_jobs", ["lease_expires_at"])

    if not _table_exists("project_artifact_retention"):
        op.create_table(
            "project_artifact_retention",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("project_id", sa.String(length=32), nullable=False),
            sa.Column("report_retention_days", sa.Integer(), nullable=True),
            sa.Column("evidence_retention_days", sa.Integer(), nullable=True),
            sa.Column("max_disk_usage_mb", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("project_id"),
        )
        op.create_index(
            "ix_project_artifact_retention_project",
            "project_artifact_retention",
            ["project_id"],
        )


def downgrade() -> None:
    """Drop additive P1 Workbench operation tables."""
    for index_name, table_name in (
        ("ix_project_artifact_retention_project", "project_artifact_retention"),
        ("ix_workbench_jobs_lease", "workbench_jobs"),
        ("ix_workbench_jobs_target", "workbench_jobs"),
        ("ix_workbench_jobs_project_created", "workbench_jobs"),
        ("ix_workbench_jobs_status_priority", "workbench_jobs"),
        ("ix_detection_control_attachments_project", "detection_control_attachments"),
        ("ix_detection_control_attachments_control", "detection_control_attachments"),
        ("ix_detection_control_history_project", "detection_control_history"),
        ("ix_detection_control_history_control", "detection_control_history"),
    ):
        if _table_exists(table_name):
            op.drop_index(index_name, table_name=table_name)
    for table_name in (
        "project_artifact_retention",
        "workbench_jobs",
        "detection_control_attachments",
        "detection_control_history",
    ):
        if _table_exists(table_name):
            op.drop_table(table_name)
    for column_name in ("review_status", "evidence_refs_json"):
        if _column_exists("detection_controls", column_name):
            op.drop_column("detection_controls", column_name)


def _table_exists(table_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table_name in inspector.get_table_names()


def _column_exists(table_name: str, column_name: str) -> bool:
    if not _table_exists(table_name):
        return False
    inspector = sa.inspect(op.get_bind())
    return column_name in {column["name"] for column in inspector.get_columns(table_name)}
