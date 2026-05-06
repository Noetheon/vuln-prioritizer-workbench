"""add sessions and audit events for public deployment hardening

Revision ID: 20260506_0011
Revises: 20260505_0010
Create Date: 2026-05-06 10:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260506_0011"
down_revision = "20260505_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auth_session",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("jti_hash", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("jti_hash"),
    )
    op.create_index("ix_auth_session_expires_at", "auth_session", ["expires_at"], unique=False)
    op.create_index("ix_auth_session_revoked_at", "auth_session", ["revoked_at"], unique=False)
    op.create_index("ix_auth_session_user_id", "auth_session", ["user_id"], unique=False)

    op.create_table(
        "audit_event",
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("resource_type", sa.String(length=100), nullable=False),
        sa.Column("resource_id", sa.String(length=100), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("project_id", sa.Uuid(), nullable=True),
        sa.Column("api_token_id", sa.Uuid(), nullable=True),
        sa.Column("detail_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["actor_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["api_token_id"], ["api_token.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_event_action", "audit_event", ["action"], unique=False)
    op.create_index("ix_audit_event_actor_user_id", "audit_event", ["actor_user_id"], unique=False)
    op.create_index("ix_audit_event_api_token_id", "audit_event", ["api_token_id"], unique=False)
    op.create_index("ix_audit_event_created_at", "audit_event", ["created_at"], unique=False)
    op.create_index("ix_audit_event_project_created", "audit_event", ["project_id", "created_at"])
    op.create_index("ix_audit_event_project_id", "audit_event", ["project_id"], unique=False)
    op.create_index("ix_audit_event_resource_id", "audit_event", ["resource_id"], unique=False)
    op.create_index("ix_audit_event_resource_type", "audit_event", ["resource_type"], unique=False)
    op.create_index("ix_audit_event_status", "audit_event", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_audit_event_status", table_name="audit_event")
    op.drop_index("ix_audit_event_resource_type", table_name="audit_event")
    op.drop_index("ix_audit_event_resource_id", table_name="audit_event")
    op.drop_index("ix_audit_event_project_id", table_name="audit_event")
    op.drop_index("ix_audit_event_project_created", table_name="audit_event")
    op.drop_index("ix_audit_event_created_at", table_name="audit_event")
    op.drop_index("ix_audit_event_api_token_id", table_name="audit_event")
    op.drop_index("ix_audit_event_actor_user_id", table_name="audit_event")
    op.drop_index("ix_audit_event_action", table_name="audit_event")
    op.drop_table("audit_event")

    op.drop_index("ix_auth_session_user_id", table_name="auth_session")
    op.drop_index("ix_auth_session_revoked_at", table_name="auth_session")
    op.drop_index("ix_auth_session_expires_at", table_name="auth_session")
    op.drop_table("auth_session")
