"""add attack stix snapshot catalog

Revision ID: 20260430_0007
Revises: 20260430_0006
Create Date: 2026-04-30 13:40:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op

revision = "20260430_0007"
down_revision = "20260430_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "attack_stix_snapshot",
        sa.Column("attack_version", sqlmodel.sql.sqltypes.AutoString(length=40), nullable=False),
        sa.Column("domain", sqlmodel.sql.sqltypes.AutoString(length=80), nullable=False),
        sa.Column("stix_spec_version", sqlmodel.sql.sqltypes.AutoString(length=40), nullable=True),
        sa.Column("bundle_sha256", sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column("source_path", sqlmodel.sql.sqltypes.AutoString(length=1000), nullable=True),
        sa.Column("object_counts_json", sa.JSON(), nullable=False),
        sa.Column("source_metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("provider_snapshot_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["provider_snapshot_id"], ["provider_snapshot.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("bundle_sha256", name="uq_attack_stix_snapshot_bundle_sha256"),
    )
    op.create_index(
        "ix_attack_stix_snapshot_domain_version",
        "attack_stix_snapshot",
        ["domain", "attack_version"],
        unique=False,
    )
    op.create_index(
        op.f("ix_attack_stix_snapshot_provider_snapshot_id"),
        "attack_stix_snapshot",
        ["provider_snapshot_id"],
        unique=False,
    )

    op.create_table(
        "attack_stix_tactic",
        sa.Column("stix_id", sqlmodel.sql.sqltypes.AutoString(length=120), nullable=False),
        sa.Column("tactic_id", sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False),
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(length=200), nullable=False),
        sa.Column("short_name", sqlmodel.sql.sqltypes.AutoString(length=120), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("url", sqlmodel.sql.sqltypes.AutoString(length=500), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("deprecated", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["snapshot_id"], ["attack_stix_snapshot.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "snapshot_id", "tactic_id", name="uq_attack_stix_tactic_snapshot_tactic"
        ),
    )
    op.create_index("ix_attack_stix_tactic_tactic_id", "attack_stix_tactic", ["tactic_id"])
    op.create_index(
        op.f("ix_attack_stix_tactic_snapshot_id"), "attack_stix_tactic", ["snapshot_id"]
    )

    op.create_table(
        "attack_stix_technique",
        sa.Column("stix_id", sqlmodel.sql.sqltypes.AutoString(length=120), nullable=False),
        sa.Column("technique_id", sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False),
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(length=300), nullable=False),
        sa.Column("tactic_ids_json", sa.JSON(), nullable=False),
        sa.Column("tactic_short_names_json", sa.JSON(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("url", sqlmodel.sql.sqltypes.AutoString(length=500), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("deprecated", sa.Boolean(), nullable=False),
        sa.Column("is_subtechnique", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["snapshot_id"], ["attack_stix_snapshot.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "snapshot_id",
            "technique_id",
            name="uq_attack_stix_technique_snapshot_technique",
        ),
    )
    op.create_index(
        "ix_attack_stix_technique_technique_id",
        "attack_stix_technique",
        ["technique_id"],
    )
    op.create_index(
        op.f("ix_attack_stix_technique_snapshot_id"),
        "attack_stix_technique",
        ["snapshot_id"],
    )

    op.create_table(
        "attack_stix_mitigation",
        sa.Column("stix_id", sqlmodel.sql.sqltypes.AutoString(length=120), nullable=False),
        sa.Column("mitigation_id", sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False),
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(length=300), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("url", sqlmodel.sql.sqltypes.AutoString(length=500), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("deprecated", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["snapshot_id"], ["attack_stix_snapshot.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "snapshot_id",
            "mitigation_id",
            name="uq_attack_stix_mitigation_snapshot_mitigation",
        ),
    )
    op.create_index(
        "ix_attack_stix_mitigation_mitigation_id",
        "attack_stix_mitigation",
        ["mitigation_id"],
    )
    op.create_index(
        op.f("ix_attack_stix_mitigation_snapshot_id"),
        "attack_stix_mitigation",
        ["snapshot_id"],
    )

    op.create_table(
        "attack_stix_technique_mitigation",
        sa.Column("relationship_id", sqlmodel.sql.sqltypes.AutoString(length=120), nullable=False),
        sa.Column("technique_id", sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False),
        sa.Column("mitigation_id", sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["snapshot_id"], ["attack_stix_snapshot.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "snapshot_id",
            "technique_id",
            "mitigation_id",
            "relationship_id",
            name="uq_attack_stix_technique_mitigation_snapshot_relationship",
        ),
    )
    op.create_index(
        "ix_attack_stix_technique_mitigation_technique",
        "attack_stix_technique_mitigation",
        ["snapshot_id", "technique_id"],
    )
    op.create_index(
        op.f("ix_attack_stix_technique_mitigation_snapshot_id"),
        "attack_stix_technique_mitigation",
        ["snapshot_id"],
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_attack_stix_technique_mitigation_snapshot_id"),
        table_name="attack_stix_technique_mitigation",
    )
    op.drop_index(
        "ix_attack_stix_technique_mitigation_technique",
        table_name="attack_stix_technique_mitigation",
    )
    op.drop_table("attack_stix_technique_mitigation")
    op.drop_index(
        op.f("ix_attack_stix_mitigation_snapshot_id"),
        table_name="attack_stix_mitigation",
    )
    op.drop_index("ix_attack_stix_mitigation_mitigation_id", table_name="attack_stix_mitigation")
    op.drop_table("attack_stix_mitigation")
    op.drop_index(
        op.f("ix_attack_stix_technique_snapshot_id"),
        table_name="attack_stix_technique",
    )
    op.drop_index("ix_attack_stix_technique_technique_id", table_name="attack_stix_technique")
    op.drop_table("attack_stix_technique")
    op.drop_index(op.f("ix_attack_stix_tactic_snapshot_id"), table_name="attack_stix_tactic")
    op.drop_index("ix_attack_stix_tactic_tactic_id", table_name="attack_stix_tactic")
    op.drop_table("attack_stix_tactic")
    op.drop_index(
        op.f("ix_attack_stix_snapshot_provider_snapshot_id"),
        table_name="attack_stix_snapshot",
    )
    op.drop_index("ix_attack_stix_snapshot_domain_version", table_name="attack_stix_snapshot")
    op.drop_table("attack_stix_snapshot")
