"""
Add the materialized current side of the Decision Ledger.

Revision ID: 20260710_0004
Revises: 20260612_0003
Create Date: 2026-07-10 00:00:00.000000
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op

revision = "20260710_0004"
down_revision = "20260612_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create and backfill one current projection row per finding."""
    op.create_table(
        "finding_current_projection",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("source_analysis_run_id", sa.Uuid(), nullable=True),
        sa.Column("source_finding_evidence_id", sa.Uuid(), nullable=True),
        sa.Column("source_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "schema_version",
            sqlmodel.sql.sqltypes.AutoString(length=80),
            nullable=False,
        ),
        sa.Column("cve_id", sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column("dedup_key", sqlmodel.sql.sqltypes.AutoString(length=512), nullable=False),
        sa.Column("priority", sqlmodel.sql.sqltypes.AutoString(length=40), nullable=False),
        sa.Column("status", sqlmodel.sql.sqltypes.AutoString(length=40), nullable=False),
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
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("recommended_action", sa.Text(), nullable=True),
        sa.Column("lifecycle_overlay_json", sa.JSON(), nullable=False),
        sa.Column(
            "source_payload_sha256",
            sqlmodel.sql.sqltypes.AutoString(length=64),
            nullable=False,
        ),
        sa.Column(
            "projection_payload_sha256",
            sqlmodel.sql.sqltypes.AutoString(length=64),
            nullable=False,
        ),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("lifecycle_revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["source_analysis_run_id"],
            ["analysis_run.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["source_finding_evidence_id"],
            ["finding_decision_evidence.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("finding_id"),
    )
    op.create_index(
        op.f("ix_finding_current_projection_project_id"),
        "finding_current_projection",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_current_projection_source_analysis_run_id"),
        "finding_current_projection",
        ["source_analysis_run_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_current_projection_source_finding_evidence_id"),
        "finding_current_projection",
        ["source_finding_evidence_id"],
        unique=False,
    )
    for name, columns in (
        (
            "ix_finding_current_projection_project_operational",
            ["project_id", "operational_rank", "priority_rank"],
        ),
        ("ix_finding_current_projection_project_priority", ["project_id", "priority_rank"]),
        ("ix_finding_current_projection_project_status", ["project_id", "status"]),
        ("ix_finding_current_projection_project_kev", ["project_id", "in_kev"]),
        ("ix_finding_current_projection_project_epss", ["project_id", "epss"]),
        ("ix_finding_current_projection_project_cvss", ["project_id", "cvss_base_score"]),
        ("ix_finding_current_projection_project_risk", ["project_id", "risk_score"]),
    ):
        op.create_index(name, "finding_current_projection", columns, unique=False)

    _backfill_current_projection()


def downgrade() -> None:
    """Drop the materialized current projection."""
    op.drop_table("finding_current_projection")


def _backfill_current_projection() -> None:
    bind = op.get_bind()
    metadata = sa.MetaData()
    evidence = sa.Table(
        "finding_decision_evidence",
        metadata,
        autoload_with=bind,
        resolve_fks=False,
    )
    projection = sa.Table(
        "finding_current_projection",
        metadata,
        autoload_with=bind,
        resolve_fks=False,
    )
    rows = bind.execute(
        sa.select(evidence).order_by(
            evidence.c.finding_id,
            evidence.c.created_at.desc(),
            evidence.c.id.desc(),
        )
    ).mappings()
    seen: set[Any] = set()
    batch: list[dict[str, Any]] = []
    for row in rows:
        finding_id = row["finding_id"]
        if finding_id in seen:
            continue
        seen.add(finding_id)
        payload = dict(row["payload_json"] or {})
        payload_hash = _payload_sha256(payload)
        batch.append(
            {
                "finding_id": finding_id,
                "project_id": row["project_id"],
                "source_analysis_run_id": row["analysis_run_id"],
                "source_finding_evidence_id": row["id"],
                "source_created_at": row["created_at"],
                "schema_version": "finding-current-projection.v1",
                "cve_id": payload.get("cve_id") or row["cve_id"],
                "dedup_key": payload.get("dedup_key") or row["dedup_key"],
                "priority": payload.get("priority") or row["priority"],
                "status": payload.get("status") or row["status"],
                "priority_rank": int(payload.get("priority_rank", 99)),
                "risk_score": payload.get("risk_score"),
                "operational_rank": int(payload.get("operational_rank", 0)),
                "in_kev": bool(payload.get("in_kev", False)),
                "epss": payload.get("epss"),
                "cvss_base_score": payload.get("cvss_base_score"),
                "attack_mapped": bool(payload.get("attack_mapped", False)),
                "suppressed_by_vex": bool(payload.get("suppressed_by_vex", False)),
                "under_investigation": bool(payload.get("under_investigation", False)),
                "waived": bool(payload.get("waived", False)),
                "rationale": payload.get("rationale"),
                "recommended_action": payload.get("recommended_action"),
                "lifecycle_overlay_json": {},
                "source_payload_sha256": payload_hash,
                "projection_payload_sha256": payload_hash,
                "revision": 1,
                "lifecycle_revision": 0,
                "created_at": row["created_at"],
                "updated_at": row["created_at"],
            }
        )
        if len(batch) >= 500:
            bind.execute(projection.insert(), batch)
            batch.clear()
    if batch:
        bind.execute(projection.insert(), batch)


def _payload_sha256(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
