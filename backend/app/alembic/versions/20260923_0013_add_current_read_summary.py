"""Backfill compact list and dashboard display fields from recorded evidence."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from app.decision_core.read_summary import read_summary_from_payload

revision = "20260923_0013"
down_revision = "20260923_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Populate bounded read summaries without changing historical payloads."""
    # SQLite must enter a write transaction before DDL so a failed backfill
    # rolls the new column back together with the Alembic revision.
    connection = op.get_bind()
    connection.execute(
        sa.text("UPDATE finding_current_projection SET finding_id = finding_id WHERE 1 = 0")
    )
    op.add_column(
        "finding_current_projection",
        sa.Column("read_summary_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )
    metadata = sa.MetaData()
    projection = sa.Table(
        "finding_current_projection", metadata, autoload_with=connection, resolve_fks=False
    )
    evidence = sa.Table(
        "finding_decision_evidence", metadata, autoload_with=connection, resolve_fks=False
    )
    after = None
    while True:
        statement = (
            sa.select(
                projection.c.finding_id,
                projection.c.lifecycle_overlay_json,
                evidence.c.payload_json,
            )
            .select_from(
                projection.outerjoin(
                    evidence, projection.c.source_finding_evidence_id == evidence.c.id
                )
            )
            .order_by(projection.c.finding_id)
            .limit(250)
        )
        if after is not None:
            statement = statement.where(projection.c.finding_id > after)
        rows = connection.execute(statement).mappings().all()
        if not rows:
            break
        batch = []
        for row in rows:
            if row["payload_json"] is None:
                raise RuntimeError("A current projection is missing its immutable decision source.")
            payload = dict(row["payload_json"]) | dict(row["lifecycle_overlay_json"] or {})
            batch.append(
                {"row_id": row["finding_id"], "summary": read_summary_from_payload(payload)}
            )
        connection.execute(
            projection.update()
            .where(projection.c.finding_id == sa.bindparam("row_id"))
            .values(read_summary_json=sa.bindparam("summary")),
            batch,
        )
        after = rows[-1]["finding_id"]


def downgrade() -> None:
    """Remove only compact display fields; retain current and historical decisions."""
    op.drop_column("finding_current_projection", "read_summary_json")
