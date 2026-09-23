"""Separate current queue ordering from immutable decision evidence."""

import sqlalchemy as sa
from alembic import op

from app.decision_core.current_queue import with_current_rank
from app.decision_core.ledger import canonical_payload_sha256

revision = "20260923_0011"
down_revision = "20260906_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add disposable sort keys without rewriting historical decisions."""
    # NULL keys are hydrated once by the queue owner. This keeps migration memory
    # bounded and leaves immutable historical payloads and their hashes untouched.
    op.add_column(
        "finding_current_projection",
        sa.Column("operational_sort_key_json", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    """Restore current ranks in legacy overlays before removing the compact keys."""
    connection = op.get_bind()
    # Begin a SQLite write transaction before DDL; failed conversion must leave
    # both the old schema revision and its queue representation intact.
    connection.execute(
        sa.text("UPDATE finding_current_projection SET finding_id = finding_id WHERE 1 = 0")
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
                projection.c.operational_rank,
                projection.c.lifecycle_overlay_json,
                evidence.c.payload_json,
            )
            .select_from(
                projection.outerjoin(
                    evidence, projection.c.source_finding_evidence_id == evidence.c.id
                )
            )
            .order_by(projection.c.finding_id)
            .limit(100)
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
            source = dict(row["payload_json"])
            current = source | dict(row["lifecycle_overlay_json"] or {})
            restored = with_current_rank(current, row["operational_rank"])
            if restored == current:
                continue
            batch.append(
                {
                    "row_id": row["finding_id"],
                    "overlay": {
                        key: value
                        for key, value in restored.items()
                        if key not in source or source[key] != value
                    },
                    "payload_hash": canonical_payload_sha256(restored),
                }
            )
        if batch:
            connection.execute(
                projection.update()
                .where(projection.c.finding_id == sa.bindparam("row_id"))
                .values(
                    lifecycle_overlay_json=sa.bindparam("overlay"),
                    projection_payload_sha256=sa.bindparam("payload_hash"),
                    lifecycle_revision=projection.c.lifecycle_revision + 1,
                    revision=projection.c.revision + 1,
                ),
                batch,
            )
        after = rows[-1]["finding_id"]
    op.drop_column("finding_current_projection", "operational_sort_key_json")
