"""Share repeated immutable evidence sections without changing historical contracts."""

from __future__ import annotations

import uuid
from collections import defaultdict

import sqlalchemy as sa
from alembic import op

from app.decision_core.ledger import canonical_payload_sha256
from app.repositories.evidence_payloads import EvidencePayloadStore

revision = "20260923_0014"
down_revision = "20260923_0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Atomically encode historical rows, retaining their exact JSON semantics."""
    connection = op.get_bind()
    connection.execute(sa.text("UPDATE finding_decision_evidence SET id = id WHERE 1 = 0"))
    op.create_table(
        "evidence_section",
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("decoded_size", sa.Integer(), nullable=False),
        sa.Column("payload_zlib", sa.LargeBinary(), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("project_id", "sha256"),
    )
    _rewrite(encode=True)


def _rewrite(*, encode: bool) -> None:
    connection = op.get_bind()
    evidence = sa.Table(
        "finding_decision_evidence", sa.MetaData(), autoload_with=connection, resolve_fks=False
    )
    store = EvidencePayloadStore(connection)
    after = None
    while True:
        statement = (
            sa.select(evidence.c.id, evidence.c.project_id, evidence.c.payload_json)
            .order_by(evidence.c.id)
            .limit(100)
        )
        if after is not None:
            statement = statement.where(evidence.c.id > after)
        rows = connection.execute(statement).mappings().all()
        if not rows:
            break
        batch = []
        if encode:
            projects = defaultdict(list)
            for row in rows:
                projects[uuid.UUID(str(row["project_id"]))].append(row)
            for project_id, project_rows in projects.items():
                payloads = [row["payload_json"] for row in project_rows]
                encoded = store.store_payloads(project_id, payloads)
                # Check exact reconstruction before changing the historical row.
                decoded = store.load_documents([(project_id, item) for item in encoded])
                for row, document, payload in zip(project_rows, encoded, decoded, strict=True):
                    if canonical_payload_sha256(payload) != canonical_payload_sha256(
                        row["payload_json"]
                    ):
                        raise RuntimeError("Evidence migration changed a historical payload.")
                    batch.append({"row_id": row["id"], "payload": document})
        else:
            payloads = store.load_documents(
                [(uuid.UUID(str(row["project_id"])), row["payload_json"]) for row in rows]
            )
            batch = [
                {"row_id": row["id"], "payload": payload}
                for row, payload in zip(rows, payloads, strict=True)
            ]
        connection.execute(
            evidence.update()
            .where(evidence.c.id == sa.bindparam("row_id"))
            .values(payload_json=sa.bindparam("payload")),
            batch,
        )
        after = rows[-1]["id"]


def downgrade() -> None:
    """Recreate standalone v2 JSON before removing the shared section store."""
    connection = op.get_bind()
    connection.execute(sa.text("UPDATE finding_decision_evidence SET id = id WHERE 1 = 0"))
    _rewrite(encode=False)
    op.drop_table("evidence_section")
