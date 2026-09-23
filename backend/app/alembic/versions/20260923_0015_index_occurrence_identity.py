"""Index the immutable identity subset used by import collision checks."""

from alembic import op
from sqlalchemy import JSON, Column, Index, MetaData, Table, Uuid

from app.models.occurrence_identity import (
    OCCURRENCE_IDENTITY_INDEX,
    occurrence_identity_expressions,
)

revision = "20260923_0015"
down_revision = "20260923_0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Cover distinct identity reads without rewriting historical observations."""
    table = Table(
        "finding_occurrence",
        MetaData(),
        Column("finding_id", Uuid()),
        Column("evidence_json", JSON()),
    )
    Index(
        OCCURRENCE_IDENTITY_INDEX,
        table.c.finding_id,
        *occurrence_identity_expressions(table.c.evidence_json),
    ).create(op.get_bind())


def downgrade() -> None:
    """Remove only the derived index."""
    op.drop_index(OCCURRENCE_IDENTITY_INDEX, table_name="finding_occurrence")
