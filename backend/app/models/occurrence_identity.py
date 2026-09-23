"""Shared SQL expressions for the occurrence identity covering index."""

from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, Text, bindparam, cast
from sqlalchemy.sql.elements import ColumnElement

OCCURRENCE_IDENTITY_FIELDS = ("asset_id", "target_kind", "target_ref")
OCCURRENCE_IDENTITY_INDEX = "ix_finding_occurrence_identity"


def occurrence_identity_expressions(column: Any) -> tuple[ColumnElement[str], ...]:
    """
    Keep JSON types intact and match the indexed expressions on SQLite/Postgres.

    Only these fixed schema keys are rendered as literals. Parameterized JSON
    paths prevent SQLite from recognizing its expression index during reads.
    """
    return tuple(
        cast(
            column[
                bindparam(
                    f"identity_{name}",
                    name,
                    type_=JSON.JSONStrIndexType(),
                    literal_execute=True,
                )
            ],
            Text,
        )
        for name in OCCURRENCE_IDENTITY_FIELDS
    )
