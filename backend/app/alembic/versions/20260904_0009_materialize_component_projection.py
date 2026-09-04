"""
Materialize evidence-bound component fields for project finding queries.

Revision ID: 20260904_0009
Revises: 20260904_0008
Create Date: 2026-09-04 03:00:00.000000
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op
from packageurl import PackageURL

revision = "20260904_0009"
down_revision = "20260904_0008"
branch_labels = None
depends_on = None

_PROJECTION_SCHEMA_V1 = "finding-current-projection.v1"
_PROJECTION_SCHEMA_V2 = "finding-current-projection.v2"
_COMPONENT_INDEX = "ix_finding_current_projection_project_component"
_COMPONENT_COLUMNS = (
    ("component_name", 300),
    ("component_version", 200),
    ("component_purl", 1000),
    ("component_package_type", 120),
    ("component_ecosystem", 120),
)


def upgrade() -> None:
    """Backfill query fields exclusively from each projection's immutable evidence."""
    _start_portable_write_transaction()
    for column_name, length in _COMPONENT_COLUMNS:
        op.add_column(
            "finding_current_projection",
            sa.Column(
                column_name,
                sqlmodel.sql.sqltypes.AutoString(length=length),
                nullable=True,
            ),
        )
    _backfill_component_fields()
    op.create_index(
        _COMPONENT_INDEX,
        "finding_current_projection",
        ["project_id", "component_name", "component_version"],
        unique=False,
    )


def downgrade() -> None:
    """Remove evidence-bound component query fields."""
    _start_portable_write_transaction()
    connection = op.get_bind()
    projection = _projection_table(connection)
    connection.execute(sa.update(projection).values(schema_version=_PROJECTION_SCHEMA_V1))
    op.drop_index(_COMPONENT_INDEX, table_name="finding_current_projection")
    for column_name, _length in reversed(_COMPONENT_COLUMNS):
        op.drop_column("finding_current_projection", column_name)


def _backfill_component_fields() -> None:
    connection = op.get_bind()
    metadata = sa.MetaData()
    projection = sa.Table(
        "finding_current_projection",
        metadata,
        autoload_with=connection,
        resolve_fks=False,
    )
    evidence = sa.Table(
        "finding_decision_evidence",
        metadata,
        autoload_with=connection,
        resolve_fks=False,
    )
    rows = connection.execute(
        sa.select(
            projection.c.finding_id,
            projection.c.source_finding_evidence_id,
            projection.c.lifecycle_overlay_json,
            evidence.c.payload_json,
        )
        .select_from(
            projection.outerjoin(
                evidence,
                projection.c.source_finding_evidence_id == evidence.c.id,
            )
        )
        .order_by(projection.c.finding_id)
    ).mappings()
    update_statement = (
        sa.update(projection)
        .where(projection.c.finding_id == sa.bindparam("_finding_id"))
        .values(
            schema_version=sa.bindparam("_schema_version"),
            component_name=sa.bindparam("_component_name"),
            component_version=sa.bindparam("_component_version"),
            component_purl=sa.bindparam("_component_purl"),
            component_package_type=sa.bindparam("_component_package_type"),
            component_ecosystem=sa.bindparam("_component_ecosystem"),
        )
    )
    batch: list[dict[str, Any]] = []
    for row in rows:
        if row["source_finding_evidence_id"] is None or row["payload_json"] is None:
            raise RuntimeError(
                "Every current projection must retain immutable source evidence before "
                "component fields can be materialized."
            )
        payload = dict(_mapping(row["payload_json"]))
        payload.update(_mapping(row["lifecycle_overlay_json"]))
        component = _component_projection(payload)
        batch.append(
            {
                "_finding_id": row["finding_id"],
                "_schema_version": _PROJECTION_SCHEMA_V2,
                "_component_name": component["name"],
                "_component_version": component["version"],
                "_component_purl": component["purl"],
                "_component_package_type": component["package_type"],
                "_component_ecosystem": component["ecosystem"],
            }
        )
        if len(batch) >= 500:
            connection.execute(update_statement, batch)
            batch.clear()
    if batch:
        connection.execute(update_statement, batch)


def _component_projection(payload: Mapping[str, Any]) -> dict[str, str | None]:
    scope = _mapping(payload.get("occurrence_scope"))
    occurrences = payload.get("occurrences")
    occurrence_rows = occurrences if isinstance(occurrences, list) else []
    purl = _clean_text(scope.get("purl")) or _single_occurrence_text(
        occurrence_rows,
        "purl",
    )
    parsed_purl = _parse_purl(purl)
    package_type = (
        _clean_text(scope.get("package_type"))
        or _single_occurrence_text(occurrence_rows, "package_type")
        or _purl_text(parsed_purl, "type")
    )
    return {
        "name": (
            _clean_text(scope.get("component_name"))
            or _single_occurrence_text(occurrence_rows, "component_name")
            or _purl_text(parsed_purl, "name")
        ),
        "version": (
            _clean_text(scope.get("component_version"))
            or _single_occurrence_text(occurrence_rows, "component_version")
            or _purl_text(parsed_purl, "version")
        ),
        "purl": purl,
        "package_type": package_type,
        "ecosystem": package_type,
    }


def _single_occurrence_text(rows: list[Any], field_name: str) -> str | None:
    values = {
        value
        for row in rows
        if isinstance(row, Mapping) and (value := _clean_text(row.get(field_name))) is not None
    }
    return next(iter(values)) if len(values) == 1 else None


def _parse_purl(purl: str | None) -> PackageURL | None:
    if purl is None:
        return None
    try:
        return PackageURL.from_string(purl)
    except ValueError:
        return None


def _purl_text(parsed: PackageURL | None, field_name: str) -> str | None:
    return _clean_text(getattr(parsed, field_name, None))


def _clean_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _start_portable_write_transaction() -> None:
    """Start SQLite's transaction before additive DDL and data changes."""
    connection = op.get_bind()
    projection = _projection_table(connection)
    connection.execute(
        sa.update(projection).where(sa.false()).values(finding_id=projection.c.finding_id)
    )


def _projection_table(connection: Any) -> sa.Table:
    return sa.Table(
        "finding_current_projection",
        sa.MetaData(),
        autoload_with=connection,
        resolve_fks=False,
    )
