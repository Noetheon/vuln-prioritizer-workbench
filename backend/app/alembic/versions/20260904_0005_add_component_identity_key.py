"""
Add indexed canonical component identities and normalize legacy asset keys.

Revision ID: 20260904_0005
Revises: 20260710_0004
Create Date: 2026-09-04 00:00:00.000000
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Mapping
from typing import Any

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op
from packageurl import PackageURL

revision = "20260904_0005"
down_revision = "20260710_0004"
branch_labels = None
depends_on = None

_COMPONENT_IDENTITY_PREFIX = "component-identity-v1:"
_COMPONENT_STORAGE_KEY_PREFIX = "vpw-component-storage-v1:"
_ASSET_IDENTITY_KEY_PREFIX = "vpw-asset-identity-v2:"
_LEGACY_RESERVED_ASSET_STORAGE_KEY_PREFIX = "vpw-legacy-asset-identity-v1:"
_DOWNGRADE_ASSET_STORAGE_MARKER_PREFIX = (
    _LEGACY_RESERVED_ASSET_STORAGE_KEY_PREFIX + "migration-0005-downgrade-v1:"
)
_ASSET_REFERENCE_COLUMNS = (
    ("finding", "asset_id"),
    ("waiver", "asset_id"),
)


def upgrade() -> None:
    """
    Merge legacy aliases, then index the frozen v1 canonical identities.

    Asset and component duplicates keep the row with the earliest
    ``created_at``; a tie is resolved by the lexicographically smallest UUID.
    Every relational reference is re-pointed to that survivor before the
    duplicate is deleted.  Missing asset metadata is filled from aliases in
    the same deterministic order, while conflicting survivor values win.
    Finding, occurrence, and Decision Ledger rows are otherwise left untouched.
    """
    asset_updates, asset_merges, asset_key_updates = _asset_identity_plan()
    component_updates, component_merges = _component_identity_plan()
    _start_portable_write_transaction()
    _merge_asset_duplicates(asset_merges)
    _backfill_asset_keys(asset_updates)
    _normalize_waiver_asset_keys(asset_key_updates)
    _merge_component_duplicates(component_merges)
    op.add_column(
        "component",
        sa.Column(
            "identity_key",
            sqlmodel.sql.sqltypes.AutoString(length=128),
            nullable=True,
        ),
    )
    op.add_column(
        "component",
        sa.Column("identity_material", sa.Text(), nullable=True),
    )
    _backfill_component_identities(component_updates)
    with op.batch_alter_table("component") as batch_op:
        batch_op.drop_constraint("uq_component_identity", type_="unique")
        batch_op.drop_constraint("uq_component_purl", type_="unique")
        batch_op.alter_column(
            "identity_key",
            existing_type=sqlmodel.sql.sqltypes.AutoString(length=128),
            nullable=False,
        )
        batch_op.alter_column(
            "identity_material",
            existing_type=sa.Text(),
            nullable=False,
        )
        batch_op.create_unique_constraint("uq_component_identity_key", ["identity_key"])


def downgrade() -> None:
    """Remove indexed canonical component identities."""
    _preflight_legacy_identity_constraint()
    asset_marker_updates = _downgrade_asset_marker_plan()
    _start_portable_write_transaction()
    _backfill_asset_keys(asset_marker_updates)
    _mark_waiver_asset_keys_for_downgrade()
    with op.batch_alter_table("component") as batch_op:
        batch_op.drop_constraint("uq_component_identity_key", type_="unique")
        batch_op.create_unique_constraint(
            "uq_component_identity",
            ["name", "version", "ecosystem"],
        )
        batch_op.create_unique_constraint("uq_component_purl", ["purl"])
        batch_op.drop_column("identity_material")
        batch_op.drop_column("identity_key")


def _asset_identity_plan() -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[tuple[str, str], str],
]:
    """Plan project-scoped NFC-v1 asset-key updates and deterministic merges."""
    connection = op.get_bind()
    metadata = sa.MetaData()
    asset = sa.Table(
        "asset",
        metadata,
        autoload_with=connection,
        resolve_fks=False,
    )
    rows = connection.execute(
        sa.select(
            asset.c.id,
            asset.c.project_id,
            asset.c.asset_key,
        ).order_by(asset.c.created_at, asset.c.id)
    ).mappings()
    seen_by_identity: dict[tuple[str, str], Any] = {}
    updates: list[dict[str, Any]] = []
    merges: list[dict[str, Any]] = []
    for row in rows:
        normalized_key = _normalized_text(_string_value(row["asset_key"]))
        if normalized_key is None:
            raise RuntimeError(f"Asset {row['id']!s} has a blank identity key.")
        restored_key = _restore_downgraded_asset_storage_key(
            normalized_key,
            project_id=row["project_id"],
            expected_asset_id=row["id"],
        )
        identity = (str(row["project_id"]), normalized_key)
        survivor_id = seen_by_identity.get(identity)
        if survivor_id is not None:
            merges.append(
                {
                    "duplicate_id": row["id"],
                    "survivor_id": survivor_id,
                }
            )
            continue
        seen_by_identity[identity] = row["id"]
        updates.append(
            {
                "asset_id": row["id"],
                "project_id": row["project_id"],
                "normalized_key": normalized_key,
                "asset_key": restored_key or _asset_storage_key(normalized_key),
            }
        )
    _resolve_asset_storage_key_overlaps(updates)
    key_updates = {
        (str(update["project_id"]), update["normalized_key"]): update["asset_key"]
        for update in updates
    }
    for update in updates:
        del update["normalized_key"]
    return updates, merges, key_updates


def _resolve_asset_storage_key_overlaps(updates: list[dict[str, Any]]) -> None:
    """Displace fresh legacy-looking keys only when a preimage claims their key."""
    updates_by_project: dict[str, list[dict[str, Any]]] = {}
    for update in updates:
        updates_by_project.setdefault(str(update["project_id"]), []).append(update)

    for project_updates in updates_by_project.values():
        occupied: dict[str, dict[str, Any]] = {}
        movers: list[dict[str, Any]] = []
        for update in project_updates:
            if update["asset_key"] == update["normalized_key"]:
                occupied[update["asset_key"]] = update
            else:
                movers.append(update)

        for mover in movers:
            claimant = mover
            target = str(mover["asset_key"])
            visited_targets: set[str] = set()
            while True:
                if target in visited_targets:
                    raise RuntimeError("Asset identity escape cycle detected during migration.")
                visited_targets.add(target)
                occupant = occupied.get(target)
                if occupant is None:
                    claimant["asset_key"] = target
                    occupied[target] = claimant
                    break
                if occupant["asset_key"] != occupant["normalized_key"]:
                    raise RuntimeError("Asset identity hash collision detected during migration.")
                claimant["asset_key"] = target
                occupied[target] = claimant
                claimant = occupant
                target = _escaped_asset_storage_key(target)


def _merge_asset_duplicates(merges: list[dict[str, Any]]) -> None:
    """Merge asset aliases without dropping relational links or useful metadata."""
    if not merges:
        return
    connection = op.get_bind()
    metadata = sa.MetaData()
    asset = sa.Table(
        "asset",
        metadata,
        autoload_with=connection,
        resolve_fks=False,
    )
    reference_tables = tuple(
        (
            sa.Table(
                table_name,
                metadata,
                autoload_with=connection,
                resolve_fks=False,
            ),
            column_name,
        )
        for table_name, column_name in _ASSET_REFERENCE_COLUMNS
    )
    for merge in merges:
        survivor = (
            connection.execute(sa.select(asset).where(asset.c.id == merge["survivor_id"]))
            .mappings()
            .one()
        )
        duplicate = (
            connection.execute(sa.select(asset).where(asset.c.id == merge["duplicate_id"]))
            .mappings()
            .one()
        )
        connection.execute(
            sa.update(asset)
            .where(asset.c.id == merge["survivor_id"])
            .values(_merged_asset_values(dict(survivor), dict(duplicate)))
        )
        for table, column_name in reference_tables:
            reference_column = table.c[column_name]
            connection.execute(
                sa.update(table)
                .where(reference_column == merge["duplicate_id"])
                .values({column_name: merge["survivor_id"]})
            )
        remaining_references = sum(
            connection.execute(
                sa.select(sa.func.count())
                .select_from(table)
                .where(table.c[column_name] == merge["duplicate_id"])
            ).scalar_one()
            for table, column_name in reference_tables
        )
        if remaining_references:
            raise RuntimeError("Failed to re-point all references from a duplicate asset.")

        connection.execute(sa.delete(asset).where(asset.c.id == merge["duplicate_id"]))
        remaining_asset = connection.execute(
            sa.select(sa.func.count()).select_from(asset).where(asset.c.id == merge["duplicate_id"])
        ).scalar_one()
        if remaining_asset:
            raise RuntimeError("Failed to delete a merged asset alias.")


def _merged_asset_values(
    survivor: Mapping[str, Any],
    duplicate: Mapping[str, Any],
) -> dict[str, Any]:
    """Fill missing survivor context while retaining deterministic precedence."""
    return {
        "name": _preferred_text(survivor["name"], duplicate["name"]),
        "target_ref": _preferred_text(survivor["target_ref"], duplicate["target_ref"]),
        "owner": _preferred_text(survivor["owner"], duplicate["owner"]),
        "business_service": _preferred_text(
            survivor["business_service"], duplicate["business_service"]
        ),
        "environment": _preferred_asset_context(survivor["environment"], duplicate["environment"]),
        "exposure": _preferred_asset_context(survivor["exposure"], duplicate["exposure"]),
        "criticality": _preferred_asset_context(survivor["criticality"], duplicate["criticality"]),
        "updated_at": max(survivor["updated_at"], duplicate["updated_at"]),
    }


def _preferred_text(primary: Any, fallback: Any) -> Any:
    if isinstance(primary, str) and primary.strip():
        return primary
    return fallback


def _preferred_asset_context(primary: Any, fallback: Any) -> Any:
    if isinstance(primary, str) and primary.strip().casefold() not in {"", "unknown"}:
        return primary
    return fallback


def _backfill_asset_keys(updates: list[dict[str, Any]]) -> None:
    if not updates:
        return
    connection = op.get_bind()
    metadata = sa.MetaData()
    asset = sa.Table(
        "asset",
        metadata,
        autoload_with=connection,
        resolve_fks=False,
    )
    occupied_by_project: dict[str, set[str]] = {}
    for row in connection.execute(sa.select(asset.c.project_id, asset.c.asset_key)).mappings():
        occupied_by_project.setdefault(str(row["project_id"]), set()).add(str(row["asset_key"]))
    for update in updates:
        occupied_by_project.setdefault(str(update["project_id"]), set()).add(update["asset_key"])

    staged_updates: list[dict[str, Any]] = []
    for update in updates:
        project_id = str(update["project_id"])
        occupied = occupied_by_project[project_id]
        nonce = 0
        while True:
            material = f"20260904_0005:{project_id}:{update['asset_id']}:{nonce}"
            digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
            temporary_key = f"vpw-asset-migration-temp-v1:{digest}"
            if temporary_key not in occupied:
                break
            nonce += 1
        occupied.add(temporary_key)
        staged_updates.append(
            {
                "asset_id": update["asset_id"],
                "temporary_asset_key": temporary_key,
                "asset_key": update["asset_key"],
            }
        )

    # Move every survivor out of both the old and final namespaces first.  This
    # avoids transient uniqueness failures when one old key is another row's
    # final escaped key, independent of executemany ordering or SQL dialect.
    connection.execute(
        sa.text("UPDATE asset SET asset_key = :temporary_asset_key WHERE id = :asset_id"),
        staged_updates,
    )
    connection.execute(
        sa.text("UPDATE asset SET asset_key = :asset_key WHERE id = :asset_id"),
        staged_updates,
    )


def _normalize_waiver_asset_keys(
    asset_key_updates: Mapping[tuple[str, str], str],
) -> None:
    """Keep denormalized waiver scopes aligned with normalized asset identities."""
    connection = op.get_bind()
    metadata = sa.MetaData()
    waiver = sa.Table(
        "waiver",
        metadata,
        autoload_with=connection,
        resolve_fks=False,
    )
    updates: list[dict[str, Any]] = []
    rows = connection.execute(
        sa.select(
            waiver.c.id,
            waiver.c.project_id,
            waiver.c.asset_id,
            waiver.c.asset_key,
        ).where(waiver.c.asset_key.is_not(None))
    ).mappings()
    for row in rows:
        normalized_key = _normalized_text(_string_value(row["asset_key"]))
        restored_key = (
            _restore_downgraded_asset_storage_key(
                normalized_key,
                project_id=row["project_id"],
                expected_waiver_id=row["id"],
                linked_asset_id=row["asset_id"],
            )
            if normalized_key is not None
            else None
        )
        storage_key = (
            asset_key_updates.get(
                (str(row["project_id"]), normalized_key),
                restored_key or _asset_storage_key(normalized_key),
            )
            if normalized_key is not None
            else None
        )
        if storage_key is None or storage_key == row["asset_key"]:
            continue
        updates.append({"waiver_id": row["id"], "asset_key": storage_key})
    if updates:
        connection.execute(
            sa.text("UPDATE waiver SET asset_key = :asset_key WHERE id = :waiver_id"),
            updates,
        )


def _asset_storage_key(normalized_key: str) -> str:
    """Escape pre-v2 operator keys that now overlap internal storage namespaces."""
    folded = normalized_key.casefold()
    if folded.startswith((_ASSET_IDENTITY_KEY_PREFIX, _LEGACY_RESERVED_ASSET_STORAGE_KEY_PREFIX)):
        return _escaped_asset_storage_key(normalized_key)
    return normalized_key


def _escaped_asset_storage_key(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"{_LEGACY_RESERVED_ASSET_STORAGE_KEY_PREFIX}{digest}"


def _downgrade_asset_marker_plan() -> list[dict[str, Any]]:
    """Mark internal asset keys so a later re-upgrade cannot hash them again."""
    connection = op.get_bind()
    metadata = sa.MetaData()
    asset = sa.Table(
        "asset",
        metadata,
        autoload_with=connection,
        resolve_fks=False,
    )
    updates: list[dict[str, Any]] = []
    for row in connection.execute(
        sa.select(asset.c.id, asset.c.project_id, asset.c.asset_key)
    ).mappings():
        marker = _downgrade_asset_storage_marker(
            _string_value(row["asset_key"]),
            project_id=row["project_id"],
            binding_kind="a",
            binding_id=row["id"],
        )
        if marker is None:
            continue
        updates.append(
            {
                "asset_id": row["id"],
                "project_id": row["project_id"],
                "asset_key": marker,
            }
        )
    return updates


def _mark_waiver_asset_keys_for_downgrade() -> None:
    """Apply the reversible 0005 marker to denormalized waiver asset keys."""
    connection = op.get_bind()
    metadata = sa.MetaData()
    waiver = sa.Table(
        "waiver",
        metadata,
        autoload_with=connection,
        resolve_fks=False,
    )
    updates: list[dict[str, Any]] = []
    rows = connection.execute(
        sa.select(
            waiver.c.id,
            waiver.c.project_id,
            waiver.c.asset_id,
            waiver.c.asset_key,
        ).where(waiver.c.asset_key.is_not(None))
    ).mappings()
    for row in rows:
        linked_asset_id = row["asset_id"]
        marker = _downgrade_asset_storage_marker(
            _string_value(row["asset_key"]),
            project_id=row["project_id"],
            binding_kind="a" if linked_asset_id is not None else "w",
            binding_id=linked_asset_id if linked_asset_id is not None else row["id"],
        )
        if marker is None:
            continue
        updates.append({"waiver_id": row["id"], "asset_key": marker})
    if updates:
        connection.execute(
            sa.text("UPDATE waiver SET asset_key = :asset_key WHERE id = :waiver_id"),
            updates,
        )


def _downgrade_asset_storage_marker(
    value: str | None,
    *,
    project_id: Any,
    binding_kind: str,
    binding_id: Any,
) -> str | None:
    """Encode one canonical internal key in a row-bound reversible marker."""
    parts = _canonical_internal_asset_storage_key_parts(value)
    if parts is None:
        return None
    key_kind, digest = parts
    binding = f"{binding_kind}{_stable_identifier(binding_id)}"
    original_key = _internal_asset_storage_key(key_kind, digest)
    if original_key is None:  # pragma: no cover - guarded by the parsed key kind
        raise RuntimeError("Unsupported internal asset key in downgrade marker plan.")
    signature = _downgrade_marker_signature(
        project_id=project_id,
        binding=binding,
        original_key=original_key,
    )
    return f"{_DOWNGRADE_ASSET_STORAGE_MARKER_PREFIX}{key_kind}:{digest}:{binding}:{signature}"


def _restore_downgraded_asset_storage_key(
    value: str,
    *,
    project_id: Any,
    expected_asset_id: Any | None = None,
    expected_waiver_id: Any | None = None,
    linked_asset_id: Any | None = None,
) -> str | None:
    """Restore only an authenticated row-bound marker emitted by downgrade()."""
    if not value.startswith(_DOWNGRADE_ASSET_STORAGE_MARKER_PREFIX):
        return None
    payload = value.removeprefix(_DOWNGRADE_ASSET_STORAGE_MARKER_PREFIX)
    fields = payload.split(":")
    if len(fields) != 4:
        return None
    key_kind, digest, binding, signature = fields
    original_key = _internal_asset_storage_key(key_kind, digest)
    if original_key is None or not _is_lower_hex(signature, length=32):
        return None
    if expected_asset_id is not None:
        expected_binding = f"a{_stable_identifier(expected_asset_id)}"
        if binding != expected_binding:
            return None
    elif expected_waiver_id is not None:
        valid_bindings = {f"w{_stable_identifier(expected_waiver_id)}"}
        if linked_asset_id is not None:
            valid_bindings.add(f"a{_stable_identifier(linked_asset_id)}")
        if binding not in valid_bindings:
            return None
    expected_signature = _downgrade_marker_signature(
        project_id=project_id,
        binding=binding,
        original_key=original_key,
    )
    if signature != expected_signature:
        return None
    return original_key


def _canonical_internal_asset_storage_key_parts(value: str | None) -> tuple[str, str] | None:
    if value is None:
        return None
    for key_kind, prefix in (
        ("a", _ASSET_IDENTITY_KEY_PREFIX),
        ("l", _LEGACY_RESERVED_ASSET_STORAGE_KEY_PREFIX),
    ):
        if value.startswith(prefix):
            digest = value.removeprefix(prefix)
            if _is_lower_hex(digest, length=64):
                return key_kind, digest
    return None


def _internal_asset_storage_key(key_kind: str, digest: str) -> str | None:
    if not _is_lower_hex(digest, length=64):
        return None
    if key_kind == "a":
        return f"{_ASSET_IDENTITY_KEY_PREFIX}{digest}"
    if key_kind == "l":
        return f"{_LEGACY_RESERVED_ASSET_STORAGE_KEY_PREFIX}{digest}"
    return None


def _downgrade_marker_signature(
    *,
    project_id: Any,
    binding: str,
    original_key: str,
) -> str:
    material = json.dumps(
        [revision, _stable_identifier(project_id), binding, original_key],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _stable_identifier(value: Any) -> str:
    compact = str(value).replace("-", "").casefold()
    return compact


def _is_lower_hex(value: str, *, length: int) -> bool:
    return len(value) == length and all(character in "0123456789abcdef" for character in value)


def _component_identity_plan() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Plan deterministic merges and fail on a true hash collision before mutation."""
    connection = op.get_bind()
    metadata = sa.MetaData()
    component = sa.Table(
        "component",
        metadata,
        autoload_with=connection,
        resolve_fks=False,
    )
    rows = connection.execute(
        sa.select(
            component.c.id,
            component.c.name,
            component.c.version,
            component.c.purl,
            component.c.ecosystem,
            component.c.package_type,
        ).order_by(component.c.created_at, component.c.id)
    ).mappings()
    seen_by_key: dict[str, tuple[str, Any]] = {}
    updates: list[dict[str, Any]] = []
    merges: list[dict[str, Any]] = []
    for row in rows:
        material = _component_identity_material(dict(row))
        storage_key = _component_storage_key(material)
        previous = seen_by_key.get(storage_key)
        if previous is not None:
            previous_material, previous_id = previous
            if previous_material != material:
                raise RuntimeError("Component identity hash collision detected during migration.")
            merges.append(
                {
                    "duplicate_id": row["id"],
                    "survivor_id": previous_id,
                }
            )
            continue
        seen_by_key[storage_key] = (material, row["id"])
        updates.append(
            {
                "component_id": row["id"],
                "identity_key": storage_key,
                "identity_material": material,
            }
        )
    return updates, merges


def _start_portable_write_transaction() -> None:
    """
    Make SQLite's first statement DML so Alembic's revision is fully atomic.

    Python's legacy SQLite transaction mode does not start a database
    transaction for DDL.  Alembic already owns the per-revision SQLAlchemy
    transaction; this portable no-op UPDATE makes the DBAPI transaction real
    before any data change or batch DDL.  PostgreSQL simply executes it inside
    the transaction Alembic has already opened.
    """
    connection = op.get_bind()
    metadata = sa.MetaData()
    component = sa.Table(
        "component",
        metadata,
        autoload_with=connection,
        resolve_fks=False,
    )
    connection.execute(sa.update(component).where(sa.false()).values(id=component.c.id))


def _merge_component_duplicates(merges: list[dict[str, Any]]) -> None:
    """Re-point every finding reference and delete only unreferenced aliases."""
    if not merges:
        return
    connection = op.get_bind()
    metadata = sa.MetaData()
    component = sa.Table(
        "component",
        metadata,
        autoload_with=connection,
        resolve_fks=False,
    )
    finding = sa.Table(
        "finding",
        metadata,
        autoload_with=connection,
        resolve_fks=False,
    )
    for merge in merges:
        connection.execute(
            sa.update(finding)
            .where(finding.c.component_id == merge["duplicate_id"])
            .values(component_id=merge["survivor_id"])
        )
        remaining_references = connection.execute(
            sa.select(sa.func.count())
            .select_from(finding)
            .where(finding.c.component_id == merge["duplicate_id"])
        ).scalar_one()
        if remaining_references:
            raise RuntimeError("Failed to re-point all findings from a duplicate component.")

        connection.execute(sa.delete(component).where(component.c.id == merge["duplicate_id"]))
        remaining_component = connection.execute(
            sa.select(sa.func.count())
            .select_from(component)
            .where(component.c.id == merge["duplicate_id"])
        ).scalar_one()
        if remaining_component:
            raise RuntimeError("Failed to delete a merged component alias.")


def _backfill_component_identities(updates: list[dict[str, Any]]) -> None:
    if not updates:
        return
    op.get_bind().execute(
        sa.text(
            "UPDATE component SET identity_key = :identity_key, "
            "identity_material = :identity_material WHERE id = :component_id"
        ),
        updates,
    )


def _preflight_legacy_identity_constraint() -> None:
    """Fail before downgrade DDL if v1 rows cannot satisfy the legacy unique key."""
    duplicate = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT name, version, ecosystem FROM component "
                "WHERE name IS NOT NULL AND version IS NOT NULL AND ecosystem IS NOT NULL "
                "GROUP BY name, version, ecosystem HAVING COUNT(*) > 1 LIMIT 1"
            )
        )
        .first()
    )
    if duplicate is not None:
        raise RuntimeError(
            "Component rows cannot be downgraded to the legacy component identity constraint."
        )
    duplicate_purl = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT purl FROM component WHERE purl IS NOT NULL "
                "GROUP BY purl HAVING COUNT(*) > 1 LIMIT 1"
            )
        )
        .first()
    )
    if duplicate_purl is not None:
        raise RuntimeError("Component rows cannot be downgraded to the legacy PURL constraint.")


def _component_identity_material(row: Mapping[str, Any]) -> str:
    purl = _canonicalize_package_url(_string_value(row["purl"]))
    version = _normalized_text(_string_value(row["version"]))
    name = _normalized_text(_string_value(row["name"]), collapse_whitespace=True)
    package_type = _normalized_text(
        _string_value(row["package_type"]),
        casefold=True,
        collapse_whitespace=True,
    )
    ecosystem = _normalized_text(
        _string_value(row["ecosystem"]),
        casefold=True,
        collapse_whitespace=True,
    )
    if purl is not None:
        parsed_purl = _parsed_package_url(purl)
        if parsed_purl is not None and parsed_purl.version is not None:
            return _tagged_component_identity("purl", purl)
        return _tagged_component_identity("purl", purl, version)
    if name is None:
        raise RuntimeError(f"Component {row['id']!s} has no stable identity material.")
    return _tagged_component_identity(
        "coordinates",
        name.casefold(),
        version,
        package_type or ecosystem,
    )


def _component_storage_key(identity_material: str) -> str:
    digest = hashlib.sha256(identity_material.encode("utf-8")).hexdigest()
    return _COMPONENT_STORAGE_KEY_PREFIX + digest


def _tagged_component_identity(kind: str, *values: str | None) -> str:
    return _COMPONENT_IDENTITY_PREFIX + json.dumps(
        [kind, *values],
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _canonicalize_package_url(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = unicodedata.normalize("NFC", value).strip()
    if not normalized:
        return None
    scheme, separator, body = normalized.partition(":")
    package_type, path_separator, path = body.partition("/")
    candidate = normalized
    if separator and path_separator and scheme.casefold() == "pkg":
        candidate = f"pkg:{package_type.casefold()}/{path}"
    try:
        return PackageURL.from_string(candidate).to_string()
    except ValueError:
        return normalized


def _parsed_package_url(value: str) -> PackageURL | None:
    try:
        return PackageURL.from_string(value)
    except ValueError:
        return None


def _normalized_text(
    value: str | None,
    *,
    casefold: bool = False,
    collapse_whitespace: bool = False,
) -> str | None:
    if value is None:
        return None
    normalized = unicodedata.normalize("NFC", value).strip()
    if not normalized:
        return None
    if collapse_whitespace:
        normalized = " ".join(normalized.split())
    return normalized.casefold() if casefold else normalized


def _string_value(value: Any) -> str | None:
    return value if isinstance(value, str) else None
