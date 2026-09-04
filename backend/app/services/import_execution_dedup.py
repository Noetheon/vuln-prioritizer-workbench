"""Deduplication key helpers for Workbench import persistence."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import defaultdict
from collections.abc import Mapping, Sequence

from app.decision_core.identity import (
    FindingScopeIdentity,
    finding_scope_identity,
    finding_scope_key,
    observation_identity,
    observation_key,
)
from app.domain.asset_identity import (
    ASSET_IDENTITY_KEY_PREFIX,
    is_legacy_reserved_asset_storage_key,
    is_reserved_asset_storage_key,
    legacy_reserved_asset_storage_key,
    normalize_asset_identity_value,
    normalize_asset_target_kind,
)
from app.domain.import_asset_context import string_evidence as _string_evidence
from app.importers.contracts import NormalizedOccurrence


def _dedup_key_parts(
    project_id: uuid.UUID,
    occurrence: NormalizedOccurrence,
) -> dict[str, str | None]:
    scope = finding_scope_identity(
        project_id=project_id,
        cve_id=occurrence.cve_id,
        component_name=occurrence.component_name,
        component_version=occurrence.component_version,
        purl=_string_evidence(occurrence.raw_evidence, "purl"),
        package_type=_string_evidence(occurrence.raw_evidence, "package_type"),
        asset_id=occurrence.asset_id,
        target_kind=occurrence.target_kind,
        target_ref=occurrence.target_ref,
    )
    source_id = _normalized_identity_value(
        _string_evidence(occurrence.raw_evidence, "source_id")
        or _string_evidence(occurrence.raw_evidence, "vulnerability_id")
        or occurrence.cve_id
    )
    return {
        **scope.parts(),
        "source_id": source_id,
    }


def _finding_dedup_key(parts: Mapping[str, str | None]) -> str:
    project_id = parts["project_id"]
    cve_id = parts["cve_id"]
    target_kind = parts["target_kind"]
    if project_id is None or cve_id is None or target_kind is None:
        raise ValueError("Finding identity is missing a required scope field.")
    return finding_scope_key(
        FindingScopeIdentity(
            project_id=project_id,
            cve_id=cve_id,
            component_identity=parts["component_identity"],
            target_kind=target_kind,
            target_ref=parts["target_ref"],
        )
    )


def _observation_key(occurrence: NormalizedOccurrence) -> str:
    identity = observation_identity(
        source=occurrence.source,
        source_record_id=_string_evidence(occurrence.raw_evidence, "source_record_id"),
        source_id=(
            _string_evidence(occurrence.raw_evidence, "source_id")
            or _string_evidence(occurrence.raw_evidence, "vulnerability_id")
        ),
        cve_id=occurrence.cve_id,
    )
    return observation_key(identity)


def _persistence_order_key(
    project_id: uuid.UUID,
    occurrence: NormalizedOccurrence,
) -> tuple[str, str]:
    """Return an input-order-independent representative key for projections."""
    return (
        _finding_dedup_key(_dedup_key_parts(project_id, occurrence)),
        _observation_key(occurrence),
    )


def _normalized_identity_value(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _asset_persistence_key(occurrence: NormalizedOccurrence) -> str | None:
    """Return a collision-free logical identity for one mutable asset link."""
    if occurrence.asset_id is not None:
        parts = ["asset-id", normalize_asset_identity_value(occurrence.asset_id)]
    elif occurrence.target_ref is not None:
        parts = [
            "source-target",
            normalize_asset_target_kind(occurrence.target_kind),
            normalize_asset_identity_value(occurrence.target_ref),
        ]
    else:
        return None
    material = json.dumps(
        parts,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return ASSET_IDENTITY_KEY_PREFIX + hashlib.sha256(material.encode("utf-8")).hexdigest()


def _preferred_asset_storage_key(
    occurrence: NormalizedOccurrence,
    *,
    allow_legacy_reserved: bool = False,
) -> str | None:
    """Return the backward-compatible operator-facing key preferred for storage."""
    if occurrence.asset_id is not None:
        asset_id = normalize_asset_identity_value(occurrence.asset_id)
        if is_reserved_asset_storage_key(asset_id):
            if not allow_legacy_reserved:
                raise ValueError("Asset ID uses the reserved Workbench identity namespace.")
            return legacy_reserved_asset_storage_key(asset_id)
        return asset_id
    if occurrence.target_ref is None:
        return None
    target_kind = normalize_asset_target_kind(occurrence.target_kind)
    target_ref = normalize_asset_identity_value(occurrence.target_ref)
    if target_kind == "generic":
        return target_ref
    return f"{target_kind}:{target_ref}"


def _asset_storage_keys_by_identity(
    occurrences_by_identity: Mapping[str, Sequence[NormalizedOccurrence]],
    *,
    allow_legacy_reserved: bool = False,
) -> dict[str, str]:
    """Assign readable storage keys and disambiguate real collisions deterministically."""
    identities_by_preferred: defaultdict[str, list[str]] = defaultdict(list)
    for identity_key, occurrences in occurrences_by_identity.items():
        preferred = {
            key
            for occurrence in occurrences
            if (
                key := _preferred_asset_storage_key(
                    occurrence,
                    allow_legacy_reserved=allow_legacy_reserved,
                )
            )
            is not None
        }
        if len(preferred) != 1:
            raise ValueError("One asset identity resolved to inconsistent storage keys.")
        preferred_key = next(iter(preferred))
        if len(preferred_key) > 200 or (
            is_reserved_asset_storage_key(preferred_key)
            and not is_legacy_reserved_asset_storage_key(preferred_key)
        ):
            preferred_key = identity_key
        identities_by_preferred[preferred_key].append(identity_key)

    storage_by_identity: dict[str, str] = {}
    for preferred_key, identities in identities_by_preferred.items():
        ordered = sorted(
            identities,
            key=lambda identity: (
                not any(
                    occurrence.asset_id is not None
                    for occurrence in occurrences_by_identity[identity]
                ),
                identity,
            ),
        )
        storage_by_identity[ordered[0]] = preferred_key
        for identity in ordered[1:]:
            storage_by_identity[identity] = identity
    if len(set(storage_by_identity.values())) != len(storage_by_identity):
        raise ValueError("Asset identities resolved to colliding storage keys.")
    return storage_by_identity


def _legacy_asset_persistence_keys(occurrence: NormalizedOccurrence) -> tuple[str, ...]:
    """Return pre-v2 implicit keys that may be promoted only with scope evidence."""
    if occurrence.asset_id is not None or occurrence.target_ref is None:
        return ()
    normalized_ref = normalize_asset_identity_value(occurrence.target_ref)
    normalized_kind = normalize_asset_target_kind(occurrence.target_kind)
    keys = [occurrence.target_ref, normalized_ref]
    if occurrence.target_kind != "generic":
        keys.append(f"{occurrence.target_kind}:{occurrence.target_ref}")
        keys.append(f"{normalized_kind}:{normalized_ref}")
    return tuple(dict.fromkeys(keys))
