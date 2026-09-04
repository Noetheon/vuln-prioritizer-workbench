"""Stable observation and finding-scope identities for decision workflows."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, NamedTuple

from app.domain.asset_identity import (
    normalize_asset_identity_value,
    normalize_asset_target_kind,
)
from app.domain.component_identity import component_scope_identity

OBSERVATION_KEY_VERSION: Final = "observation-v1"
OBSERVATION_KEY_PREFIX: Final = "vpw-observation-v1:"
FINDING_SCOPE_KEY_VERSION: Final = "finding-scope-v2"
FINDING_SCOPE_KEY_PREFIX: Final = "vpw-finding-scope-v2:"


@dataclass(frozen=True, slots=True)
class ObservationIdentity:
    """Identity of one normalized source observation for one CVE alias."""

    source: str
    source_record_id: str | None
    cve_id: str
    source_id: str | None

    def parts(self) -> dict[str, str | None]:
        """Return the canonical material used by the observation key."""
        return {
            "source": self.source,
            "source_record_id": self.source_record_id,
            "cve_id": self.cve_id,
            "source_id": self.source_id,
        }


@dataclass(frozen=True, slots=True)
class FindingScopeIdentity:
    """Identity of the persisted finding scope independent of source provenance."""

    project_id: str
    cve_id: str
    component_identity: str | None
    target_kind: str
    target_ref: str | None

    def parts(self) -> dict[str, str | None]:
        """Return the canonical material used by the finding-scope key."""
        return {
            "project_id": self.project_id,
            "cve_id": self.cve_id,
            "component_identity": self.component_identity,
            "target_kind": self.target_kind,
            "target_ref": self.target_ref,
        }


class FindingScopeParts(NamedTuple):
    """Project-independent normalized fields shared by analysis and persistence."""

    cve_id: str
    component_identity: str | None
    target_kind: str
    target_ref: str | None


def observation_identity(
    *,
    source: str,
    source_record_id: str | None,
    cve_id: str,
    source_id: str | None = None,
) -> ObservationIdentity:
    """Build canonical provenance identity for one source record and CVE alias."""
    normalized_source = _normalize_observation_casefolded_value(source)
    if normalized_source is None:
        raise ValueError("Observation source must not be blank.")
    return ObservationIdentity(
        source=normalized_source,
        # Provenance identifiers stay source-exact apart from boundary
        # whitespace. Unicode normalization could collapse byte-distinct IDs
        # assigned by an upstream scanner.
        source_record_id=_normalize_observation_identity_value(source_record_id),
        cve_id=_normalize_cve_id(cve_id),
        source_id=_normalize_observation_identity_value(source_id),
    )


def observation_key(identity: ObservationIdentity) -> str:
    """Return the versioned stable key for a normalized observation."""
    return _versioned_identity_key(
        prefix=OBSERVATION_KEY_PREFIX,
        version=OBSERVATION_KEY_VERSION,
        parts=identity.parts(),
    )


def finding_scope_identity(
    *,
    project_id: uuid.UUID | str,
    cve_id: str,
    component_name: str | None = None,
    component_version: str | None = None,
    purl: str | None = None,
    package_type: str | None = None,
    asset_id: str | None = None,
    target_kind: str | None = "generic",
    target_ref: str | None = None,
) -> FindingScopeIdentity:
    """Build canonical identity for one project/CVE/component/asset finding scope."""
    scope_parts = finding_scope_parts(
        cve_id=cve_id,
        component_name=component_name,
        component_version=component_version,
        purl=purl,
        package_type=package_type,
        asset_id=asset_id,
        target_kind=target_kind,
        target_ref=target_ref,
    )
    return FindingScopeIdentity(
        project_id=str(uuid.UUID(str(project_id).strip())),
        cve_id=scope_parts.cve_id,
        component_identity=scope_parts.component_identity,
        target_kind=scope_parts.target_kind,
        target_ref=scope_parts.target_ref,
    )


def finding_scope_parts(
    *,
    cve_id: str,
    component_name: str | None = None,
    component_version: str | None = None,
    purl: str | None = None,
    package_type: str | None = None,
    asset_id: str | None = None,
    target_kind: str | None = "generic",
    target_ref: str | None = None,
) -> FindingScopeParts:
    """Normalize the project-independent scope fields used by analysis and persistence."""
    normalized_target_ref = _normalize_scope_identity_value(target_ref)
    normalized_asset_id = _normalize_scope_identity_value(asset_id)
    normalized_target_kind = (
        normalize_asset_target_kind(target_kind) if target_kind is not None else None
    )
    return FindingScopeParts(
        cve_id=_normalize_cve_id(cve_id),
        component_identity=_component_identity(
            component_name=component_name,
            component_version=component_version,
            purl=purl,
            package_type=package_type,
        ),
        target_kind=normalized_target_kind or "generic",
        target_ref=normalized_target_ref or normalized_asset_id,
    )


def finding_scope_key(identity: FindingScopeIdentity) -> str:
    """Return the versioned stable key for a persisted finding scope."""
    return _versioned_identity_key(
        prefix=FINDING_SCOPE_KEY_PREFIX,
        version=FINDING_SCOPE_KEY_VERSION,
        parts=identity.parts(),
    )


def _component_identity(
    *,
    component_name: str | None,
    component_version: str | None,
    purl: str | None,
    package_type: str | None,
) -> str | None:
    return component_scope_identity(
        component_name=component_name,
        component_version=component_version,
        purl=purl,
        package_type=package_type,
    )


def _normalize_cve_id(value: str) -> str:
    return value.strip().upper()


def _normalize_scope_identity_value(value: str | None) -> str | None:
    """Normalize user-visible scope labels without changing their case semantics."""
    if value is None:
        return None
    normalized = normalize_asset_identity_value(value)
    return normalized or None


def _normalize_observation_casefolded_value(value: str | None) -> str | None:
    normalized = _normalize_observation_identity_value(value)
    return normalized.casefold() if normalized is not None else None


def _normalize_observation_identity_value(value: str | None) -> str | None:
    """Preserve source-assigned provenance IDs except for boundary whitespace."""
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _versioned_identity_key(
    *,
    prefix: str,
    version: str,
    parts: Mapping[str, str | None],
) -> str:
    material = json.dumps(
        {"version": version, "parts": parts},
        sort_keys=True,
        separators=(",", ":"),
    )
    return prefix + hashlib.sha256(material.encode("utf-8")).hexdigest()
