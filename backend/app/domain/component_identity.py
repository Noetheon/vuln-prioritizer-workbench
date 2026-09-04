"""Canonical component identities shared by decision and persistence layers."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Final

from packageurl import PackageURL

COMPONENT_IDENTITY_PREFIX: Final = "component-identity-v1:"
COMPONENT_STORAGE_KEY_VERSION: Final = "component-storage-v1"
COMPONENT_STORAGE_KEY_PREFIX: Final = "vpw-component-storage-v1:"


def component_scope_identity(
    *,
    component_name: str | None,
    component_version: str | None = None,
    purl: str | None = None,
    package_type: str | None = None,
) -> str | None:
    """Return the collision-free canonical identity of one component scope."""
    normalized_purl = canonicalize_package_url(purl)
    if normalized_purl is not None:
        normalized_version = normalize_component_version(component_version)
        parsed_purl = _parsed_package_url(normalized_purl)
        if parsed_purl is not None and parsed_purl.version is not None:
            # A versioned PURL is authoritative. Some scanner formats also
            # expose an upstream version without a distro release suffix
            # (for example 5.6.0 beside apk 5.6.0-r0), so disagreement is not
            # sufficient evidence of malformed input.
            return _tagged_component_identity("purl", normalized_purl)
        # Package URLs are valid without a version. The source's separate
        # component version must then remain part of the scope or different
        # installed versions would silently collapse into one component row.
        return _tagged_component_identity("purl", normalized_purl, normalized_version)
    normalized_component_name = normalize_component_name(component_name)
    if normalized_component_name is None:
        return None
    return _tagged_component_identity(
        "coordinates",
        normalized_component_name,
        normalize_component_version(component_version),
        _normalize_casefolded_value(package_type, collapse_whitespace=True),
    )


def normalize_component_name(value: str | None) -> str | None:
    """Normalize a component name using the frozen coordinate-identity rules."""
    return _normalize_casefolded_value(value, collapse_whitespace=True)


def normalize_component_version(value: str | None) -> str | None:
    """Normalize a case-sensitive component version using NFC and boundary trim."""
    return _normalize_identity_value(value)


def canonicalize_package_url(value: str | None) -> str | None:
    """Canonicalize a PURL without erasing type-specific case semantics."""
    if value is None:
        return None
    normalized = _normalize_identity_value(value)
    if normalized is None:
        return None

    # PackageURL correctly applies ecosystem-specific rules (for example,
    # PyPI names are case-insensitive while generic names and versions are
    # not). Be liberal only about the scheme and type spelling at the input
    # boundary; malformed values stay exact so lossy normalization cannot
    # create an identity collision.
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
    """Return a parsed canonical PURL while keeping malformed input exact."""
    try:
        return PackageURL.from_string(value)
    except ValueError:
        return None


def component_storage_key(identity_material: str) -> str:
    """Return the bounded indexed key for canonical component material."""
    digest = hashlib.sha256(identity_material.encode("utf-8")).hexdigest()
    return COMPONENT_STORAGE_KEY_PREFIX + digest


def _tagged_component_identity(kind: str, *values: str | None) -> str:
    material = json.dumps(
        [kind, *values],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return COMPONENT_IDENTITY_PREFIX + material


def _normalize_identity_value(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = unicodedata.normalize("NFC", value).strip()
    return normalized or None


def _normalize_casefolded_value(
    value: str | None,
    *,
    collapse_whitespace: bool = False,
) -> str | None:
    normalized = _normalize_identity_value(value)
    if normalized is None:
        return None
    if collapse_whitespace:
        normalized = " ".join(normalized.split())
    return normalized.casefold()
