"""Reserved persistence identities for project assets."""

from __future__ import annotations

import hashlib
import unicodedata
from typing import Final

ASSET_IDENTITY_KEY_PREFIX: Final = "vpw-asset-identity-v2:"
LEGACY_RESERVED_ASSET_STORAGE_KEY_PREFIX: Final = "vpw-legacy-asset-identity-v1:"
ASSET_IDENTITY_NORMALIZATION_VERSION: Final = "nfc-v1"


def normalize_asset_identity_value(value: str) -> str:
    """Return the frozen NFC-v1 normalization shared by both v2 scope identities."""
    return unicodedata.normalize("NFC", value).strip()


def normalize_asset_target_kind(value: str) -> str:
    """Return the frozen NFC-v1 target-kind normalization for both v2 identities."""
    return " ".join(normalize_asset_identity_value(value).split()).casefold()


def is_reserved_asset_storage_key(value: str) -> bool:
    """Return whether an operator-facing key overlaps the internal namespace."""
    normalized = normalize_asset_identity_value(value).casefold()
    return normalized.startswith(
        (ASSET_IDENTITY_KEY_PREFIX, LEGACY_RESERVED_ASSET_STORAGE_KEY_PREFIX)
    )


def is_versioned_asset_identity_key(value: str) -> bool:
    """Return whether a key is a native v2 logical-identity storage key."""
    return normalize_asset_identity_value(value).casefold().startswith(ASSET_IDENTITY_KEY_PREFIX)


def is_legacy_reserved_asset_storage_key(value: str) -> bool:
    """Return whether a key is the escaped storage alias for a pre-v2 operator ID."""
    return (
        normalize_asset_identity_value(value)
        .casefold()
        .startswith(LEGACY_RESERVED_ASSET_STORAGE_KEY_PREFIX)
    )


def legacy_reserved_asset_storage_key(value: str) -> str:
    """Escape a pre-v2 operator key that now overlaps an internal namespace."""
    normalized = normalize_asset_identity_value(value)
    if not normalized or not is_reserved_asset_storage_key(normalized):
        raise ValueError("Legacy asset key does not use a reserved Workbench namespace.")
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return f"{LEGACY_RESERVED_ASSET_STORAGE_KEY_PREFIX}{digest}"


def validate_operator_asset_key(value: str) -> str:
    """Reject operator-controlled keys that can impersonate an internal identity."""
    normalized = normalize_asset_identity_value(value)
    if not normalized:
        raise ValueError("Asset key must not be blank.")
    if is_reserved_asset_storage_key(normalized):
        raise ValueError("Asset key uses the reserved Workbench identity namespace.")
    return normalized


def validate_asset_key_update(value: str, *, current_asset_key: str) -> str:
    """Allow an unchanged internal key while rejecting a new internal-key claim."""
    normalized = normalize_asset_identity_value(value)
    if normalized == normalize_asset_identity_value(current_asset_key):
        return normalized
    return validate_operator_asset_key(normalized)
