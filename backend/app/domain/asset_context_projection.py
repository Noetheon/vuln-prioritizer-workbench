"""Asset context projection and rescore helpers."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from app.domain.engine.inputs.loader import AssetContextRecord
from app.models import (
    Asset,
    AssetCriticality,
    AssetEnvironment,
    AssetExposure,
)


def _with_rescore_flag(
    payload: dict[str, Any],
    *,
    asset_id: uuid.UUID,
    changed_fields: Sequence[str],
    changed_at: datetime,
) -> dict[str, Any]:
    """With rescore flag function."""
    data_quality = dict(payload or {})
    raw_flags = data_quality.get("flags")
    flags = (
        [dict(flag) for flag in raw_flags if isinstance(flag, dict)]
        if isinstance(raw_flags, list)
        else []
    )
    flags = [flag for flag in flags if flag.get("code") != "asset_context_rescore_needed"]
    flags.append(
        {
            "source": "asset_context",
            "code": "asset_context_rescore_needed",
            "severity": "warning",
            "message": (
                "Asset context changed; rerun analysis or review the operational "
                "score before relying on this priority."
            ),
            "asset_id": str(asset_id),
            "changed_fields": list(changed_fields),
            "changed_at": changed_at.isoformat(),
        }
    )
    data_quality["flags"] = flags
    data_quality["confidence"] = "medium"
    return data_quality


def _records_by_asset_key(records: Sequence[AssetContextRecord]) -> list[AssetContextRecord]:
    """Records by asset key function."""
    deduped: dict[str, AssetContextRecord] = {}
    for record in records:
        deduped[record.asset_id] = record
    return list(deduped.values())


def _asset_snapshot(asset: Asset | None) -> dict[str, Any]:
    """Asset snapshot function."""
    if asset is None:
        return {}
    return {
        "asset_key": asset.asset_key,
        "target_ref": asset.target_ref,
        "owner": asset.owner,
        "business_service": asset.business_service,
        "environment": str(asset.environment),
        "exposure": str(asset.exposure),
        "criticality": str(asset.criticality),
    }


def _changed_asset_fields(
    before: dict[str, Any],
    after: dict[str, Any],
) -> list[str]:
    """Changed asset fields function."""
    return sorted(field for field, previous in before.items() if after.get(field) != previous)


def _asset_environment(value: str | None) -> AssetEnvironment:
    """Asset environment function."""
    normalized = (value or "").strip().lower().replace("_", "-")
    return {
        "prod": AssetEnvironment.PRODUCTION,
        "production": AssetEnvironment.PRODUCTION,
        "stage": AssetEnvironment.STAGING,
        "staging": AssetEnvironment.STAGING,
        "dev": AssetEnvironment.DEVELOPMENT,
        "development": AssetEnvironment.DEVELOPMENT,
        "test": AssetEnvironment.TEST,
        "testing": AssetEnvironment.TEST,
        "unknown": AssetEnvironment.UNKNOWN,
    }.get(normalized, AssetEnvironment.UNKNOWN)


def _asset_exposure(value: str | None) -> AssetExposure:
    """Asset exposure function."""
    normalized = (value or "").strip().lower().replace("_", "-")
    return {
        "external": AssetExposure.INTERNET_FACING,
        "internet": AssetExposure.INTERNET_FACING,
        "internet-facing": AssetExposure.INTERNET_FACING,
        "public": AssetExposure.INTERNET_FACING,
        "internal": AssetExposure.INTERNAL,
        "private": AssetExposure.PRIVATE,
        "unknown": AssetExposure.UNKNOWN,
    }.get(normalized, AssetExposure.UNKNOWN)


def _asset_criticality(value: str | None) -> AssetCriticality:
    """Asset criticality function."""
    normalized = (value or "").strip().lower().replace("_", "-")
    return {
        "critical": AssetCriticality.CRITICAL,
        "high": AssetCriticality.HIGH,
        "medium": AssetCriticality.MEDIUM,
        "med": AssetCriticality.MEDIUM,
        "low": AssetCriticality.LOW,
        "unknown": AssetCriticality.UNKNOWN,
    }.get(normalized, AssetCriticality.UNKNOWN)


def _with_rescore_evidence(
    payload: dict[str, Any],
    *,
    asset_id: uuid.UUID,
    changed_fields: Sequence[str],
    changed_at: datetime,
) -> dict[str, Any]:
    """With rescore evidence function."""
    evidence = dict(payload or {})
    evidence["asset_context"] = {
        "rescore_needed": True,
        "asset_id": str(asset_id),
        "changed_fields": list(changed_fields),
        "changed_at": changed_at.isoformat(),
    }
    return evidence


def _value_list(value: Any) -> list[str]:
    """Value list function."""
    if value is None:
        return []
    text = str(value).strip()
    return [text] if text else []


__all__ = [
    "_with_rescore_flag",
    "_records_by_asset_key",
    "_asset_snapshot",
    "_changed_asset_fields",
    "_asset_environment",
    "_asset_exposure",
    "_asset_criticality",
    "_with_rescore_evidence",
    "_value_list",
]
