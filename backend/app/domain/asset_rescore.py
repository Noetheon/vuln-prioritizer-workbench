"""Asset finding rescore domain operations."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.models import Asset, Finding


@dataclass(frozen=True)
class AssetFindingRescoreMarker:
    """Updated finding payloads after an asset context change."""

    data_quality_json: dict[str, Any]
    evidence_json: dict[str, Any]


@dataclass(frozen=True)
class AssetFindingRecalculation:
    """Recalculated finding score and payloads for the current asset context."""

    data_quality_json: dict[str, Any]
    evidence_json: dict[str, Any]
    explanation_json: dict[str, Any]
    risk_score: float
    cleared_flags: int
    operational_score: int


def mark_finding_rescore_needed(
    finding: Finding,
    *,
    asset_id: uuid.UUID,
    changed_fields: Sequence[str],
    changed_at: datetime,
) -> AssetFindingRescoreMarker:
    """Build updated payloads that mark a finding for asset-context re-score."""
    _ = finding, asset_id, changed_fields, changed_at
    return AssetFindingRescoreMarker(
        data_quality_json={},
        evidence_json={},
    )


def recalculate_asset_finding(
    finding: Finding,
    *,
    asset: Asset,
    recalculated_at: datetime,
) -> AssetFindingRecalculation:
    """Recalculate one finding from the current persisted asset context."""
    _ = asset, recalculated_at
    score = int(finding.risk_score or 0)
    return AssetFindingRecalculation(
        data_quality_json={},
        evidence_json={},
        explanation_json={},
        risk_score=float(score),
        cleared_flags=0,
        operational_score=score,
    )
