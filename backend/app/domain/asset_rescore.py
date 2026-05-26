"""Asset finding rescore domain operations."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.domain.asset_context_projection import (
    _finding_as_prioritized,
    _recalculated_evidence_json,
    _recalculated_explanation_json,
    _with_current_asset_context,
    _with_rescore_evidence,
    _with_rescore_flag,
    _without_rescore_flag,
)
from app.models import Asset, Finding
from vuln_prioritizer.models import PriorityPolicy
from vuln_prioritizer.scoring import build_operational_score, determine_priority_state


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
    return AssetFindingRescoreMarker(
        data_quality_json=_with_rescore_flag(
            finding.data_quality_json,
            asset_id=asset_id,
            changed_fields=changed_fields,
            changed_at=changed_at,
        ),
        evidence_json=_with_rescore_evidence(
            finding.evidence_json,
            asset_id=asset_id,
            changed_fields=changed_fields,
            changed_at=changed_at,
        ),
    )


def recalculate_asset_finding(
    finding: Finding,
    *,
    asset: Asset,
    recalculated_at: datetime,
) -> AssetFindingRecalculation:
    """Recalculate one finding from the current persisted asset context."""
    prioritized = _finding_as_prioritized(finding)
    prioritized = _with_current_asset_context(prioritized, asset)
    score, reasons = build_operational_score(prioritized, PriorityPolicy())
    priority_state = determine_priority_state(prioritized).value
    explanation_json = _recalculated_explanation_json(
        finding.explanation_json,
        prioritized=prioritized,
        priority_state=priority_state,
        score=score,
        reasons=reasons,
    )
    data_quality_json, removed_from_data_quality = _without_rescore_flag(
        finding.data_quality_json,
        flags_key="flags",
        confidence_key="confidence",
    )
    explanation_json, removed_from_explanation = _without_rescore_flag(
        explanation_json,
        flags_key="data_quality_flags",
        confidence_key="data_quality_confidence",
    )
    evidence_json = _recalculated_evidence_json(
        finding.evidence_json,
        asset=asset,
        recalculated_at=recalculated_at,
        score=score,
        reasons=reasons,
    )
    return AssetFindingRecalculation(
        data_quality_json=data_quality_json,
        evidence_json=evidence_json,
        explanation_json=explanation_json,
        risk_score=float(score),
        cleared_flags=removed_from_data_quality + removed_from_explanation,
        operational_score=score,
    )
