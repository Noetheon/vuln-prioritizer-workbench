from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.domain.asset_context_projection import (
    _asset_criticality,
    _asset_environment,
    _asset_exposure,
    _asset_snapshot,
    _changed_asset_fields,
    _finding_as_prioritized,
    _priority_label,
    _provenance_from_finding,
    _recalculated_evidence_json,
    _recalculated_explanation_json,
    _records_by_asset_key,
    _value_list,
    _with_current_asset_context,
    _with_rescore_evidence,
    _with_rescore_flag,
    _without_rescore_flag,
)
from app.models import Asset, AssetCriticality, AssetEnvironment, AssetExposure, Finding
from vuln_prioritizer.inputs.loader import AssetContextRecord


def test_asset_context_projection_helpers_cover_rescore_and_recalculation_paths() -> None:
    changed_at = datetime(2026, 5, 29, 12, 0, tzinfo=UTC)
    asset_id = uuid.uuid4()
    rescore = _with_rescore_flag(
        {"flags": [{"code": "asset_context_rescore_needed"}, {"code": "kept"}]},
        asset_id=asset_id,
        changed_fields=["owner", "criticality"],
        changed_at=changed_at,
    )

    assert rescore["confidence"] == "medium"
    assert [flag["code"] for flag in rescore["flags"]] == [
        "kept",
        "asset_context_rescore_needed",
    ]
    assert _without_rescore_flag(
        {"flags": rescore["flags"], "confidence": "medium"},
        flags_key="flags",
        confidence_key="confidence",
    ) == ({"flags": [{"code": "kept"}], "confidence": "medium"}, 1)
    assert _without_rescore_flag(
        {"flags": [{"code": "asset_context_rescore_needed"}], "confidence": "medium"},
        flags_key="flags",
        confidence_key="confidence",
    ) == ({"flags": [], "confidence": "high"}, 1)

    evidence = _with_rescore_evidence(
        {}, asset_id=asset_id, changed_fields=["owner"], changed_at=changed_at
    )
    assert evidence["asset_context"]["rescore_needed"] is True
    assert evidence["asset_context"]["asset_id"] == str(asset_id)


def test_asset_context_projection_helpers_normalize_assets_and_prioritized_findings() -> None:
    project_id = uuid.uuid4()
    asset = Asset(
        id=uuid.uuid4(),
        project_id=project_id,
        asset_key="payments-api",
        name="Payments API",
        target_ref="host-1",
        owner="platform",
        business_service="checkout",
        environment=AssetEnvironment.PRODUCTION,
        exposure=AssetExposure.INTERNET_FACING,
        criticality=AssetCriticality.CRITICAL,
    )
    finding = Finding(
        id=uuid.uuid4(),
        project_id=project_id,
        vulnerability_id=uuid.uuid4(),
        asset_id=asset.id,
        cve_id="CVE-2024-3094",
        priority="critical",
        priority_rank=1,
        risk_score=96.0,
        operational_rank=2,
        epss=0.91,
        cvss_base_score=10.0,
        in_kev=True,
        attack_mapped=True,
        rationale="KEV and high EPSS.",
        recommended_action="Patch now.",
    )
    finding.asset = asset

    assert _asset_snapshot(None) == {}
    assert _asset_snapshot(asset)["business_service"] == "checkout"
    assert _changed_asset_fields(
        {"owner": "platform", "criticality": "high"}, {"owner": "appsec"}
    ) == [
        "criticality",
        "owner",
    ]
    assert _asset_environment("prod") == AssetEnvironment.PRODUCTION
    assert _asset_environment("testing") == AssetEnvironment.TEST
    assert _asset_environment("other") == AssetEnvironment.UNKNOWN
    assert _asset_exposure("public") == AssetExposure.INTERNET_FACING
    assert _asset_exposure("private") == AssetExposure.PRIVATE
    assert _asset_criticality("med") == AssetCriticality.MEDIUM
    assert _asset_criticality("other") == AssetCriticality.UNKNOWN
    assert _priority_label("FindingPriority.HIGH") == "High"
    assert _priority_label("unexpected") == "Low"
    assert _value_list("  host-1  ") == ["host-1"]
    assert _value_list("") == []
    assert (
        _records_by_asset_key(
            [
                AssetContextRecord(target_kind="host", target_ref="old", asset_id="api"),
                AssetContextRecord(target_kind="host", target_ref="new", asset_id="api"),
            ]
        )[0].target_ref
        == "new"
    )

    provenance = _provenance_from_finding(finding)
    assert provenance.asset_ids == ["payments-api"]
    prioritized = _finding_as_prioritized(finding)
    assert prioritized.priority_label == "Critical"
    assert prioritized.provenance.occurrences[0].asset_business_service == "checkout"

    updated_asset = asset.model_copy(
        update={
            "target_ref": None,
            "asset_key": "payments-v2",
            "owner": "appsec",
            "business_service": "payments",
            "environment": AssetEnvironment.STAGING,
            "exposure": AssetExposure.INTERNAL,
            "criticality": AssetCriticality.HIGH,
        }
    )
    with_context = _with_current_asset_context(prioritized, updated_asset)
    assert with_context.provenance.targets == ["payments-v2"]
    assert with_context.provenance.asset_owners == ["appsec"]
    assert with_context.context_summary is not None

    explanation = _recalculated_explanation_json(
        {"explanation": {"score_inputs": {"previous": True}}},
        prioritized=with_context,
        priority_state="High",
        score=88,
        reasons=["asset context updated"],
    )
    assert explanation["explanation"]["score_inputs"]["asset_context_recalculated"] is True
    assert explanation["operational_score_reasons"] == ["asset context updated"]

    recalculated = _recalculated_evidence_json(
        {},
        asset=updated_asset,
        recalculated_at=datetime(2026, 5, 29, 13, 0, tzinfo=UTC),
        score=88,
        reasons=["asset context updated"],
    )
    assert recalculated["asset_context"]["rescore_needed"] is False
    assert recalculated["asset_context"]["asset_key"] == "payments-v2"
