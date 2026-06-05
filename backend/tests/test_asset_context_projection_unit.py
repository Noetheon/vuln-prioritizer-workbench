from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.domain.asset_context_projection import (
    _asset_criticality,
    _asset_environment,
    _asset_exposure,
    _asset_snapshot,
    _changed_asset_fields,
    _records_by_asset_key,
    _value_list,
    _with_rescore_evidence,
    _with_rescore_flag,
)
from app.domain.engine.inputs.loader import AssetContextRecord
from app.models import Asset, AssetCriticality, AssetEnvironment, AssetExposure


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

    evidence = _with_rescore_evidence(
        {}, asset_id=asset_id, changed_fields=["owner"], changed_at=changed_at
    )
    assert evidence["asset_context"]["rescore_needed"] is True
    assert evidence["asset_context"]["asset_id"] == str(asset_id)


def test_asset_context_projection_helpers_normalize_asset_values() -> None:
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
