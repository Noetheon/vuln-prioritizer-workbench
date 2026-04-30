from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

from sqlmodel import Session
from utils.template_workbench import (
    TemplateApiEnv,
    auth_headers,
    create_component,
    create_project_via_api,
)

from app.models.base import get_datetime_utc


def test_vpw067_governance_rollups_count_owner_service_environment_and_waiver_debt(
    template_api_env: TemplateApiEnv,
) -> None:
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    _seed_vpw067_governance_graph(template_api_env, project_id)

    response = template_api_env.client.get(
        f"/api/v1/projects/{project_id}/governance/rollups/",
        headers=headers,
        params={"limit": 5},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["project_id"] == str(project_id)

    checkout = payload["top_services_by_risk"][0]
    assert checkout["label"] == "checkout"
    assert checkout["finding_count"] == 2
    assert checkout["critical_count"] == 1
    assert checkout["high_count"] == 1
    assert checkout["accepted_count"] == 2
    assert checkout["suppressed_by_vex_count"] == 1
    assert checkout["review_due_waiver_count"] == 2
    assert checkout["risk_score_total"] == 180.0
    assert checkout["priority_counts"]["Critical"] == 1
    assert checkout["priority_counts"]["High"] == 1
    assert checkout["status_counts"]["accepted"] == 2
    assert checkout["top_cves"] == ["CVE-2026-6701", "CVE-2026-6702"]

    top_asset = payload["top_assets_by_risk"][0]
    assert top_asset["dimension"] == "asset"
    assert top_asset["label"] == "payments-api"
    assert top_asset["finding_count"] == 2
    assert top_asset["accepted_count"] == 2
    assert top_asset["suppressed_by_vex_count"] == 1

    production = next(item for item in payload["environments"] if item["label"] == "production")
    assert production["finding_count"] == 3
    assert production["expired_waiver_count"] == 1
    assert production["review_due_waiver_count"] == 2

    platform = next(item for item in payload["owners"] if item["label"] == "platform")
    assert platform["finding_count"] == 2
    assert platform["accepted_count"] == 2

    waiver_debt = payload["waiver_debt"]
    assert waiver_debt["waiver_count"] == 2
    assert waiver_debt["review_due_count"] == 1
    assert waiver_debt["expired_count"] == 1
    assert waiver_debt["expiring_soon_count"] == 1
    assert waiver_debt["matched_finding_count"] == 3
    assert waiver_debt["accepted_finding_count"] == 2
    assert waiver_debt["expired_finding_count"] == 1
    assert waiver_debt["review_due_finding_count"] == 2
    assert waiver_debt["owner_counts"] == {"legacy-risk": 1, "risk-team": 1}
    assert [item["status"] for item in waiver_debt["items"]] == ["expired", "review_due"]
    assert waiver_debt["items"][0]["matched_findings"] == 1
    assert waiver_debt["items"][1]["service"] == "checkout"


def _seed_vpw067_governance_graph(
    template_api_env: TemplateApiEnv,
    project_id: uuid.UUID,
) -> None:
    app_models = template_api_env.app_models
    repositories = template_api_env.repositories
    today = get_datetime_utc().date()
    with Session(template_api_env.engine) as session:
        asset_repo = repositories.AssetRepository(session)
        finding_repo = repositories.FindingRepository(session)
        waiver_repo = repositories.WaiverRepository(session)
        checkout_asset = asset_repo.upsert_asset(
            project_id=project_id,
            asset_key="payments-api",
            name="Payments API",
            owner="platform",
            business_service="checkout",
            environment=app_models.AssetEnvironment.PRODUCTION,
            exposure=app_models.AssetExposure.INTERNET_FACING,
            criticality=app_models.AssetCriticality.CRITICAL,
        )
        identity_asset = asset_repo.upsert_asset(
            project_id=project_id,
            asset_key="identity-api",
            name="Identity API",
            owner="appsec",
            business_service="identity",
            environment=app_models.AssetEnvironment.PRODUCTION,
            exposure=app_models.AssetExposure.INTERNAL,
            criticality=app_models.AssetCriticality.HIGH,
        )
        component = create_component(session, repositories, name="openssl", version="3.0.0")
        _create_rollup_finding(
            app_models,
            finding_repo,
            project_id=project_id,
            asset_id=checkout_asset.id,
            component_id=component.id,
            cve_id="CVE-2026-6701",
            priority=app_models.FindingPriority.CRITICAL,
            priority_rank=1,
            operational_rank=1,
            risk_score=100.0,
            in_kev=True,
            attack_mapped=True,
        )
        _create_rollup_finding(
            app_models,
            finding_repo,
            project_id=project_id,
            asset_id=checkout_asset.id,
            component_id=component.id,
            cve_id="CVE-2026-6702",
            priority=app_models.FindingPriority.HIGH,
            priority_rank=2,
            operational_rank=2,
            risk_score=80.0,
            suppressed_by_vex=True,
            under_investigation=True,
        )
        _create_rollup_finding(
            app_models,
            finding_repo,
            project_id=project_id,
            asset_id=identity_asset.id,
            component_id=component.id,
            cve_id="CVE-2026-6703",
            priority=app_models.FindingPriority.MEDIUM,
            priority_rank=3,
            operational_rank=3,
            risk_score=30.0,
            status=app_models.FindingStatus.FIXED,
        )
        waiver_repo.create_project_waiver(
            project_id=project_id,
            waiver_in=app_models.WaiverCreate(
                service="checkout",
                owner="risk-team",
                reason="Review-due service acceptance for checkout risk.",
                expires_at=today + timedelta(days=7),
                review_at=today,
                approval_ref="CAB-067-A",
            ),
        )
        waiver_repo.create_project_waiver(
            project_id=project_id,
            waiver_in=app_models.WaiverCreate(
                cve_id="CVE-2026-6703",
                owner="legacy-risk",
                reason="Expired acceptance must remain visible as debt.",
                expires_at=today - timedelta(days=1),
                review_at=today - timedelta(days=2),
                approval_ref="CAB-067-B",
            ),
        )
        waiver_repo.sync_project_waivers(project_id)
        session.commit()


def _create_rollup_finding(
    app_models: Any,
    finding_repo: Any,
    *,
    project_id: uuid.UUID,
    asset_id: uuid.UUID,
    component_id: uuid.UUID,
    cve_id: str,
    priority: object,
    priority_rank: int,
    operational_rank: int,
    risk_score: float,
    status: object | None = None,
    in_kev: bool = False,
    attack_mapped: bool = False,
    suppressed_by_vex: bool = False,
    under_investigation: bool = False,
) -> None:
    vulnerability = finding_repo.upsert_vulnerability(cve_id=cve_id, source_id=cve_id)
    finding_repo.create_or_update_finding(
        project_id=project_id,
        vulnerability_id=vulnerability.id,
        component_id=component_id,
        asset_id=asset_id,
        cve_id=cve_id,
        dedup_key=f"vpw067:{cve_id}",
        priority=priority,
        priority_rank=priority_rank,
        operational_rank=operational_rank,
        risk_score=risk_score,
        status=status or app_models.FindingStatus.OPEN,
        in_kev=in_kev,
        attack_mapped=attack_mapped,
        suppressed_by_vex=suppressed_by_vex,
        under_investigation=under_investigation,
    )
