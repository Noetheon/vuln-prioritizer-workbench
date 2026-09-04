from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

from sqlmodel import Session
from utils.workbench_contracts import _seed_analysis_evidence, _seed_finding_evidence
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_component,
    create_project_via_api,
    local_api_headers,
)

from app.models.base import get_datetime_utc


def test_vpw067_governance_rollups_count_owner_service_environment_and_waiver_debt(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    _seed_vpw067_governance_graph(workbench_api_env, project_id)

    response = workbench_api_env.client.get(
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
    assert checkout["risk_score_total"] == 34.0
    assert checkout["risk_score_max"] == 34.0
    assert checkout["priority_counts"]["Critical"] == 1
    assert checkout["priority_counts"]["High"] == 1
    assert checkout["status_counts"]["accepted"] == 1
    assert checkout["status_counts"]["suppressed"] == 1
    assert checkout["suppressed_count"] == 1
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
    workbench_api_env: WorkbenchApiEnv,
    project_id: uuid.UUID,
) -> None:
    app_models = workbench_api_env.app_models
    repositories = workbench_api_env.repositories
    today = get_datetime_utc().date()
    with Session(workbench_api_env.engine) as session:
        asset_repo = repositories.AssetRepository(session)
        finding_repo = repositories.FindingRepository(session)
        run_repo = repositories.RunRepository(session)
        evidence_repo = repositories.EvidenceRepository(session)
        waiver_repo = repositories.WaiverRepository(session)
        snapshot = run_repo.get_or_create_provider_snapshot(
            content_hash="sha256:vpw067-governance",
            source_hashes_json={"provider_snapshot": "sha256:vpw067-governance"},
            source_metadata_json={"locked_provider_data": True},
        )
        run = run_repo.create_analysis_run(
            project_id=project_id,
            provider_snapshot_id=snapshot.id,
            input_type="generic-occurrence-csv",
            filename="vpw067-governance.csv",
            status=app_models.AnalysisRunStatus.COMPLETED,
        )
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
        first = _create_rollup_finding(
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
        second = _create_rollup_finding(
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
        third = _create_rollup_finding(
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
        evidence_items = [
            _rollup_finding_evidence(
                app_models,
                finding=first,
                run_id=run.id,
                project_id=project_id,
                asset_key=checkout_asset.asset_key,
                asset_name=checkout_asset.name or checkout_asset.asset_key,
                component_name=component.name,
                component_version=component.version or "",
                component_purl=component.purl,
                component_package_type=component.package_type or component.ecosystem,
                priority=app_models.FindingPriority.CRITICAL,
                priority_rank=1,
                operational_rank=1,
                risk_score=100.0,
                status=app_models.FindingStatus.ACCEPTED,
                in_kev=True,
                attack_mapped=True,
                waived=True,
            ),
            _rollup_finding_evidence(
                app_models,
                finding=second,
                run_id=run.id,
                project_id=project_id,
                asset_key=checkout_asset.asset_key,
                asset_name=checkout_asset.name or checkout_asset.asset_key,
                component_name=component.name,
                component_version=component.version or "",
                component_purl=component.purl,
                component_package_type=component.package_type or component.ecosystem,
                priority=app_models.FindingPriority.HIGH,
                priority_rank=2,
                operational_rank=2,
                risk_score=80.0,
                status=app_models.FindingStatus.ACCEPTED,
                suppressed_by_vex=True,
                under_investigation=True,
                waived=True,
            ),
            _rollup_finding_evidence(
                app_models,
                finding=third,
                run_id=run.id,
                project_id=project_id,
                asset_key=identity_asset.asset_key,
                asset_name=identity_asset.name or identity_asset.asset_key,
                component_name=component.name,
                component_version=component.version or "",
                component_purl=component.purl,
                component_package_type=component.package_type or component.ecosystem,
                priority=app_models.FindingPriority.MEDIUM,
                priority_rank=3,
                operational_rank=3,
                risk_score=30.0,
                status=app_models.FindingStatus.FIXED,
            ),
        ]
        analysis_evidence = evidence_repo.upsert_analysis_evidence(
            project_id=project_id,
            analysis_run_id=run.id,
            provider_snapshot_id=snapshot.id,
            evidence=_seed_analysis_evidence(
                project_id=project_id,
                run=run,
                provider_snapshot_id=snapshot.id,
                provider_snapshot_hash=snapshot.content_hash,
                finding_count=len(evidence_items),
                counts_by_priority={"Critical": 1, "High": 1, "Medium": 1},
                locked_provider_data=True,
                findings=evidence_items,
            ),
        )
        evidence_repo.replace_finding_decision_evidence(
            analysis_evidence_id=analysis_evidence.id,
            project_id=project_id,
            analysis_run_id=run.id,
            evidence_items=evidence_items,
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
) -> Any:
    vulnerability = finding_repo.upsert_vulnerability(cve_id=cve_id, source_id=cve_id)
    return finding_repo.create_or_update_finding(
        project_id=project_id,
        vulnerability_id=vulnerability.id,
        component_id=component_id,
        asset_id=asset_id,
        cve_id=cve_id,
        dedup_key=f"vpw067:{cve_id}",
        status=status or app_models.FindingStatus.OPEN,
    )


def _rollup_finding_evidence(
    app_models: Any,
    *,
    finding: Any,
    run_id: uuid.UUID,
    project_id: uuid.UUID,
    asset_key: str,
    asset_name: str,
    component_name: str,
    component_version: str,
    component_purl: str | None = None,
    component_package_type: str | None = None,
    priority: object,
    priority_rank: int,
    operational_rank: int,
    risk_score: float,
    status: object,
    in_kev: bool = False,
    attack_mapped: bool = False,
    suppressed_by_vex: bool = False,
    under_investigation: bool = False,
    waived: bool = False,
) -> Any:
    evidence = _seed_finding_evidence(
        finding=finding,
        analysis_run_id=run_id,
        project_id=project_id,
        asset_key=asset_key,
        asset_name=asset_name,
        component_name=component_name,
        component_version=component_version,
        component_purl=component_purl,
        component_package_type=component_package_type,
        priority=priority,
        priority_rank=priority_rank,
        risk_score=risk_score,
        operational_rank=operational_rank,
        epss=0.5,
        cvss=8.0,
        in_kev=in_kev,
        rationale=f"{finding.cve_id} governance rollup fixture.",
        action="Review governance evidence.",
        confidence="high",
        flags=[],
    )
    status_value = str(getattr(status, "value", status))
    return evidence.model_copy(
        update={
            "status": status_value,
            "attack_mapped": attack_mapped,
            "suppressed_by_vex": suppressed_by_vex,
            "under_investigation": under_investigation,
            "waived": waived,
            "governance": evidence.governance.model_copy(
                update={
                    "suppressed_by_vex": suppressed_by_vex,
                    "under_investigation": under_investigation,
                    "waived": waived,
                }
            ),
            "attack": evidence.attack.model_copy(update={"mapped": attack_mapped}),
        }
    )
