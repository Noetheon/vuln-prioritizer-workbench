from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlmodel import Session, select
from utils.import_contracts import completed_run_payload, configure_upload_dir
from utils.workbench_contracts import (
    _create_report_via_worker,
    _seed_analysis_evidence,
    _seed_finding_evidence,
)
from utils.workbench_env import (
    DEMO_CVE_LOG4SHELL,
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
    seed_finding_pair,
)

from app.contracts.decision_evidence import OccurrenceEvidenceV2


def test_vpw064_workbench_waiver_lifecycle_and_report_visibility(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
    )
    finding_id = str(seeded["finding_ids"][0])
    finding = workbench_api_env.client.get(f"/api/v1/findings/{finding_id}", headers=headers).json()
    asset_id = finding["asset_id"]
    asset_update = workbench_api_env.client.patch(
        f"/api/v1/assets/{asset_id}",
        headers=headers,
        json={
            "asset_key": "payments-api",
            "name": "Payments API",
            "business_service": "checkout",
            "owner": "risk-team",
            "environment": "production",
            "exposure": "internet-facing",
            "criticality": "critical",
        },
    )
    assert asset_update.status_code == 200, asset_update.text

    created = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "cve_id": DEMO_CVE_LOG4SHELL,
            "owner": "risk-owner",
            "reason": "Temporary accepted risk while compensating controls are verified.",
            "expires_at": "2099-12-31",
            "review_at": "2099-12-01",
            "approval_ref": "CAB-064",
        },
    )
    assert created.status_code == 200, created.text
    waiver = created.json()
    assert waiver["status"] == "active"
    assert waiver["matched_findings"] == 1

    accepted_detail = workbench_api_env.client.get(
        f"/api/v1/findings/{finding_id}",
        headers=headers,
    )
    assert accepted_detail.status_code == 200
    accepted = accepted_detail.json()
    assert accepted["status"] == "accepted"
    assert accepted["waived"] is True
    assert "explanation_json" not in accepted

    run_id = _seed_report_run(
        workbench_api_env,
        project_id=uuid.UUID(project["id"]),
        finding_id=finding_id,
    )
    report = _create_report_via_worker(
        workbench_api_env,
        uuid.UUID(run_id),
        headers=headers,
        payload={"format": "csv"},
    )
    csv_download = workbench_api_env.client.get(report["download_url"], headers=headers)
    assert csv_download.status_code == 200
    assert "accepted" in csv_download.text
    assert "Accepted-risk governance remains visible." in csv_download.text

    updated = workbench_api_env.client.patch(
        f"/api/v1/waivers/{waiver['id']}",
        headers=headers,
        json={
            "service": "checkout",
            "owner": "service-risk",
            "reason": "Service-scoped accepted risk reviewed by the owner.",
            "expires_at": "2099-12-31",
            "review_at": "2099-12-01",
            "approval_ref": "CAB-065",
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["service"] == "checkout"
    assert updated.json()["matched_findings"] == 2

    expired = workbench_api_env.client.post(
        f"/api/v1/waivers/{waiver['id']}/expire",
        headers=headers,
    )
    assert expired.status_code == 200, expired.text
    assert expired.json()["status"] == "expired"
    assert expired.json()["matched_findings"] == 2

    expired_detail = workbench_api_env.client.get(
        f"/api/v1/findings/{finding_id}",
        headers=headers,
    )
    assert expired_detail.status_code == 200
    expired_finding = expired_detail.json()
    assert expired_finding["status"] == "open"
    assert expired_finding["waived"] is False
    assert "explanation_json" not in expired_finding


def test_vpw064_workbench_waiver_scopes_match_finding_cve_asset_and_service(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
    )
    finding_id = str(seeded["finding_ids"][0])
    finding = workbench_api_env.client.get(f"/api/v1/findings/{finding_id}", headers=headers).json()
    asset_id = finding["asset_id"]
    workbench_api_env.client.patch(
        f"/api/v1/assets/{asset_id}",
        headers=headers,
        json={
            "asset_key": "payments-api",
            "name": "Payments API",
            "business_service": "checkout",
        },
    )

    scoped_payloads: tuple[tuple[dict[str, Any], int], ...] = (
        ({"finding_id": finding_id, "owner": "finding-risk"}, 1),
        ({"cve_id": DEMO_CVE_LOG4SHELL, "owner": "cve-risk"}, 1),
        ({"asset_key": "payments-api", "owner": "asset-risk"}, 2),
        ({"service": "checkout", "owner": "service-risk"}, 2),
    )
    for payload, expected_matches in scoped_payloads:
        response = workbench_api_env.client.post(
            f"/api/v1/projects/{project['id']}/waivers/",
            headers=headers,
            json={
                **payload,
                "reason": f"Scope validation for {next(iter(payload))}.",
                "expires_at": "2099-12-31",
                "approval_ref": "CAB-SCOPE",
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["matched_findings"] == expected_matches

    listed = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
    )
    assert listed.status_code == 200
    assert listed.json()["count"] == 4


@pytest.mark.parametrize(
    ("waiver_scope", "asset_update"),
    [
        ({"service": "checkout", "owner": "service-risk"}, {"business_service": "identity"}),
        ({"asset_key": "payments-api", "owner": "asset-risk"}, {"asset_key": "renamed-api"}),
    ],
)
def test_workbench_asset_context_changes_resync_waiver_state(
    workbench_api_env: WorkbenchApiEnv,
    waiver_scope: dict[str, str],
    asset_update: dict[str, str],
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
    )
    finding_id = str(seeded["finding_ids"][0])
    finding = workbench_api_env.client.get(f"/api/v1/findings/{finding_id}", headers=headers).json()
    asset_id = finding["asset_id"]
    asset_seed = workbench_api_env.client.patch(
        f"/api/v1/assets/{asset_id}",
        headers=headers,
        json={"asset_key": "payments-api", "business_service": "checkout"},
    )
    assert asset_seed.status_code == 200, asset_seed.text

    created = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            **waiver_scope,
            "reason": "Scope should clear when asset context no longer matches.",
            "expires_at": "2099-12-31",
            "approval_ref": "CAB-ASSET-SYNC",
        },
    )
    assert created.status_code == 200, created.text
    assert (
        workbench_api_env.client.get(
            f"/api/v1/findings/{finding_id}",
            headers=headers,
        ).json()["waived"]
        is True
    )

    changed = workbench_api_env.client.patch(
        f"/api/v1/assets/{asset_id}",
        headers=headers,
        json=asset_update,
    )

    assert changed.status_code == 200, changed.text
    refreshed = workbench_api_env.client.get(f"/api/v1/findings/{finding_id}", headers=headers)
    assert refreshed.status_code == 200
    finding_payload = refreshed.json()
    assert finding_payload["status"] == "open"
    assert finding_payload["waived"] is False
    assert "evidence_json" not in finding_payload


def test_workbench_asset_context_import_resyncs_waiver_state(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
    )
    finding_id = str(seeded["finding_ids"][0])
    finding = workbench_api_env.client.get(f"/api/v1/findings/{finding_id}", headers=headers).json()
    asset_id = finding["asset_id"]
    asset_seed = workbench_api_env.client.patch(
        f"/api/v1/assets/{asset_id}",
        headers=headers,
        json={"asset_key": "payments-api", "business_service": "checkout"},
    )
    assert asset_seed.status_code == 200, asset_seed.text
    waiver = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "service": "checkout",
            "owner": "service-risk",
            "reason": "Import should clear this service scope.",
            "expires_at": "2099-12-31",
            "approval_ref": "CAB-ASSET-IMPORT-SYNC",
        },
    )
    assert waiver.status_code == 200, waiver.text

    context_csv = "\n".join(
        [
            "target_kind,target_ref,asset_id,business_service",
            "host,payments-api,payments-api,identity",
            "",
        ]
    ).encode()
    imported = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/assets/import",
        headers=headers,
        files={"asset_context_file": ("asset-context.csv", context_csv, "text/csv")},
    )

    assert imported.status_code == 200, imported.text
    refreshed = workbench_api_env.client.get(f"/api/v1/findings/{finding_id}", headers=headers)
    assert refreshed.status_code == 200
    assert refreshed.json()["status"] == "open"
    assert refreshed.json()["waived"] is False


def test_workbench_expired_waiver_sync_updates_v2_evidence_with_string_status(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Any,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    occurrence_csv = "\n".join(
        [
            "cve_id,asset_ref,component,version,business_service",
            f"{DEMO_CVE_LOG4SHELL},identity-api,log4j,2.14.1,checkout",
            "",
        ]
    ).encode()
    imported = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("waiver-evidence.csv", occurrence_csv, "text/csv")},
    )
    run_payload = completed_run_payload(workbench_api_env, imported, headers=headers)
    assert run_payload["evidence"]["analysis_evidence_id"]

    with Session(workbench_api_env.engine) as session:
        finding = session.exec(
            select(workbench_api_env.app_models.Finding).where(
                workbench_api_env.app_models.Finding.project_id == project_id,
                workbench_api_env.app_models.Finding.cve_id == DEMO_CVE_LOG4SHELL,
            )
        ).one()
        finding_id = finding.id
        finding.status = "open"
        session.add(finding)
        session.commit()

    expired = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "cve_id": DEMO_CVE_LOG4SHELL,
            "owner": "legacy-risk",
            "reason": "Expired waiver should still update typed evidence.",
            "expires_at": "2020-01-01",
            "review_at": "2019-12-31",
            "approval_ref": "CAB-STRING-STATUS",
        },
    )
    assert expired.status_code == 200, expired.text
    assert expired.json()["matched_findings"] == 1

    detail = workbench_api_env.client.get(f"/api/v1/findings/{finding_id}", headers=headers)
    assert detail.status_code == 200, detail.text
    assert detail.json()["status"] == "open"
    assert detail.json()["waived"] is False
    with Session(workbench_api_env.engine) as session:
        evidence = workbench_api_env.repositories.EvidenceRepository(
            session
        ).latest_finding_decision_evidence(finding_id)
        assert evidence is not None
        assert evidence.status == "open"
        assert evidence.governance.waived is False
        waiver_record = {
            **evidence.governance.waiver,
            **dict(evidence.priority_evidence.raw.get("waiver") or {}),
        }
        assert waiver_record["waiver_status"] == "expired"


def test_vpw064_workbench_waiver_validation_errors(workbench_api_env: WorkbenchApiEnv) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    missing_scope = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "owner": "risk",
            "reason": "No scope.",
            "expires_at": "2099-12-31",
        },
    )
    assert missing_scope.status_code == 422

    missing_expiry = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "cve_id": DEMO_CVE_LOG4SHELL,
            "owner": "risk",
            "reason": "Missing expiry.",
        },
    )
    assert missing_expiry.status_code == 422

    review_after_expiry = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "cve_id": DEMO_CVE_LOG4SHELL,
            "owner": "risk",
            "reason": "Bad review date.",
            "expires_at": "2099-01-01",
            "review_at": "2099-02-01",
        },
    )
    assert review_after_expiry.status_code == 422


def _seed_report_run(
    workbench_api_env: WorkbenchApiEnv,
    *,
    project_id: uuid.UUID,
    finding_id: str,
) -> str:
    with Session(workbench_api_env.engine) as session:
        run_repo = workbench_api_env.repositories.RunRepository(session)
        run = run_repo.create_analysis_run(
            project_id=project_id,
            input_type="generic-occurrence-csv",
            filename="waiver-report.csv",
            status=workbench_api_env.app_models.AnalysisRunStatus.COMPLETED,
            result_json={"parsed": 1, "findings": 1},
        )
        finding = session.get(workbench_api_env.app_models.Finding, uuid.UUID(finding_id))
        assert finding is not None
        occurrence = run_repo.add_finding_occurrence(
            finding_id=uuid.UUID(finding_id),
            analysis_run_id=run.id,
            source="generic-occurrence-csv",
            raw_reference=DEMO_CVE_LOG4SHELL,
        )
        finding_evidence = _seed_finding_evidence(
            finding=finding,
            analysis_run_id=run.id,
            project_id=project_id,
            asset_key=finding.asset.asset_key if finding.asset is not None else "payments-api",
            asset_name=finding.asset.name if finding.asset is not None else "Payments API",
            component_name=finding.component.name
            if finding.component is not None
            else "log4j-core",
            component_version=finding.component.version
            if finding.component is not None
            else "2.14.1",
            priority=finding.priority,
            priority_rank=finding.priority_rank,
            risk_score=finding.risk_score or 0.0,
            operational_rank=finding.operational_rank,
            epss=finding.epss or 0.0,
            cvss=finding.cvss_base_score or 0.0,
            in_kev=finding.in_kev,
            rationale=finding.rationale or "Accepted risk report seed.",
            action=finding.recommended_action or "Review accepted risk.",
            confidence="high",
            flags=[],
        )
        finding_evidence.occurrences.append(
            OccurrenceEvidenceV2(
                occurrence_id=str(occurrence.id),
                analysis_run_id=str(run.id),
                source="generic-occurrence-csv",
                raw_reference=DEMO_CVE_LOG4SHELL,
            )
        )
        evidence_repo = workbench_api_env.repositories.EvidenceRepository(session)
        analysis_evidence = evidence_repo.upsert_analysis_evidence(
            project_id=project_id,
            analysis_run_id=run.id,
            provider_snapshot_id=run.provider_snapshot_id,
            evidence=_seed_analysis_evidence(
                project_id=project_id,
                run=run,
                provider_snapshot_id=run.provider_snapshot_id,
                provider_snapshot_hash=None,
                finding_count=1,
                counts_by_priority={finding_evidence.priority_evidence.priority_label: 1},
                locked_provider_data=False,
                findings=[finding_evidence],
            ),
        )
        evidence_repo.replace_finding_decision_evidence(
            analysis_evidence_id=analysis_evidence.id,
            project_id=project_id,
            analysis_run_id=run.id,
            evidence_items=[finding_evidence],
        )
        session.commit()
        return str(run.id)
