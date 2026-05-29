from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlmodel import Session
from utils.workbench_contracts import _create_report_via_worker
from utils.workbench_env import (
    DEMO_CVE_LOG4SHELL,
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
    seed_finding_pair,
)


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
    assert accepted["explanation_json"]["waiver_status"] == "active"
    assert accepted["explanation_json"]["waiver_owner"] == "risk-owner"

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
    assert "risk-owner" in csv_download.text
    assert "active" in csv_download.text

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
    assert expired_finding["explanation_json"]["waiver_status"] == "expired"
    assert expired_finding["explanation_json"]["waiver_owner"] == "service-risk"


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
    assert "waiver" not in finding_payload["evidence_json"]


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
        run_repo.add_finding_occurrence(
            finding_id=uuid.UUID(finding_id),
            analysis_run_id=run.id,
            source="generic-occurrence-csv",
            raw_reference=DEMO_CVE_LOG4SHELL,
        )
        session.commit()
        return str(run.id)
