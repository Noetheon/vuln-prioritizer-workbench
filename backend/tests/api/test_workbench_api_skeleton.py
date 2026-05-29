from __future__ import annotations

import json
import uuid
from dataclasses import replace
from datetime import timedelta
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlmodel import Session
from utils.workbench_env import (
    DEMO_CVE_LOG4SHELL,
    DEMO_CVE_XZ,
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
    seed_analysis_run,
    seed_finding_pair,
    seed_secondary_project_graph,
)

from app.main import app
from app.models.base import get_datetime_utc


def test_vpw011_openapi_exposes_workbench_domain_routes_without_items() -> None:
    client = TestClient(app)
    try:
        response = client.get("/api/v1/openapi.json")
        missing_items = client.get("/api/v1/items/")
    finally:
        client.close()

    assert response.status_code == 200
    payload = response.json()
    paths = set(payload["paths"])
    schemas = set(payload["components"]["schemas"])

    expected_paths = {
        "/api/v1/projects/",
        "/api/v1/projects/{project_id}",
        "/api/v1/projects/{project_id}/assets/",
        "/api/v1/assets/{asset_id}",
        "/api/v1/projects/{project_id}/imports",
        "/api/v1/providers/status",
        "/api/v1/projects/{project_id}/runs/",
        "/api/v1/runs/{run_id}",
        "/api/v1/runs/{run_id}/summary",
        "/api/v1/runs/{run_id}/report-jobs",
        "/api/v1/runs/{run_id}/reports",
        "/api/v1/workflows/{workflow_id}",
        "/api/v1/reports/{report_id}/download",
        "/api/v1/projects/{project_id}/findings/",
        "/api/v1/findings/{finding_id}",
        "/api/v1/findings/{finding_id}/explain",
        "/api/v1/projects/{project_id}/waivers/",
        "/api/v1/waivers/{waiver_id}",
        "/api/v1/waivers/{waiver_id}/expire",
        "/api/v1/projects/{project_id}/summary",
        "/api/v1/projects/{project_id}/dashboard",
        "/api/v1/projects/{project_id}/governance/rollups/",
        "/api/v1/projects/{project_id}/compare/cvss-only",
        "/api/v1/workbench/capabilities",
    }
    expected_schemas = {
        "AnalysisRunPublic",
        "AnalysisRunSummaryPublic",
        "AnalysisRunsPublic",
        "AssetCreate",
        "AssetPublic",
        "AssetsPublic",
        "AssetUpdate",
        "AttackSourceCapabilityPublic",
        "DashboardEpssBucketsPublic",
        "DashboardSignalCountsPublic",
        "FindingPublic",
        "FindingExplanationPublic",
        "FindingsPublic",
        "GovernanceRollupPublic",
        "GovernanceWaiverDebtEntryPublic",
        "GovernanceWaiverDebtPublic",
        "ImportFormatCapabilityPublic",
        "RunParseErrorV2",
        "ProjectCreate",
        "ProjectCvssOnlyComparisonPublic",
        "ProjectDashboardFindingsPublic",
        "ProjectDashboardPublic",
        "ProjectDecisionSummaryPublic",
        "ProjectGovernanceRollupsPublic",
        "ProjectPublic",
        "ProjectsPublic",
        "ProjectUpdate",
        "ProviderSnapshotStatusPublic",
        "ProviderSourceStatusPublic",
        "ProviderStatusPublic",
        "ReportCreate",
        "ReportFormatCapabilityPublic",
        "ReportPublic",
        "ReportsPublic",
        "SidecarUploadCapabilityPublic",
        "UploadPolicyPublic",
        "WaiverCreate",
        "WaiverPublic",
        "WaiversPublic",
        "WaiverUpdate",
        "WorkbenchCapabilitiesPublic",
    }
    assert expected_paths.issubset(paths)

    assert all("/items" not in path for path in paths)
    assert missing_items.status_code == 404
    assert expected_schemas.issubset(schemas)
    assert all("Item" not in schema_name for schema_name in schemas)
    for schema_name in ("AnalysisRunPublic", "AnalysisRunSummaryPublic"):
        properties = payload["components"]["schemas"][schema_name]["properties"]
        assert "summary_json" not in properties
        assert "error_json" not in properties


def test_workbench_capabilities_contract_is_redacted(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    response = workbench_api_env.client.get(
        "/api/v1/workbench/capabilities",
        headers=local_api_headers(workbench_api_env.client),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["schema_version"] == "workbench-capabilities.v1"
    assert len(payload["import_formats"]) == 10
    assert len(payload["report_formats"]) == 7
    assert payload["upload_policy"]["max_upload_bytes"] > 0
    serialized = json.dumps(payload)
    assert "/Users/" not in serialized
    assert "/private/" not in serialized
    assert "SECRET" not in serialized.upper()
    assert "TOKEN" not in serialized.upper()
    assert "PASSWORD" not in serialized.upper()


def test_vpw011_domain_routes_do_not_require_auth_in_local_runtime(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    project_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    run_id = uuid.uuid4()
    finding_id = uuid.uuid4()

    protected_calls: tuple[tuple[str, str, dict[str, Any]], ...] = (
        ("get", "/api/v1/projects/", {}),
        ("post", "/api/v1/projects/", {"json": {"name": "Unauthenticated Project"}}),
        ("get", f"/api/v1/projects/{project_id}", {}),
        ("patch", f"/api/v1/projects/{project_id}", {"json": {"name": "Updated"}}),
        ("delete", f"/api/v1/projects/{project_id}", {}),
        ("get", f"/api/v1/projects/{project_id}/assets/", {}),
        (
            "post",
            f"/api/v1/projects/{project_id}/assets/",
            {
                "json": {
                    "asset_key": "payments-api",
                    "name": "Payments API",
                }
            },
        ),
        ("patch", f"/api/v1/assets/{asset_id}", {"json": {"name": "Renamed API"}}),
        ("get", f"/api/v1/projects/{project_id}/runs/", {}),
        ("get", f"/api/v1/projects/{project_id}/runs", {}),
        (
            "post",
            f"/api/v1/projects/{project_id}/imports",
            {
                "data": {"input_type": "cve-list"},
                "files": {"file": ("sample.txt", b"CVE-2024-3094\n", "text/plain")},
            },
        ),
        ("get", "/api/v1/providers/status", {}),
        ("get", f"/api/v1/runs/{run_id}", {}),
        ("get", f"/api/v1/runs/{run_id}/summary", {}),
        ("get", f"/api/v1/runs/{run_id}/workflow-metadata", {}),
        ("get", f"/api/v1/runs/{run_id}/reports", {}),
        ("post", f"/api/v1/runs/{run_id}/reports", {"json": {"format": "markdown"}}),
        ("get", f"/api/v1/reports/{run_id}/download", {}),
        (
            "get",
            f"/api/v1/projects/{project_id}/findings/",
            {"params": {"limit": 1, "offset": 0}},
        ),
        ("get", f"/api/v1/findings/{finding_id}", {}),
        ("get", f"/api/v1/findings/{finding_id}/explain", {}),
        ("get", f"/api/v1/projects/{project_id}/waivers/", {}),
        (
            "post",
            f"/api/v1/projects/{project_id}/waivers/",
            {
                "json": {
                    "cve_id": "CVE-2024-3094",
                    "owner": "risk",
                    "reason": "Auth check.",
                    "expires_at": "2099-12-31",
                }
            },
        ),
        (
            "patch",
            f"/api/v1/waivers/{finding_id}",
            {
                "json": {
                    "cve_id": "CVE-2024-3094",
                    "owner": "risk",
                    "reason": "Auth check.",
                    "expires_at": "2099-12-31",
                }
            },
        ),
        ("post", f"/api/v1/waivers/{finding_id}/expire", {}),
        ("get", f"/api/v1/projects/{project_id}/summary", {}),
        ("get", f"/api/v1/projects/{project_id}/dashboard", {}),
        ("get", f"/api/v1/projects/{project_id}/governance/rollups/", {}),
        ("get", f"/api/v1/projects/{project_id}/compare/cvss-only", {}),
        ("get", "/api/v1/workbench/capabilities", {}),
    )

    for method, path, kwargs in protected_calls:
        response = getattr(workbench_api_env.client, method)(path, **kwargs)
        assert response.status_code != 401, f"{method.upper()} {path}: {response.text}"


def test_vpw011_project_lifecycle_create_list_get_update_delete(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)

    create_response = workbench_api_env.client.post(
        "/api/v1/projects/",
        headers=headers,
        json={
            "name": "External Attack Surface",
            "description": "Internet-facing CVE prioritization workspace.",
        },
    )
    assert create_response.status_code == 200
    created = create_response.json()
    assert created["name"] == "External Attack Surface"
    assert created["description"] == "Internet-facing CVE prioritization workspace."
    assert "owner_id" not in created

    list_response = workbench_api_env.client.get("/api/v1/projects/", headers=headers)
    assert list_response.status_code == 200
    assert list_response.json()["data"] == [created]
    assert list_response.json()["count"] == 1

    get_response = workbench_api_env.client.get(
        f"/api/v1/projects/{created['id']}", headers=headers
    )
    assert get_response.status_code == 200
    assert get_response.json() == created

    update_response = workbench_api_env.client.patch(
        f"/api/v1/projects/{created['id']}",
        headers=headers,
        json={
            "name": "External Attack Surface Updated",
            "description": "Updated Workbench project description.",
        },
    )
    assert update_response.status_code == 200
    updated = update_response.json()
    assert updated["id"] == created["id"]
    assert "owner_id" not in updated
    assert updated["name"] == "External Attack Surface Updated"
    assert updated["description"] == "Updated Workbench project description."

    delete_response = workbench_api_env.client.delete(
        f"/api/v1/projects/{created['id']}",
        headers=headers,
    )
    assert delete_response.status_code == 204

    missing_after_delete = workbench_api_env.client.get(
        f"/api/v1/projects/{created['id']}",
        headers=headers,
    )
    assert missing_after_delete.status_code == 404
    assert workbench_api_env.client.get("/api/v1/projects/", headers=headers).json() == {
        "data": [],
        "count": 0,
    }


def test_vpw011_asset_list_create_and_update(workbench_api_env: WorkbenchApiEnv) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    create_response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
        json={
            "asset_key": "payments-api",
            "name": "Payments API",
            "target_ref": "registry.example.test/payments-api:2026.04.28",
            "owner": "platform",
            "business_service": "payments",
            "environment": "production",
            "exposure": "internet-facing",
            "criticality": "critical",
        },
    )
    assert create_response.status_code == 200
    created = create_response.json()
    assert created["project_id"] == project["id"]
    assert created["asset_key"] == "payments-api"
    assert created["name"] == "Payments API"
    assert created["environment"] == "production"
    assert created["exposure"] == "internet-facing"
    assert created["criticality"] == "critical"

    list_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
    )
    assert list_response.status_code == 200
    assert list_response.json()["data"] == [created]
    assert list_response.json()["count"] == 1

    update_asset_response = workbench_api_env.client.patch(
        f"/api/v1/assets/{created['id']}",
        headers=headers,
        json={"name": "Payments API Cluster", "criticality": "high"},
    )
    assert update_asset_response.status_code == 200
    updated = update_asset_response.json()
    assert updated["id"] == created["id"]
    assert updated["project_id"] == project["id"]
    assert updated["name"] == "Payments API Cluster"
    assert updated["criticality"] == "high"


def test_vpw011_run_list_and_get_use_repository_seeded_graph(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    seeded = seed_analysis_run(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
    )

    list_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/runs",
        headers=headers,
    )
    assert list_response.status_code == 200
    list_payload = list_response.json()
    assert list_payload["count"] == 1
    assert list_payload["data"][0]["id"] == str(seeded["run_id"])
    assert list_payload["data"][0]["project_id"] == project["id"]
    assert list_payload["data"][0]["status"] == "completed"

    get_response = workbench_api_env.client.get(f"/api/v1/runs/{seeded['run_id']}", headers=headers)
    assert get_response.status_code == 200
    detail = get_response.json()
    assert detail["id"] == str(seeded["run_id"])
    assert detail["provider_snapshot_id"] == str(seeded["provider_snapshot_id"])
    assert detail["workflow"]["status"] == "succeeded"
    assert "result" not in detail
    assert detail["evidence"] is None
    assert detail["diagnostics"] is None
    assert detail["counts"]["created_findings"] == 0
    assert "workflow_schema_version" not in detail
    assert "summary_json" not in detail
    assert "error_json" not in detail

    summary_response = workbench_api_env.client.get(
        f"/api/v1/runs/{seeded['run_id']}/summary",
        headers=headers,
    )
    assert summary_response.status_code == 200
    summary = summary_response.json()
    assert summary["id"] == str(seeded["run_id"])
    assert summary["project_id"] == project["id"]
    assert summary["status"] == "completed"
    assert summary["created_findings"] == 0
    assert summary["updated_findings"] == 0
    assert summary["parse_errors"] == []
    assert summary["workflow"]["status"] == "succeeded"
    assert "result" not in summary
    assert summary["evidence"] is None
    assert summary["diagnostics"] is None
    assert "workflow_schema_version" not in summary
    assert "summary_json" not in summary
    assert "error_json" not in summary

    metadata_response = workbench_api_env.client.get(
        f"/api/v1/runs/{seeded['run_id']}/workflow-metadata",
        headers=headers,
    )
    assert metadata_response.status_code == 404


def test_run_workflow_metadata_endpoint_redacts_raw_diagnostics(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Any,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    seeded = seed_analysis_run(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
    )
    private_upload = tmp_path / "private-upload.csv"
    private_log = tmp_path / "private-error.log"
    with Session(workbench_api_env.engine) as session:
        run = session.get(workbench_api_env.app_models.AnalysisRun, seeded["run_id"])
        assert run is not None
        workflow = workbench_api_env.repositories.WorkflowRepository(
            session
        ).get_latest_analysis_workflow(
            analysis_run_id=run.id,
            kind=workbench_api_env.app_models.WorkflowRunKind.IMPORT,
        )
        assert workflow is not None
        workflow.result_json = {
            "created_findings": 0,
            "updated_findings": 0,
            "input_upload": {
                "input_type": "cve-list",
                "path": str(private_upload),
                "sha256": "abc123",
            },
            "token": "Bearer summary-secret-token",
        }
        workflow.diagnostics_json = {
            "analysis_error": {
                "stage": "import",
                "message": f"failed at {private_log}",
                "error_type": "RuntimeError",
            },
            "authorization": "Bearer error-secret-token",
        }
        session.add(workflow)
        session.commit()

    response = workbench_api_env.client.get(
        f"/api/v1/runs/{seeded['run_id']}",
        headers=headers,
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    serialized = json.dumps(payload)
    assert str(tmp_path) not in serialized
    assert "summary-secret-token" not in serialized
    assert "error-secret-token" not in serialized
    assert "result" not in payload
    assert payload["evidence"] is None
    assert payload["diagnostics"]["analysis_error"]["message"] == "[REDACTED]"
    assert "raw_summary" not in payload
    assert "raw_error" not in payload


def test_run_workflow_metadata_endpoint_returns_404_for_unknown_run(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    missing_run_id = uuid.UUID("00000000-0000-4000-8000-000000000404")

    response = workbench_api_env.client.get(
        f"/api/v1/runs/{missing_run_id}/workflow-metadata",
        headers=headers,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Not Found"


def test_vpw011_finding_list_and_get_support_pagination(
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

    list_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
        params={"limit": 1, "offset": 1},
    )
    assert list_response.status_code == 200
    page = list_response.json()
    assert page["count"] == 2
    assert len(page["data"]) == 1
    assert page["data"][0]["id"] == str(seeded["finding_ids"][1])
    assert page["data"][0]["cve_id"] == DEMO_CVE_XZ

    get_response = workbench_api_env.client.get(
        f"/api/v1/findings/{seeded['finding_ids'][0]}",
        headers=headers,
    )
    assert get_response.status_code == 200
    detail = get_response.json()
    assert detail["id"] == str(seeded["finding_ids"][0])
    assert detail["project_id"] == project["id"]
    assert detail["cve_id"] == DEMO_CVE_LOG4SHELL
    assert detail["priority"] == "critical"
    assert detail["in_kev"] is True


def test_vpw011_finding_public_payloads_redact_raw_json_fields(
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
    finding_id = seeded["finding_ids"][0]

    list_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    detail_response = workbench_api_env.client.get(
        f"/api/v1/findings/{finding_id}",
        headers=headers,
    )

    assert list_response.status_code == 200, list_response.text
    assert detail_response.status_code == 200, detail_response.text
    for response in (list_response, detail_response):
        payload_text = response.text
        assert "/Users/alice" not in payload_text
        assert "/tmp/provider-cache.json" not in payload_text
        assert "super-secret-password" not in payload_text
        assert "imported-secret-token" not in payload_text
        assert "nvd-secret-key" not in payload_text

    public_finding = next(
        item for item in list_response.json()["data"] if item["id"] == str(finding_id)
    )
    assert "explanation_json" not in public_finding
    assert "data_quality_json" not in public_finding
    assert "evidence_json" not in public_finding


def test_vpw042_findings_list_filters_and_display_fields(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    seeded = _seed_vpw042_findings(workbench_api_env, uuid.UUID(project["id"]))

    list_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
        params={"priority": "critical"},
    )
    assert list_response.status_code == 200, list_response.text
    critical_page = list_response.json()
    assert critical_page["count"] == 1
    critical = critical_page["data"][0]
    assert critical["id"] == str(seeded["critical"])
    assert critical["component_name"] == "log4j-core"
    assert critical["component_version"] == "2.14.1"
    assert critical["component_purl"].startswith("pkg:maven/")
    assert critical["asset_name"] == "Payments API"
    assert critical["asset_key"] == "payments-api"
    assert critical["asset_target_ref"] == "registry.example.test/payments-api:2026.04.28"
    assert critical["asset_environment"] == "production"
    assert critical["asset_criticality"] == "critical"
    assert critical["owner"] == "platform"
    assert critical["business_service"] == "payments"
    assert critical["exposure"] == "internet-facing"

    assert _finding_cves(workbench_api_env, project, headers, {"status": "suppressed"}) == [
        "CVE-2024-4577"
    ]
    assert _finding_cves(workbench_api_env, project, headers, {"kev": "true"}) == [
        DEMO_CVE_LOG4SHELL
    ]
    assert _finding_cves(workbench_api_env, project, headers, {"owner": "platform"}) == [
        DEMO_CVE_LOG4SHELL
    ]
    assert _finding_cves(workbench_api_env, project, headers, {"service": "identity"}) == [
        "CVE-2022-22965"
    ]
    assert _finding_cves(workbench_api_env, project, headers, {"owner_service": "payments"}) == [
        DEMO_CVE_LOG4SHELL
    ]
    assert _finding_cves(workbench_api_env, project, headers, {"q": "spring-webmvc"}) == [
        "CVE-2022-22965"
    ]
    assert _finding_cves(workbench_api_env, project, headers, {"q": "edge-worker"}) == [
        "CVE-2024-4577"
    ]
    assert _finding_cves(workbench_api_env, project, headers, {"q": DEMO_CVE_LOG4SHELL}) == [
        DEMO_CVE_LOG4SHELL
    ]
    assert _finding_cves(
        workbench_api_env,
        project,
        headers,
        {"asset_id": str(seeded["critical_asset"])},
    ) == [DEMO_CVE_LOG4SHELL]
    assert _finding_cves(workbench_api_env, project, headers, {"exposure": "internal"}) == [
        "CVE-2022-22965"
    ]
    assert _finding_cves(
        workbench_api_env,
        project,
        headers,
        {"epss_min": "0.40", "epss_max": "0.50"},
    ) == ["CVE-2024-4577"]
    assert _finding_cves(
        workbench_api_env,
        project,
        headers,
        {"cvss_min": "8.0", "cvss_max": "9.0"},
    ) == ["CVE-2022-22965"]

    detail_response = workbench_api_env.client.get(
        f"/api/v1/findings/{seeded['critical']}",
        headers=headers,
    )
    assert detail_response.status_code == 200, detail_response.text
    detail = detail_response.json()
    assert detail["component_name"] == "log4j-core"
    assert detail["asset_key"] == "payments-api"
    assert detail["asset_target_ref"] == "registry.example.test/payments-api:2026.04.28"
    assert detail["asset_environment"] == "production"
    assert detail["asset_criticality"] == "critical"
    assert detail["owner"] == "platform"
    assert detail["business_service"] == "payments"
    assert detail["exposure"] == "internet-facing"
    assert len(detail["occurrences"]) == 1
    occurrence = detail["occurrences"][0]
    assert occurrence["source"] == "generic-occurrence-csv"
    assert occurrence["source_format"] == "generic-occurrence-csv"
    assert occurrence["source_id"] == DEMO_CVE_LOG4SHELL
    assert occurrence["source_record_id"] == "row:2"
    assert occurrence["component_name"] == "log4j-core"
    assert occurrence["component_version"] == "2.14.1"
    assert occurrence["purl"] == detail["component_purl"]
    assert occurrence["fix_versions"] == ["2.17.1", "2.17.2"]
    assert occurrence["target_kind"] == "container"
    assert occurrence["target_ref"] == "registry.example.test/payments-api:2026.04.28"
    assert occurrence["asset_ref"] == "payments-api"
    assert occurrence["asset_owner"] == "platform"
    assert occurrence["asset_business_service"] == "payments"
    assert occurrence["asset_exposure"] == "internet-facing"
    assert occurrence["raw_severity"] == "CRITICAL"

    invalid_exposure = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
        params={"exposure": "public"},
    )
    assert invalid_exposure.status_code == 422


def test_vpw044_asset_edit_rescore_flag_is_merged_into_explain(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    seeded = _seed_vpw042_findings(workbench_api_env, uuid.UUID(project["id"]))

    update_response = workbench_api_env.client.patch(
        f"/api/v1/assets/{seeded['critical_asset']}",
        headers=headers,
        json={"criticality": "high"},
    )
    assert update_response.status_code == 200, update_response.text

    explain_response = workbench_api_env.client.get(
        f"/api/v1/findings/{seeded['critical']}/explain",
        headers=headers,
    )
    assert explain_response.status_code == 422, explain_response.text


def test_asset_post_upsert_marks_existing_asset_findings_for_rescore(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    seeded = _seed_vpw042_findings(workbench_api_env, uuid.UUID(project["id"]))

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
        json={
            "asset_key": "payments-api",
            "name": "Payments API",
            "target_ref": "registry.example.test/payments-api:2026.04.28",
            "owner": "platform",
            "business_service": "payments",
            "environment": "production",
            "exposure": "internal",
            "criticality": "high",
        },
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["id"] == str(seeded["critical_asset"])
    assert payload["rescore_needed"] is False


def test_vpw063_asset_filters_and_recalculate_action_clear_rescore_flag(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    seeded = _seed_vpw042_findings(workbench_api_env, uuid.UUID(project["id"]))

    owner_filtered = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
        params={"owner": "platform"},
    )
    assert owner_filtered.status_code == 200, owner_filtered.text
    assert owner_filtered.json()["count"] == 1
    assert owner_filtered.json()["data"][0]["asset_key"] == "payments-api"

    service_filtered = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
        params={"service": "identity"},
    )
    assert service_filtered.status_code == 200, service_filtered.text
    assert service_filtered.json()["count"] == 1
    assert service_filtered.json()["data"][0]["asset_key"] == "identity-api"

    update_response = workbench_api_env.client.patch(
        f"/api/v1/assets/{seeded['critical_asset']}",
        headers=headers,
        json={"criticality": "high"},
    )
    assert update_response.status_code == 200, update_response.text
    assert update_response.json()["rescore_needed"] is False

    recalculate_response = workbench_api_env.client.post(
        f"/api/v1/assets/{seeded['critical_asset']}/recalculate",
        headers=headers,
    )
    assert recalculate_response.status_code == 200, recalculate_response.text
    recalculated = recalculate_response.json()
    assert recalculated["asset_id"] == str(seeded["critical_asset"])
    assert recalculated["asset_key"] == "payments-api"
    assert recalculated["recalculated_findings"] == 1
    assert recalculated["cleared_rescore_flags"] == 0
    assert recalculated["operational_scores"] == [99]
    assert recalculated["rescore_needed"] is False

    asset_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
        params={"owner": "platform"},
    )
    assert asset_response.status_code == 200
    assert asset_response.json()["data"][0]["rescore_needed"] is False

    explain_response = workbench_api_env.client.get(
        f"/api/v1/findings/{seeded['critical']}/explain",
        headers=headers,
    )
    assert explain_response.status_code == 422, explain_response.text


def test_vpw063_asset_context_import_endpoint_upserts_assets_and_marks_rescore(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    seeded = _seed_vpw042_findings(workbench_api_env, uuid.UUID(project["id"]))
    context_csv = "\n".join(
        [
            (
                "target_kind,target_ref,asset_id,owner,business_service,"
                "criticality,exposure,environment"
            ),
            "container,registry.example.test/payments-api:2026.04.28,payments-api,platform,payments,high,internal,prod",
            "host,batch-01,batch-worker,data,batch,medium,private,staging",
            "",
        ]
    ).encode()

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/assets/import",
        headers=headers,
        files={"asset_context_file": ("asset-context.csv", context_csv, "text/csv")},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["project_id"] == project["id"]
    assert payload["imported_assets"] == 2
    assert payload["created_assets"] == 1
    assert payload["updated_assets"] == 1
    assert payload["unchanged_assets"] == 0
    assert payload["rescore_needed_findings"] == 1
    assert payload["asset_keys"] == ["payments-api", "batch-worker"]

    assets = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
        params={"owner": "data"},
    )
    assert assets.status_code == 200
    assert assets.json()["data"][0]["asset_key"] == "batch-worker"

    updated = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
        params={"owner": "platform"},
    )
    assert updated.status_code == 200
    payments_asset = next(
        item for item in updated.json()["data"] if item["id"] == str(seeded["critical_asset"])
    )
    assert payments_asset["criticality"] == "high"
    assert payments_asset["exposure"] == "internal"
    assert payments_asset["rescore_needed"] is False

    explain_response = workbench_api_env.client.get(
        f"/api/v1/findings/{seeded['critical']}/explain",
        headers=headers,
    )
    assert explain_response.status_code == 422, explain_response.text


def test_vpw042_findings_sort_direction_and_pagination(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    _seed_vpw042_findings(workbench_api_env, uuid.UUID(project["id"]))

    score_page = _finding_cves(
        workbench_api_env,
        project,
        headers,
        {"sort": "score", "direction": "desc", "limit": "2", "offset": "1"},
    )
    assert score_page == ["CVE-2022-22965", "CVE-2024-4577"]
    assert _finding_cves(
        workbench_api_env,
        project,
        headers,
        {"sort": "epss", "direction": "desc"},
    ) == [DEMO_CVE_LOG4SHELL, "CVE-2024-4577", "CVE-2022-22965"]
    assert _finding_cves(
        workbench_api_env,
        project,
        headers,
        {"sort": "cvss", "direction": "asc"},
    ) == ["CVE-2024-4577", "CVE-2022-22965", DEMO_CVE_LOG4SHELL]
    assert (
        _finding_cves(
            workbench_api_env,
            project,
            headers,
            {"sort": "kev", "direction": "desc"},
        )[0]
        == DEMO_CVE_LOG4SHELL
    )
    assert _finding_cves(
        workbench_api_env,
        project,
        headers,
        {"sort": "last_seen", "direction": "desc"},
    ) == [DEMO_CVE_LOG4SHELL, "CVE-2022-22965", "CVE-2024-4577"]
    assert _finding_cves(
        workbench_api_env,
        project,
        headers,
        {"sort": "component", "direction": "asc"},
    ) == [DEMO_CVE_LOG4SHELL, "CVE-2024-4577", "CVE-2022-22965"]
    assert _finding_cves(
        workbench_api_env,
        project,
        headers,
        {"sort": "owner", "direction": "asc"},
    ) == ["CVE-2022-22965", DEMO_CVE_LOG4SHELL, "CVE-2024-4577"]
    assert _finding_cves(
        workbench_api_env,
        project,
        headers,
        {"sort": "owner", "direction": "desc"},
    ) == ["CVE-2024-4577", DEMO_CVE_LOG4SHELL, "CVE-2022-22965"]


def test_vpw042_findings_page_eager_loads_asset_and_component(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    _seed_vpw042_findings(workbench_api_env, uuid.UUID(project["id"]))
    select_statements: list[str] = []

    def capture_select(
        _conn: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        if statement.lstrip().lower().startswith("select"):
            select_statements.append(statement)

    event.listen(workbench_api_env.engine, "before_cursor_execute", capture_select)
    try:
        with Session(workbench_api_env.engine) as session:
            findings, count = workbench_api_env.repositories.FindingRepository(
                session
            ).list_project_findings_page(
                uuid.UUID(project["id"]),
                limit=3,
            )
            assert count == 3
            assert len(findings) == 3
            assert all(finding.asset is not None for finding in findings)
            assert all(finding.component is not None for finding in findings)
    finally:
        event.remove(workbench_api_env.engine, "before_cursor_execute", capture_select)

    assert len(select_statements) <= 4


def _finding_cves(
    workbench_api_env: WorkbenchApiEnv,
    project: dict[str, Any],
    headers: dict[str, str],
    params: dict[str, str],
) -> list[str]:
    response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
        params=params,
    )
    assert response.status_code == 200, response.text
    return [item["cve_id"] for item in response.json()["data"]]


def _seed_vpw042_findings(
    workbench_api_env: WorkbenchApiEnv,
    project_id: uuid.UUID,
) -> dict[str, uuid.UUID]:
    """Seed deterministic findings with distinct filter and sort dimensions."""
    app_models = workbench_api_env.app_models
    repositories = workbench_api_env.repositories
    now = get_datetime_utc()
    with Session(workbench_api_env.engine) as session:
        asset_repo = repositories.AssetRepository(session)
        finding_repo = repositories.FindingRepository(session)
        critical_asset = asset_repo.upsert_asset(
            project_id=project_id,
            asset_key="payments-api",
            name="Payments API",
            target_ref="registry.example.test/payments-api:2026.04.28",
            owner="platform",
            business_service="payments",
            environment=app_models.AssetEnvironment.PRODUCTION,
            exposure=app_models.AssetExposure.INTERNET_FACING,
            criticality=app_models.AssetCriticality.CRITICAL,
        )
        high_asset = asset_repo.upsert_asset(
            project_id=project_id,
            asset_key="identity-api",
            name="Identity API",
            target_ref="registry.example.test/identity-api:2026.04.28",
            owner="appsec",
            business_service="identity",
            environment=app_models.AssetEnvironment.PRODUCTION,
            exposure=app_models.AssetExposure.INTERNAL,
            criticality=app_models.AssetCriticality.HIGH,
        )
        medium_asset = asset_repo.upsert_asset(
            project_id=project_id,
            asset_key="edge-worker",
            name="Edge Worker",
            target_ref="edge-worker",
            owner="web",
            business_service="edge",
            environment=app_models.AssetEnvironment.STAGING,
            exposure=app_models.AssetExposure.PRIVATE,
            criticality=app_models.AssetCriticality.MEDIUM,
        )
        critical_component = finding_repo.upsert_component(
            name="log4j-core",
            version="2.14.1",
            purl=f"pkg:maven/org.apache.logging.log4j/log4j-core@{uuid.uuid4().hex}",
            ecosystem="maven",
        )
        high_component = finding_repo.upsert_component(
            name="spring-webmvc",
            version="5.3.17",
            purl=f"pkg:maven/org.springframework/spring-webmvc@{uuid.uuid4().hex}",
            ecosystem="maven",
        )
        medium_component = finding_repo.upsert_component(
            name="php-cgi",
            version="8.3.7",
            purl=f"pkg:deb/debian/php-cgi@{uuid.uuid4().hex}",
            ecosystem="deb",
        )
        critical_vulnerability = finding_repo.upsert_vulnerability(
            cve_id=DEMO_CVE_LOG4SHELL,
            source_id=DEMO_CVE_LOG4SHELL,
            cvss_score=10.0,
            severity="CRITICAL",
        )
        high_vulnerability = finding_repo.upsert_vulnerability(
            cve_id="CVE-2022-22965",
            source_id="CVE-2022-22965",
            cvss_score=8.1,
            severity="HIGH",
        )
        medium_vulnerability = finding_repo.upsert_vulnerability(
            cve_id="CVE-2024-4577",
            source_id="CVE-2024-4577",
            cvss_score=6.1,
            severity="MEDIUM",
        )
        critical = finding_repo.create_or_update_finding(
            project_id=project_id,
            vulnerability_id=critical_vulnerability.id,
            component_id=critical_component.id,
            asset_id=critical_asset.id,
            cve_id=DEMO_CVE_LOG4SHELL,
            priority=app_models.FindingPriority.CRITICAL,
            status=app_models.FindingStatus.OPEN,
            priority_rank=1,
            risk_score=99.0,
            operational_rank=1,
            in_kev=True,
            epss=0.95,
            cvss_base_score=10.0,
            explanation_json={
                "priority_state": "Critical",
                "explanation": {
                    "reason_codes": ["kev_catalog_match"],
                    "score_inputs": {"kev": True, "epss": 0.95, "cvss": 10.0},
                },
                "data_quality_flags": [
                    {
                        "source": "provider",
                        "code": "provider_snapshot_stale",
                        "severity": "info",
                    }
                ],
            },
        )
        high = finding_repo.create_or_update_finding(
            project_id=project_id,
            vulnerability_id=high_vulnerability.id,
            component_id=high_component.id,
            asset_id=high_asset.id,
            cve_id="CVE-2022-22965",
            priority=app_models.FindingPriority.HIGH,
            status=app_models.FindingStatus.FIXED,
            priority_rank=2,
            risk_score=88.0,
            operational_rank=2,
            in_kev=False,
            epss=0.23,
            cvss_base_score=8.1,
        )
        medium = finding_repo.create_or_update_finding(
            project_id=project_id,
            vulnerability_id=medium_vulnerability.id,
            component_id=medium_component.id,
            asset_id=medium_asset.id,
            cve_id="CVE-2024-4577",
            priority=app_models.FindingPriority.MEDIUM,
            status=app_models.FindingStatus.SUPPRESSED,
            priority_rank=3,
            risk_score=42.0,
            operational_rank=3,
            in_kev=False,
            epss=0.44,
            cvss_base_score=6.1,
        )
        run = repositories.RunRepository(session).create_analysis_run(
            project_id=project_id,
            input_type="generic-occurrence-csv",
            filename="occurrences.csv",
            status=app_models.AnalysisRunStatus.COMPLETED,
        )
        repositories.RunRepository(session).add_finding_occurrence(
            finding_id=critical.id,
            analysis_run_id=run.id,
            source="generic-occurrence-csv",
            scanner="trivy",
            raw_reference="row:2",
            fix_version="2.17.1",
            evidence_json={
                "source_format": "generic-occurrence-csv",
                "source_id": DEMO_CVE_LOG4SHELL,
                "source_record_id": "row:2",
                "component_name": "log4j-core",
                "component_version": "2.14.1",
                "purl": critical_component.purl,
                "fix_versions": ["2.17.1", "2.17.2"],
                "target_kind": "container",
                "target_ref": "registry.example.test/payments-api:2026.04.28",
                "asset_ref": "payments-api",
                "asset_owner": "platform",
                "asset_business_service": "payments",
                "asset_exposure": "internet-facing",
                "raw_severity": "CRITICAL",
            },
        )
        critical.last_seen_at = now
        high.last_seen_at = now - timedelta(minutes=5)
        medium.last_seen_at = now - timedelta(minutes=10)
        session.add(critical)
        session.add(high)
        session.add(medium)
        session.commit()
        return {
            "critical": critical.id,
            "high": high.id,
            "medium": medium.id,
            "critical_asset": critical_asset.id,
            "high_asset": high_asset.id,
            "medium_asset": medium_asset.id,
        }


def test_vpw036_explain_returns_422_when_decision_payload_is_missing(
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

    response = workbench_api_env.client.get(
        f"/api/v1/findings/{seeded['finding_ids'][0]}/explain",
        headers=headers,
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "Finding explanation is not available."


def test_vpw036_project_decision_endpoints_handle_empty_projects(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    summary_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/summary",
        headers=headers,
    )
    assert summary_response.status_code == 200
    summary_payload = summary_response.json()
    assert summary_payload["finding_count"] == 0
    assert summary_payload["open_finding_count"] == 0
    assert summary_payload["counts_by_priority"] == {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }
    assert summary_payload["counts_by_status"] == {
        "open": 0,
        "in_review": 0,
        "remediating": 0,
        "fixed": 0,
        "accepted": 0,
        "suppressed": 0,
    }
    assert summary_payload["latest_run_id"] is None

    comparison_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/compare/cvss-only",
        headers=headers,
        params={"limit": 0},
    )
    assert comparison_response.status_code == 200
    comparison_payload = comparison_response.json()
    assert comparison_payload["summary"] == {
        "total": 0,
        "changed": 0,
        "up": 0,
        "down": 0,
        "unchanged": 0,
    }
    assert comparison_payload["top_changes"] == []
    assert comparison_payload["comparisons"] == []


def test_project_cvss_comparison_suppresses_full_rows_by_default_and_caps_large_projects(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    _seed_vpw042_findings(workbench_api_env, uuid.UUID(project["id"]))

    default_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/compare/cvss-only",
        headers=headers,
        params={"limit": 1},
    )
    assert default_response.status_code == 200, default_response.text
    default_payload = default_response.json()
    assert default_payload["summary"]["total"] == 3
    assert len(default_payload["top_changes"]) <= 1
    assert default_payload["comparisons"] == []

    include_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/compare/cvss-only",
        headers=headers,
        params={"limit": 1, "include_comparisons": True},
    )
    assert include_response.status_code == 200, include_response.text
    assert len(include_response.json()["comparisons"]) == 3

    client = workbench_api_env.client
    old_settings = client.app.state.workbench_settings
    capped_settings = replace(old_settings, DECISION_API_MAX_FINDINGS=2)
    client.app.state.workbench_settings = capped_settings
    try:
        capped_response = client.get(
            f"/api/v1/projects/{project['id']}/compare/cvss-only",
            headers=headers,
        )
    finally:
        client.app.state.workbench_settings = old_settings

    assert capped_response.status_code == 413
    assert "too many findings" in capped_response.json()["detail"]


def test_vpw202_project_dashboard_aggregate_replaces_dashboard_query_fanout(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    _seed_vpw042_findings(workbench_api_env, uuid.UUID(project["id"]))

    response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/dashboard",
        headers=headers,
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["project_id"] == project["id"]
    assert payload["summary"]["finding_count"] == 3
    assert payload["summary"]["open_finding_count"] == 1
    assert payload["summary"]["counts_by_priority"] == {
        "Critical": 1,
        "High": 1,
        "Medium": 1,
        "Low": 0,
    }
    assert payload["runs"]["count"] == 1
    assert "workflow_schema_version" not in payload["runs"]["data"][0]
    assert payload["runs"]["data"][0]["counts"]["created_findings"] == 0
    assert payload["findings"]["remediation_queue"]["count"] == 3
    assert [item["cve_id"] for item in payload["findings"]["remediation_queue"]["data"]] == [
        DEMO_CVE_LOG4SHELL,
        "CVE-2022-22965",
        "CVE-2024-4577",
    ]
    assert payload["findings"]["remediation_queue"]["data"][0]["component_name"] == "log4j-core"
    assert payload["findings"]["remediation_queue"]["data"][0]["asset_key"] == "payments-api"
    assert payload["findings"]["signal_counts"] == {
        "high_epss": 1,
        "internet_facing_criticals": 1,
        "epss_buckets": {
            "low": 1,
            "medium": 1,
            "high": 0,
            "critical": 1,
        },
    }
    assert payload["governance"]["project_id"] == project["id"]
    assert payload["governance"]["services"][0]["label"] == "payments"


def test_vpw011_missing_and_secondary_project_resources_use_local_runtime_errors(
    secondary_workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(secondary_workbench_api_env.client)
    secondary_project = seed_secondary_project_graph(
        secondary_workbench_api_env.engine,
        secondary_workbench_api_env.app_models,
        secondary_workbench_api_env.repositories,
    )
    missing_id = uuid.UUID("00000000-0000-4000-8000-000000000404")

    not_found_calls: tuple[tuple[str, str, dict[str, Any]], ...] = (
        ("get", f"/api/v1/projects/{missing_id}", {}),
        ("patch", f"/api/v1/assets/{missing_id}", {"json": {"name": "Missing Asset"}}),
        ("get", f"/api/v1/runs/{missing_id}", {}),
        ("get", f"/api/v1/runs/{missing_id}/summary", {}),
        ("get", f"/api/v1/runs/{missing_id}/workflow-metadata", {}),
        ("get", f"/api/v1/runs/{missing_id}/reports", {}),
        ("post", f"/api/v1/runs/{missing_id}/reports", {"json": {"format": "markdown"}}),
        ("get", f"/api/v1/reports/{missing_id}/download", {}),
        ("get", f"/api/v1/findings/{missing_id}", {}),
        ("get", f"/api/v1/findings/{missing_id}/explain", {}),
        ("get", f"/api/v1/projects/{missing_id}/assets/", {}),
        ("get", f"/api/v1/projects/{missing_id}/runs/", {}),
        ("get", f"/api/v1/projects/{missing_id}/findings/", {}),
        ("get", f"/api/v1/projects/{missing_id}/summary", {}),
        ("get", f"/api/v1/projects/{missing_id}/dashboard", {}),
        ("get", f"/api/v1/projects/{missing_id}/attack/summary", {}),
        ("get", f"/api/v1/projects/{missing_id}/compare/cvss-only", {}),
    )
    secondary_project_calls: tuple[tuple[str, str, dict[str, Any]], ...] = (
        ("get", f"/api/v1/projects/{secondary_project['project_id']}", {}),
        (
            "patch",
            f"/api/v1/assets/{secondary_project['asset_id']}",
            {"json": {"name": "Secondary Asset"}},
        ),
        ("get", f"/api/v1/runs/{secondary_project['run_id']}", {}),
        ("get", f"/api/v1/runs/{secondary_project['run_id']}/summary", {}),
        ("get", f"/api/v1/runs/{secondary_project['run_id']}/workflow-metadata", {}),
        ("get", f"/api/v1/runs/{secondary_project['run_id']}/reports", {}),
        (
            "post",
            f"/api/v1/runs/{secondary_project['run_id']}/reports",
            {"json": {"format": "markdown"}},
        ),
        ("get", f"/api/v1/findings/{secondary_project['finding_id']}", {}),
        ("get", f"/api/v1/findings/{secondary_project['finding_id']}/explain", {}),
        ("get", f"/api/v1/projects/{secondary_project['project_id']}/assets/", {}),
        ("get", f"/api/v1/projects/{secondary_project['project_id']}/runs/", {}),
        ("get", f"/api/v1/projects/{secondary_project['project_id']}/findings/", {}),
        ("get", f"/api/v1/projects/{secondary_project['project_id']}/summary", {}),
        ("get", f"/api/v1/projects/{secondary_project['project_id']}/dashboard", {}),
        ("get", f"/api/v1/projects/{secondary_project['project_id']}/attack/summary", {}),
        ("get", f"/api/v1/projects/{secondary_project['project_id']}/compare/cvss-only", {}),
    )

    for method, path, kwargs in not_found_calls:
        response = getattr(secondary_workbench_api_env.client, method)(
            path, headers=headers, **kwargs
        )
        assert response.status_code == 404, f"{method.upper()} {path}: {response.text}"

    for method, path, kwargs in secondary_project_calls:
        response = getattr(secondary_workbench_api_env.client, method)(
            path, headers=headers, **kwargs
        )
        assert response.status_code != 403, f"{method.upper()} {path}: {response.text}"

    invalid_sort = secondary_workbench_api_env.client.get(
        f"/api/v1/projects/{missing_id}/findings/",
        headers=headers,
        params={"sort": "unknown"},
    )
    assert invalid_sort.status_code == 422
