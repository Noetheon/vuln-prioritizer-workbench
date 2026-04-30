from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

from fastapi.testclient import TestClient
from sqlmodel import Session
from utils.template_workbench import (
    DEMO_CVE_LOG4SHELL,
    DEMO_CVE_XZ,
    TemplateApiEnv,
    auth_headers,
    create_project_via_api,
    current_user,
    seed_analysis_run,
    seed_finding_pair,
    seed_foreign_project_graph,
)

from app.main import app
from app.models.base import get_datetime_utc


def test_vpw011_openapi_exposes_workbench_domain_routes_without_items() -> None:
    client = TestClient(app)

    response = client.get("/api/v1/openapi.json")

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
        "/api/v1/projects/{project_id}/runs",
        "/api/v1/projects/{project_id}/runs/",
        "/api/v1/runs/{run_id}",
        "/api/v1/runs/{run_id}/summary",
        "/api/v1/runs/{run_id}/reports",
        "/api/v1/reports/{report_id}/download",
        "/api/v1/projects/{project_id}/findings/",
        "/api/v1/findings/{finding_id}",
        "/api/v1/findings/{finding_id}/explain",
        "/api/v1/projects/{project_id}/waivers/",
        "/api/v1/waivers/{waiver_id}",
        "/api/v1/waivers/{waiver_id}/expire",
        "/api/v1/projects/{project_id}/summary",
        "/api/v1/projects/{project_id}/governance/rollups/",
        "/api/v1/projects/{project_id}/compare/cvss-only",
    }
    expected_schemas = {
        "AnalysisRunPublic",
        "AnalysisRunSummaryPublic",
        "AnalysisRunsPublic",
        "AssetCreate",
        "AssetPublic",
        "AssetsPublic",
        "AssetUpdate",
        "FindingPublic",
        "FindingExplanationPublic",
        "FindingsPublic",
        "GovernanceRollupPublic",
        "GovernanceWaiverDebtEntryPublic",
        "GovernanceWaiverDebtPublic",
        "ImportParseErrorPublic",
        "ProjectCreate",
        "ProjectCvssOnlyComparisonPublic",
        "ProjectDecisionSummaryPublic",
        "ProjectGovernanceRollupsPublic",
        "ProjectPublic",
        "ProjectsPublic",
        "ProjectUpdate",
        "ProviderSnapshotStatusPublic",
        "ProviderSourceStatusPublic",
        "ProviderStatusPublic",
        "ReportCreate",
        "ReportPublic",
        "ReportsPublic",
        "WaiverCreate",
        "WaiverPublic",
        "WaiversPublic",
        "WaiverUpdate",
    }
    assert expected_paths.issubset(paths)

    assert all("/items" not in path for path in paths)
    assert client.get("/api/v1/items/").status_code == 404
    assert expected_schemas.issubset(schemas)
    assert all("Item" not in schema_name for schema_name in schemas)


def test_vpw011_domain_routes_require_auth(template_api_env: TemplateApiEnv) -> None:
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
        ("get", f"/api/v1/projects/{project_id}/governance/rollups/", {}),
        ("get", f"/api/v1/projects/{project_id}/compare/cvss-only", {}),
    )

    for method, path, kwargs in protected_calls:
        response = getattr(template_api_env.client, method)(path, **kwargs)
        assert response.status_code == 401, f"{method.upper()} {path}: {response.text}"


def test_vpw011_project_lifecycle_create_list_get_update_delete(
    template_api_env: TemplateApiEnv,
) -> None:
    headers = auth_headers(template_api_env.client)

    create_response = template_api_env.client.post(
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
    assert created["owner_id"] == current_user(template_api_env.client, headers)["id"]

    list_response = template_api_env.client.get("/api/v1/projects/", headers=headers)
    assert list_response.status_code == 200
    assert list_response.json()["data"] == [created]
    assert list_response.json()["count"] == 1

    get_response = template_api_env.client.get(f"/api/v1/projects/{created['id']}", headers=headers)
    assert get_response.status_code == 200
    assert get_response.json() == created

    update_response = template_api_env.client.patch(
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
    assert updated["owner_id"] == created["owner_id"]
    assert updated["name"] == "External Attack Surface Updated"
    assert updated["description"] == "Updated Workbench project description."

    delete_response = template_api_env.client.delete(
        f"/api/v1/projects/{created['id']}",
        headers=headers,
    )
    assert delete_response.status_code == 204

    missing_after_delete = template_api_env.client.get(
        f"/api/v1/projects/{created['id']}",
        headers=headers,
    )
    assert missing_after_delete.status_code == 404
    assert template_api_env.client.get("/api/v1/projects/", headers=headers).json() == {
        "data": [],
        "count": 0,
    }


def test_vpw011_asset_list_create_and_update(template_api_env: TemplateApiEnv) -> None:
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    create_response = template_api_env.client.post(
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

    list_response = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
    )
    assert list_response.status_code == 200
    assert list_response.json()["data"] == [created]
    assert list_response.json()["count"] == 1

    update_asset_response = template_api_env.client.patch(
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
    template_api_env: TemplateApiEnv,
) -> None:
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    seeded = seed_analysis_run(
        template_api_env.engine,
        template_api_env.app_models,
        template_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
    )

    list_response = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/runs",
        headers=headers,
    )
    assert list_response.status_code == 200
    list_payload = list_response.json()
    assert list_payload["count"] == 1
    assert list_payload["data"][0]["id"] == str(seeded["run_id"])
    assert list_payload["data"][0]["project_id"] == project["id"]
    assert list_payload["data"][0]["status"] == "completed"

    get_response = template_api_env.client.get(f"/api/v1/runs/{seeded['run_id']}", headers=headers)
    assert get_response.status_code == 200
    detail = get_response.json()
    assert detail["id"] == str(seeded["run_id"])
    assert detail["provider_snapshot_id"] == str(seeded["provider_snapshot_id"])
    assert detail["summary_json"] == {"parsed": 2, "findings": 2}

    summary_response = template_api_env.client.get(
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
    assert summary["summary_json"] == {"parsed": 2, "findings": 2}


def test_vpw011_finding_list_and_get_support_pagination(
    template_api_env: TemplateApiEnv,
) -> None:
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    seeded = seed_finding_pair(
        template_api_env.engine,
        template_api_env.app_models,
        template_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
    )

    list_response = template_api_env.client.get(
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

    get_response = template_api_env.client.get(
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


def test_vpw042_findings_list_filters_and_display_fields(
    template_api_env: TemplateApiEnv,
) -> None:
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    seeded = _seed_vpw042_findings(template_api_env, uuid.UUID(project["id"]))

    list_response = template_api_env.client.get(
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

    assert _finding_cves(template_api_env, project, headers, {"status": "suppressed"}) == [
        "CVE-2024-4577"
    ]
    assert _finding_cves(template_api_env, project, headers, {"kev": "true"}) == [
        DEMO_CVE_LOG4SHELL
    ]
    assert _finding_cves(template_api_env, project, headers, {"owner": "platform"}) == [
        DEMO_CVE_LOG4SHELL
    ]
    assert _finding_cves(template_api_env, project, headers, {"service": "identity"}) == [
        "CVE-2022-22965"
    ]
    assert _finding_cves(template_api_env, project, headers, {"owner_service": "payments"}) == [
        DEMO_CVE_LOG4SHELL
    ]
    assert _finding_cves(
        template_api_env,
        project,
        headers,
        {"asset_id": str(seeded["critical_asset"])},
    ) == [DEMO_CVE_LOG4SHELL]
    assert _finding_cves(template_api_env, project, headers, {"exposure": "internal"}) == [
        "CVE-2022-22965"
    ]
    assert _finding_cves(
        template_api_env,
        project,
        headers,
        {"epss_min": "0.40", "epss_max": "0.50"},
    ) == ["CVE-2024-4577"]
    assert _finding_cves(
        template_api_env,
        project,
        headers,
        {"cvss_min": "8.0", "cvss_max": "9.0"},
    ) == ["CVE-2022-22965"]

    detail_response = template_api_env.client.get(
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

    invalid_exposure = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
        params={"exposure": "public"},
    )
    assert invalid_exposure.status_code == 422


def test_vpw044_asset_edit_rescore_flag_is_merged_into_explain(
    template_api_env: TemplateApiEnv,
) -> None:
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    seeded = _seed_vpw042_findings(template_api_env, uuid.UUID(project["id"]))

    update_response = template_api_env.client.patch(
        f"/api/v1/assets/{seeded['critical_asset']}",
        headers=headers,
        json={"criticality": "high"},
    )
    assert update_response.status_code == 200, update_response.text

    explain_response = template_api_env.client.get(
        f"/api/v1/findings/{seeded['critical']}/explain",
        headers=headers,
    )
    assert explain_response.status_code == 200, explain_response.text
    flags = explain_response.json()["data_quality_flags"]
    codes = {flag["code"] for flag in flags}
    assert "provider_snapshot_stale" in codes
    assert "asset_context_rescore_needed" in codes
    rescore_flag = next(flag for flag in flags if flag["code"] == "asset_context_rescore_needed")
    assert rescore_flag["asset_id"] == str(seeded["critical_asset"])
    assert rescore_flag["changed_fields"] == ["criticality"]


def test_vpw063_asset_filters_and_recalculate_action_clear_rescore_flag(
    template_api_env: TemplateApiEnv,
) -> None:
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    seeded = _seed_vpw042_findings(template_api_env, uuid.UUID(project["id"]))

    owner_filtered = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
        params={"owner": "platform"},
    )
    assert owner_filtered.status_code == 200, owner_filtered.text
    assert owner_filtered.json()["count"] == 1
    assert owner_filtered.json()["data"][0]["asset_key"] == "payments-api"

    service_filtered = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
        params={"service": "identity"},
    )
    assert service_filtered.status_code == 200, service_filtered.text
    assert service_filtered.json()["count"] == 1
    assert service_filtered.json()["data"][0]["asset_key"] == "identity-api"

    update_response = template_api_env.client.patch(
        f"/api/v1/assets/{seeded['critical_asset']}",
        headers=headers,
        json={"criticality": "high"},
    )
    assert update_response.status_code == 200, update_response.text
    assert update_response.json()["rescore_needed"] is True

    recalculate_response = template_api_env.client.post(
        f"/api/v1/assets/{seeded['critical_asset']}/recalculate",
        headers=headers,
    )
    assert recalculate_response.status_code == 200, recalculate_response.text
    recalculated = recalculate_response.json()
    assert recalculated["asset_id"] == str(seeded["critical_asset"])
    assert recalculated["asset_key"] == "payments-api"
    assert recalculated["recalculated_findings"] == 1
    assert recalculated["cleared_rescore_flags"] >= 1
    assert recalculated["operational_scores"]
    assert recalculated["rescore_needed"] is False

    asset_response = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
        params={"owner": "platform"},
    )
    assert asset_response.status_code == 200
    assert asset_response.json()["data"][0]["rescore_needed"] is False

    explain_response = template_api_env.client.get(
        f"/api/v1/findings/{seeded['critical']}/explain",
        headers=headers,
    )
    assert explain_response.status_code == 200, explain_response.text
    codes = {flag["code"] for flag in explain_response.json()["data_quality_flags"]}
    assert "provider_snapshot_stale" in codes
    assert "asset_context_rescore_needed" not in codes


def test_vpw063_asset_context_import_endpoint_upserts_assets_and_marks_rescore(
    template_api_env: TemplateApiEnv,
) -> None:
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    seeded = _seed_vpw042_findings(template_api_env, uuid.UUID(project["id"]))
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

    response = template_api_env.client.post(
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

    assets = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
        params={"owner": "data"},
    )
    assert assets.status_code == 200
    assert assets.json()["data"][0]["asset_key"] == "batch-worker"

    updated = template_api_env.client.get(
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
    assert payments_asset["rescore_needed"] is True

    explain_response = template_api_env.client.get(
        f"/api/v1/findings/{seeded['critical']}/explain",
        headers=headers,
    )
    assert explain_response.status_code == 200, explain_response.text
    codes = {flag["code"] for flag in explain_response.json()["data_quality_flags"]}
    assert "asset_context_rescore_needed" in codes


def test_vpw042_findings_sort_direction_and_pagination(
    template_api_env: TemplateApiEnv,
) -> None:
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    _seed_vpw042_findings(template_api_env, uuid.UUID(project["id"]))

    score_page = _finding_cves(
        template_api_env,
        project,
        headers,
        {"sort": "score", "direction": "desc", "limit": "2", "offset": "1"},
    )
    assert score_page == ["CVE-2022-22965", "CVE-2024-4577"]
    assert _finding_cves(
        template_api_env,
        project,
        headers,
        {"sort": "epss", "direction": "desc"},
    ) == [DEMO_CVE_LOG4SHELL, "CVE-2024-4577", "CVE-2022-22965"]
    assert _finding_cves(
        template_api_env,
        project,
        headers,
        {"sort": "cvss", "direction": "asc"},
    ) == ["CVE-2024-4577", "CVE-2022-22965", DEMO_CVE_LOG4SHELL]
    assert (
        _finding_cves(
            template_api_env,
            project,
            headers,
            {"sort": "kev", "direction": "desc"},
        )[0]
        == DEMO_CVE_LOG4SHELL
    )
    assert _finding_cves(
        template_api_env,
        project,
        headers,
        {"sort": "last_seen", "direction": "desc"},
    ) == [DEMO_CVE_LOG4SHELL, "CVE-2022-22965", "CVE-2024-4577"]


def _finding_cves(
    template_api_env: TemplateApiEnv,
    project: dict[str, Any],
    headers: dict[str, str],
    params: dict[str, str],
) -> list[str]:
    response = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
        params=params,
    )
    assert response.status_code == 200, response.text
    return [item["cve_id"] for item in response.json()["data"]]


def _seed_vpw042_findings(
    template_api_env: TemplateApiEnv,
    project_id: uuid.UUID,
) -> dict[str, uuid.UUID]:
    """Seed deterministic findings with distinct filter and sort dimensions."""
    app_models = template_api_env.app_models
    repositories = template_api_env.repositories
    now = get_datetime_utc()
    with Session(template_api_env.engine) as session:
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
            summary_json={"parsed": 1, "findings": 1},
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
    template_api_env: TemplateApiEnv,
) -> None:
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    seeded = seed_finding_pair(
        template_api_env.engine,
        template_api_env.app_models,
        template_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
    )

    response = template_api_env.client.get(
        f"/api/v1/findings/{seeded['finding_ids'][0]}/explain",
        headers=headers,
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "Finding explanation is not available."


def test_vpw036_project_decision_endpoints_handle_empty_projects(
    template_api_env: TemplateApiEnv,
) -> None:
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    summary_response = template_api_env.client.get(
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

    comparison_response = template_api_env.client.get(
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


def test_vpw011_404_and_403_are_consistent_for_project_scoped_resources(
    restricted_template_api_env: TemplateApiEnv,
) -> None:
    headers = auth_headers(restricted_template_api_env.client)
    foreign = seed_foreign_project_graph(
        restricted_template_api_env.engine,
        restricted_template_api_env.app_models,
        restricted_template_api_env.repositories,
    )
    missing_id = uuid.UUID("00000000-0000-4000-8000-000000000404")

    not_found_calls: tuple[tuple[str, str, dict[str, Any]], ...] = (
        ("get", f"/api/v1/projects/{missing_id}", {}),
        ("patch", f"/api/v1/assets/{missing_id}", {"json": {"name": "Missing Asset"}}),
        ("get", f"/api/v1/runs/{missing_id}", {}),
        ("get", f"/api/v1/runs/{missing_id}/summary", {}),
        ("get", f"/api/v1/runs/{missing_id}/reports", {}),
        ("post", f"/api/v1/runs/{missing_id}/reports", {"json": {"format": "markdown"}}),
        ("get", f"/api/v1/reports/{missing_id}/download", {}),
        ("get", f"/api/v1/findings/{missing_id}", {}),
        ("get", f"/api/v1/findings/{missing_id}/explain", {}),
        ("get", f"/api/v1/projects/{missing_id}/assets/", {}),
        ("get", f"/api/v1/projects/{missing_id}/runs/", {}),
        ("get", f"/api/v1/projects/{missing_id}/findings/", {}),
        ("get", f"/api/v1/projects/{missing_id}/summary", {}),
        ("get", f"/api/v1/projects/{missing_id}/attack/summary", {}),
        ("get", f"/api/v1/projects/{missing_id}/compare/cvss-only", {}),
    )
    forbidden_calls: tuple[tuple[str, str, dict[str, Any]], ...] = (
        ("get", f"/api/v1/projects/{foreign['project_id']}", {}),
        ("patch", f"/api/v1/assets/{foreign['asset_id']}", {"json": {"name": "Foreign Asset"}}),
        ("get", f"/api/v1/runs/{foreign['run_id']}", {}),
        ("get", f"/api/v1/runs/{foreign['run_id']}/summary", {}),
        ("get", f"/api/v1/runs/{foreign['run_id']}/reports", {}),
        ("post", f"/api/v1/runs/{foreign['run_id']}/reports", {"json": {"format": "markdown"}}),
        ("get", f"/api/v1/findings/{foreign['finding_id']}", {}),
        ("get", f"/api/v1/findings/{foreign['finding_id']}/explain", {}),
        ("get", f"/api/v1/projects/{foreign['project_id']}/assets/", {}),
        ("get", f"/api/v1/projects/{foreign['project_id']}/runs/", {}),
        ("get", f"/api/v1/projects/{foreign['project_id']}/findings/", {}),
        ("get", f"/api/v1/projects/{foreign['project_id']}/summary", {}),
        ("get", f"/api/v1/projects/{foreign['project_id']}/attack/summary", {}),
        ("get", f"/api/v1/projects/{foreign['project_id']}/compare/cvss-only", {}),
    )

    for method, path, kwargs in not_found_calls:
        response = getattr(restricted_template_api_env.client, method)(
            path, headers=headers, **kwargs
        )
        assert response.status_code == 404, f"{method.upper()} {path}: {response.text}"

    for method, path, kwargs in forbidden_calls:
        response = getattr(restricted_template_api_env.client, method)(
            path, headers=headers, **kwargs
        )
        assert response.status_code == 403, f"{method.upper()} {path}: {response.text}"

    invalid_sort = restricted_template_api_env.client.get(
        f"/api/v1/projects/{missing_id}/findings/",
        headers=headers,
        params={"sort": "unknown"},
    )
    assert invalid_sort.status_code == 422
