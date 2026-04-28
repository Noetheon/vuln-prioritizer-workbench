from __future__ import annotations

import uuid
from typing import Any

from fastapi.testclient import TestClient
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
        "/api/v1/projects/{project_id}/runs/",
        "/api/v1/runs/{run_id}",
        "/api/v1/projects/{project_id}/findings/",
        "/api/v1/findings/{finding_id}",
    }
    expected_schemas = {
        "AnalysisRunPublic",
        "AnalysisRunsPublic",
        "AssetCreate",
        "AssetPublic",
        "AssetsPublic",
        "AssetUpdate",
        "FindingPublic",
        "FindingsPublic",
        "ProjectCreate",
        "ProjectPublic",
        "ProjectsPublic",
        "ProjectUpdate",
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
        ("get", f"/api/v1/runs/{run_id}", {}),
        (
            "get",
            f"/api/v1/projects/{project_id}/findings/",
            {"params": {"limit": 1, "offset": 0}},
        ),
        ("get", f"/api/v1/findings/{finding_id}", {}),
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
        f"/api/v1/projects/{project['id']}/runs/",
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
        ("get", f"/api/v1/findings/{missing_id}", {}),
        ("get", f"/api/v1/projects/{missing_id}/assets/", {}),
        ("get", f"/api/v1/projects/{missing_id}/runs/", {}),
        ("get", f"/api/v1/projects/{missing_id}/findings/", {}),
    )
    forbidden_calls: tuple[tuple[str, str, dict[str, Any]], ...] = (
        ("get", f"/api/v1/projects/{foreign['project_id']}", {}),
        ("patch", f"/api/v1/assets/{foreign['asset_id']}", {"json": {"name": "Foreign Asset"}}),
        ("get", f"/api/v1/runs/{foreign['run_id']}", {}),
        ("get", f"/api/v1/findings/{foreign['finding_id']}", {}),
        ("get", f"/api/v1/projects/{foreign['project_id']}/assets/", {}),
        ("get", f"/api/v1/projects/{foreign['project_id']}/runs/", {}),
        ("get", f"/api/v1/projects/{foreign['project_id']}/findings/", {}),
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
