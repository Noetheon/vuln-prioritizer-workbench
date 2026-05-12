from __future__ import annotations

from uuid import uuid4

from utils.workbench_env import WorkbenchApiEnv, create_project_via_api


def test_workbench_api_token_routes_are_not_active(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    client = workbench_api_env.client

    openapi = client.get("/api/v1/openapi.json").json()

    assert "/api/v1/api-tokens/" not in openapi["paths"]
    assert "/api/v1/api-tokens/{token_id}" not in openapi["paths"]
    assert client.get("/api/v1/api-tokens/").status_code == 404
    assert client.post("/api/v1/api-tokens/", json={"name": "unused"}).status_code == 404
    assert client.delete(f"/api/v1/api-tokens/{uuid4()}").status_code == 404


def test_workbench_bearer_headers_do_not_activate_service_token_auth(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    client = workbench_api_env.client

    created = client.post(
        "/api/v1/projects/",
        headers={"Authorization": "Bearer not-a-valid-token"},
        json={"name": "Ignored Bearer", "description": None},
    )
    listed = client.get(
        "/api/v1/projects/",
        headers={"Authorization": f"Bearer vpr_{'A' * 40}"},
    )

    assert created.status_code == 200, created.text
    assert listed.status_code == 200, listed.text
    assert listed.json()["count"] == 1
    assert "ApiToken" not in dir(workbench_api_env.app_models)


def test_workbench_project_access_is_existence_only_not_token_scoped(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    client = workbench_api_env.client
    first_project = create_project_via_api(client, {})
    second_project = create_project_via_api(client, {}, name="Second Project")

    update_other_project = client.patch(
        f"/api/v1/projects/{second_project['id']}",
        headers={"Authorization": f"Bearer vpr_{'B' * 40}"},
        json={"description": "No token-scope check remains."},
    )
    missing_project = client.patch(
        f"/api/v1/projects/{uuid4()}",
        headers={"Authorization": f"Bearer vpr_{'C' * 40}"},
        json={"description": "Still missing."},
    )

    assert update_other_project.status_code == 200, update_other_project.text
    assert update_other_project.json()["id"] == second_project["id"]
    assert update_other_project.json()["description"] == "No token-scope check remains."
    assert missing_project.status_code == 404
    assert client.get(f"/api/v1/projects/{first_project['id']}").status_code == 200
