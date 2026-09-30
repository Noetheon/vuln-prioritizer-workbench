from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from utils.import_contracts import completed_run_payload, configure_upload_dir, drain_workflow_queue
from utils.workbench_contracts import _configure_report_dir
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api, local_api_headers


def _onboarding(env: WorkbenchApiEnv, project_id: str, headers: dict[str, str]) -> dict[str, Any]:
    response = env.client.get(f"/api/v1/projects/{project_id}/onboarding", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def test_onboarding_tracks_import_asset_context_and_first_report(
    workbench_api_env: WorkbenchApiEnv, tmp_path: Path
) -> None:
    env = workbench_api_env
    configure_upload_dir(env, tmp_path)
    _configure_report_dir(env, tmp_path)
    headers = local_api_headers(env.client)
    project = create_project_via_api(env.client, headers)

    fresh = _onboarding(env, project["id"], headers)
    assert fresh == {
        "project_id": project["id"],
        "import_count": 0,
        "finding_count": 0,
        "asset_count": 0,
        "assets_with_context": 0,
        "report_count": 0,
        "complete": False,
    }

    response = env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list", "resolve_missing": "false"},
        files={"file": ("cves.txt", b"CVE-2021-44228\n", "text/plain")},
    )
    run = completed_run_payload(env, response, headers=headers)
    imported = _onboarding(env, project["id"], headers)
    assert imported["import_count"] == 1
    assert imported["finding_count"] == 1
    assert imported["complete"] is False

    asset = env.client.post(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
        json={
            "asset_key": "pay-api-01",
            "name": "pay-api-01",
            "owner": "team-payments",
            "exposure": "internet-facing",
        },
    )
    assert asset.status_code in {200, 201}, asset.text
    with_context = _onboarding(env, project["id"], headers)
    assert with_context["asset_count"] >= 1
    assert with_context["assets_with_context"] == 1

    queued = env.client.post(
        f"/api/v1/runs/{run['id']}/report-jobs",
        headers=headers,
        json={"format": "markdown"},
    )
    assert queued.status_code == 200, queued.text
    drain_workflow_queue(env)
    done = _onboarding(env, project["id"], headers)
    assert done["report_count"] == 1
    assert done["complete"] is True
    assert done["import_count"] == 1


def test_onboarding_needs_a_visible_project(workbench_api_env: WorkbenchApiEnv) -> None:
    headers = local_api_headers(workbench_api_env.client)
    response = workbench_api_env.client.get(
        f"/api/v1/projects/{uuid.uuid4()}/onboarding", headers=headers
    )
    assert response.status_code == 404
