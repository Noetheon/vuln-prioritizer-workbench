from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from utils.workbench_env import WorkbenchApiEnv, local_api_headers

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_demo_workspace_status_is_disabled_by_default(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)

    status_response = workbench_api_env.client.get("/api/v1/workbench/demo", headers=headers)
    seed_response = workbench_api_env.client.post(
        "/api/v1/workbench/demo",
        headers=headers,
        json={"reset": True},
    )

    assert status_response.status_code == 200
    assert status_response.json()["enabled"] is False
    assert status_response.json()["seeded"] is False
    assert seed_response.status_code == 403


def test_demo_workspace_can_be_seeded_reset_and_removed(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _enable_demo_workspace(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)

    first_response = workbench_api_env.client.post(
        "/api/v1/workbench/demo",
        headers=headers,
        json={"reset": True},
    )

    assert first_response.status_code == 200
    payload = first_response.json()
    project_id = payload["project"]["id"]
    first_run_id = payload["latest_run"]["id"]
    assert payload["enabled"] is True
    assert payload["seeded"] is True
    assert payload["project"]["name"] == "Online Shop Demo Workspace"
    assert payload["finding_count"] == 24
    assert payload["asset_count"] == 21
    assert payload["waiver_count"] == 4
    assert payload["report_count"] == 7
    assert payload["latest_run"]["summary_json"]["finding_count"] == 24
    assert payload["latest_run"]["summary_json"]["occurrence_count"] == 24
    assert payload["latest_run"]["summary_json"]["attack_mapped_cves"] == 6
    assert {report["filename"] for report in payload["reports"]} >= {
        "technical-report.md",
        "executive-report.html",
        "analysis-result.v1.json",
        "findings.csv",
        "attack-navigator-layer.json",
        "results.sarif",
        "evidence-bundle.zip",
    }

    projects_response = workbench_api_env.client.get("/api/v1/projects/", headers=headers)
    findings_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project_id}/findings/?limit=100",
        headers=headers,
    )
    assets_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project_id}/assets/",
        headers=headers,
    )
    waivers_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project_id}/waivers/",
        headers=headers,
    )
    reports_response = workbench_api_env.client.get(
        f"/api/v1/runs/{first_run_id}/reports",
        headers=headers,
    )
    governance_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project_id}/governance/rollups/",
        headers=headers,
    )
    attack_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project_id}/attack/summary",
        headers=headers,
    )

    assert projects_response.status_code == 200
    assert projects_response.json()["count"] == 1
    assert findings_response.status_code == 200
    assert findings_response.json()["count"] == 24
    findings = findings_response.json()["data"]
    assert sum(1 for finding in findings if finding["waived"]) == 4
    assert sum(1 for finding in findings if finding["suppressed_by_vex"]) == 2
    assert {finding["status"] for finding in findings} >= {
        "accepted",
        "fixed",
        "open",
        "suppressed",
    }
    assert assets_response.status_code == 200
    assert assets_response.json()["count"] == 21
    assert waivers_response.status_code == 200
    assert waivers_response.json()["count"] == 4
    assert governance_response.status_code == 200
    waiver_debt = governance_response.json()["waiver_debt"]
    assert waiver_debt["waiver_count"] == 4
    assert waiver_debt["active_count"] == 3
    assert waiver_debt["review_due_count"] == 1
    assert waiver_debt["expired_count"] == 0
    assert waiver_debt["expiring_soon_count"] == 1
    assert waiver_debt["accepted_finding_count"] == 4
    assert reports_response.status_code == 200
    assert reports_response.json()["count"] == 7
    assert attack_response.status_code == 200
    assert attack_response.json()["mapped_finding_count"] == 21
    assert attack_response.json()["mapped_coverage_percent"] == 87.5
    assert (tmp_path / "uploads" / project_id).exists()
    assert (tmp_path / "reports" / project_id).exists()

    existing_response = workbench_api_env.client.post(
        "/api/v1/workbench/demo",
        headers=headers,
        json={"reset": False},
    )
    assert existing_response.status_code == 200
    assert existing_response.json()["project"]["id"] == project_id
    assert existing_response.json()["latest_run"]["id"] == first_run_id

    reset_response = workbench_api_env.client.post(
        "/api/v1/workbench/demo",
        headers=headers,
        json={"reset": True},
    )
    assert reset_response.status_code == 200
    assert reset_response.json()["project"]["id"] == project_id
    assert reset_response.json()["latest_run"]["id"] != first_run_id
    assert reset_response.json()["finding_count"] == 24
    assert reset_response.json()["asset_count"] == 21
    assert reset_response.json()["waiver_count"] == 4
    assert reset_response.json()["report_count"] == 7

    delete_response = workbench_api_env.client.delete("/api/v1/workbench/demo", headers=headers)
    status_response = workbench_api_env.client.get("/api/v1/workbench/demo", headers=headers)

    assert delete_response.status_code == 204
    assert status_response.status_code == 200
    assert status_response.json()["enabled"] is True
    assert status_response.json()["seeded"] is False
    assert not (tmp_path / "uploads" / project_id).exists()
    assert not (tmp_path / "reports" / project_id).exists()


def test_demo_workspace_seed_stays_disabled_outside_local(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _enable_demo_workspace(workbench_api_env, tmp_path, environment="production")
    headers = local_api_headers(workbench_api_env.client)

    status_response = workbench_api_env.client.get("/api/v1/workbench/demo", headers=headers)
    seed_response = workbench_api_env.client.post(
        "/api/v1/workbench/demo",
        headers=headers,
        json={"reset": True},
    )

    assert status_response.status_code == 200
    assert status_response.json()["enabled"] is False
    assert seed_response.status_code == 403


def _enable_demo_workspace(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    *,
    environment: str = "local",
) -> None:
    active_settings = replace(
        workbench_api_env.client.app.state.workbench_settings,
        ATTACK_ARTIFACT_DIR=str(PROJECT_ROOT / "data" / "attack"),
        DEMO_PROVIDER_SNAPSHOT_ENABLED=True,
        DEMO_WORKSPACE_ENABLED=True,
        ENVIRONMENT=environment,
        FRONTEND_HOST="https://workbench.example.com"
        if environment != "local"
        else "http://localhost:5173",
        IMPORT_UPLOAD_DIR=str(tmp_path / "uploads"),
        PROVIDER_SNAPSHOT_DIR=str(PROJECT_ROOT / "data"),
        REPORT_DIR=str(tmp_path / "reports"),
        SECRET_KEY="workbench-demo-test-secret-0123456789",
    )
    workbench_api_env.client.app.state.workbench_settings = active_settings
