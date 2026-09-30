from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from sqlmodel import Session
from utils.import_contracts import completed_run_payload, configure_upload_dir, drain_workflow_queue
from utils.workbench_contracts import _configure_report_dir
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api, local_api_headers

from app.repositories import RunRepository


def _import_cves(
    env: WorkbenchApiEnv,
    project_id: str,
    headers: dict[str, str],
    content: bytes,
) -> dict[str, Any]:
    response = env.client.post(
        f"/api/v1/projects/{project_id}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("cves.txt", content, "text/plain")},
    )
    return completed_run_payload(env, response, headers=headers)


def _reports_for_run(
    env: WorkbenchApiEnv, run_id: str, headers: dict[str, str]
) -> list[dict[str, Any]]:
    response = env.client.get(f"/api/v1/runs/{run_id}/reports", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["data"]


def _download(env: WorkbenchApiEnv, report: dict[str, Any], headers: dict[str, str]) -> str:
    response = env.client.get(f"/api/v1/reports/{report['id']}/download", headers=headers)
    assert response.status_code == 200, response.text
    return response.text


def _project_with_findings(
    env: WorkbenchApiEnv, tmp_path: Path
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    configure_upload_dir(env, tmp_path)
    _configure_report_dir(env, tmp_path)
    headers = local_api_headers(env.client)
    project = create_project_via_api(env.client, headers)
    run = _import_cves(env, project["id"], headers, b"CVE-2021-44228\nCVE-2024-3094\n")
    return project, run, headers


def _finding_id(env: WorkbenchApiEnv, project_id: str, cve_id: str, headers: dict[str, str]) -> str:
    response = env.client.get(f"/api/v1/projects/{project_id}/findings", headers=headers)
    assert response.status_code == 200, response.text
    return next(item["id"] for item in response.json()["data"] if item["cve_id"] == cve_id)


def test_state_report_covers_the_whole_project_with_current_status(
    workbench_api_env: WorkbenchApiEnv, tmp_path: Path
) -> None:
    env = workbench_api_env
    project, import_run, headers = _project_with_findings(env, tmp_path)
    fixed_id = _finding_id(env, project["id"], "CVE-2024-3094", headers)
    changed = env.client.patch(
        f"/api/v1/findings/{fixed_id}/status",
        headers=headers,
        json={"status": "resolved", "reason": "Upgraded xz-utils."},
    )
    assert changed.status_code == 200, changed.text

    queued = env.client.post(
        f"/api/v1/projects/{project['id']}/state-report-jobs",
        headers=headers,
        json={"format": "markdown"},
    )
    assert queued.status_code == 200, queued.text
    state_run_id = queued.json()["analysis_run_id"]
    assert state_run_id != import_run["id"]
    drain_workflow_queue(env)

    (report,) = _reports_for_run(env, state_run_id, headers)
    assert report["workflow"]["status"] == "succeeded"
    markdown = _download(env, report, headers)
    assert "This report covers the whole project as of" in markdown
    assert "2 findings with their current status and priority" in markdown
    # The Top Findings row carries the status as of now, not as of the import.
    assert any(
        "| CVE-2024-3094 |" in line and "| resolved |" in line for line in markdown.splitlines()
    )

    summary = env.client.get(f"/api/v1/runs/{state_run_id}/summary", headers=headers).json()
    assert summary["input_type"] == "project_state"
    assert summary["finding_count"] == 2
    assert summary["project_state_current"] is True
    assert summary["decision_summary"]["finding_count"] == 2


def test_state_snapshots_stay_out_of_run_lists(
    workbench_api_env: WorkbenchApiEnv, tmp_path: Path
) -> None:
    env = workbench_api_env
    project, import_run, headers = _project_with_findings(env, tmp_path)
    queued = env.client.post(
        f"/api/v1/projects/{project['id']}/state-report-jobs",
        headers=headers,
        json={"format": "csv"},
    )
    assert queued.status_code == 200, queued.text
    state_run_id = queued.json()["analysis_run_id"]

    default_runs = env.client.get(f"/api/v1/projects/{project['id']}/runs/", headers=headers)
    assert [run["id"] for run in default_runs.json()["data"]] == [import_run["id"]]
    assert default_runs.json()["count"] == 1
    all_runs = env.client.get(
        f"/api/v1/projects/{project['id']}/runs/?include_state_snapshots=true",
        headers=headers,
    )
    assert [run["id"] for run in all_runs.json()["data"]] == [state_run_id, import_run["id"]]
    assert [run["project_state_current"] for run in all_runs.json()["data"]] == [True, None]
    with Session(env.engine) as session:
        latest = RunRepository(session).get_latest_analysis_run(uuid.UUID(project["id"]))
    assert latest is not None and str(latest.id) == import_run["id"]


def test_state_report_refuses_a_recording_the_project_has_moved_past(
    workbench_api_env: WorkbenchApiEnv, tmp_path: Path
) -> None:
    env = workbench_api_env
    project, _import_run, headers = _project_with_findings(env, tmp_path)
    queued = env.client.post(
        f"/api/v1/projects/{project['id']}/state-report-jobs",
        headers=headers,
        json={"format": "markdown"},
    )
    assert queued.status_code == 200, queued.text
    state_run_id = queued.json()["analysis_run_id"]
    drain_workflow_queue(env)

    finding_id = _finding_id(env, project["id"], "CVE-2021-44228", headers)
    changed = env.client.patch(
        f"/api/v1/findings/{finding_id}/status",
        headers=headers,
        json={"status": "in_review"},
    )
    assert changed.status_code == 200, changed.text
    summary = env.client.get(f"/api/v1/runs/{state_run_id}/summary", headers=headers).json()
    assert summary["project_state_current"] is False
    listed = env.client.get(
        f"/api/v1/projects/{project['id']}/runs/?include_state_snapshots=true",
        headers=headers,
    ).json()["data"]
    assert listed[0]["id"] == state_run_id
    assert listed[0]["project_state_current"] is False
    assert summary["decision_summary"] is None

    later = env.client.post(
        f"/api/v1/runs/{state_run_id}/report-jobs",
        headers=headers,
        json={"format": "html"},
    )
    assert later.status_code == 200, later.text
    drain_workflow_queue(env)
    html_reports = [
        report
        for report in _reports_for_run(env, state_run_id, headers)
        if report["format"] == "html"
    ]
    workflow = env.client.get(f"/api/v1/workflows/{later.json()['id']}", headers=headers).json()
    assert html_reports == []
    assert workflow["status"] == "failed"
    assert "The project changed after its state was recorded" in workflow["error_message"]


def test_state_report_needs_findings(workbench_api_env: WorkbenchApiEnv, tmp_path: Path) -> None:
    env = workbench_api_env
    _configure_report_dir(env, tmp_path)
    headers = local_api_headers(env.client)
    project = create_project_via_api(env.client, headers)

    response = env.client.post(
        f"/api/v1/projects/{project['id']}/state-report-jobs",
        headers=headers,
        json={"format": "html"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "This project has no findings to report on yet."
    runs = env.client.get(
        f"/api/v1/projects/{project['id']}/runs/?include_state_snapshots=true",
        headers=headers,
    )
    assert runs.json()["count"] == 0


def test_state_report_evidence_bundle_verifies(
    workbench_api_env: WorkbenchApiEnv, tmp_path: Path
) -> None:
    env = workbench_api_env
    project, _import_run, headers = _project_with_findings(env, tmp_path)
    queued = env.client.post(
        f"/api/v1/projects/{project['id']}/state-report-jobs",
        headers=headers,
        json={"format": "zip"},
    )
    assert queued.status_code == 200, queued.text
    drain_workflow_queue(env)

    (bundle,) = _reports_for_run(env, queued.json()["analysis_run_id"], headers)
    verification = env.client.post(f"/api/v1/reports/{bundle['id']}/verify", headers=headers)

    assert verification.status_code == 200, verification.text
    assert verification.json()["summary"]["ok"] is True


def test_project_report_history_spans_every_run(
    workbench_api_env: WorkbenchApiEnv, tmp_path: Path
) -> None:
    env = workbench_api_env
    project, import_run, headers = _project_with_findings(env, tmp_path)
    by_run = env.client.post(
        f"/api/v1/runs/{import_run['id']}/report-jobs",
        headers=headers,
        json={"format": "markdown"},
    )
    assert by_run.status_code == 200, by_run.text
    by_state = env.client.post(
        f"/api/v1/projects/{project['id']}/state-report-jobs",
        headers=headers,
        json={"format": "csv"},
    )
    assert by_state.status_code == 200, by_state.text
    drain_workflow_queue(env)

    history = env.client.get(f"/api/v1/projects/{project['id']}/reports", headers=headers)
    assert history.status_code == 200, history.text
    body = history.json()
    assert body["count"] == 2
    # Newest first, each naming the run it covers.
    assert [item["analysis_run_id"] for item in body["data"]] == [
        by_state.json()["analysis_run_id"],
        import_run["id"],
    ]
    assert [item["format"] for item in body["data"]] == ["csv", "markdown"]

    page = env.client.get(
        f"/api/v1/projects/{project['id']}/reports?limit=1&offset=1", headers=headers
    ).json()
    assert page["count"] == 2
    assert [item["format"] for item in page["data"]] == ["markdown"]

    missing = env.client.get(f"/api/v1/projects/{uuid.uuid4()}/reports", headers=headers)
    assert missing.status_code == 404
