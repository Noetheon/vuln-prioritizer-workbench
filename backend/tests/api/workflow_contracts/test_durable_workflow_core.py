from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from utils.import_contract_fixtures import SAMPLE_CVES
from utils.workbench_env import WorkbenchApiEnv, local_api_headers
from utils.workbench_workflow_contracts import (
    assert_no_raw_workflow_fields,
    assert_no_workflow_path_leak,
    configure_workflow_context,
    create_report,
    list_reports,
    post_import,
    run_summary,
)


def test_import_and_report_workflows_are_durable_public_api_contracts(
    monkeypatch: pytest.MonkeyPatch,
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    for env_name in ("NVD_API_KEY", "FIRST_API_KEY"):
        monkeypatch.delenv(env_name, raising=False)
    for proxy_name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(proxy_name, "http://127.0.0.1:9")

    context = configure_workflow_context(workbench_api_env, tmp_path)
    import_payload = post_import(
        workbench_api_env,
        context,
        data={
            "input_type": "cve-list",
            "provider_snapshot_file": "demo_provider_snapshot.json",
            "locked_provider_data": "true",
        },
        files={"file": ("sample_cves.txt", SAMPLE_CVES.read_bytes(), "text/plain")},
    )
    run_id = import_payload["id"]
    import_workflow = import_payload["workflow"]

    _assert_import_workflow(import_workflow, run_id=run_id, project_id=context.project_id)
    import_events = _workflow_events(
        workbench_api_env,
        context.headers,
        workflow_id=import_workflow["id"],
    )
    assert import_events["count"] >= 6
    assert _event_types(import_events) >= {"created", "started", "stage", "succeeded"}
    assert {
        "store_uploads",
        "parse_upload",
        "enrich_score_explain",
        "persist_findings",
        "succeeded",
    } <= _event_stages(import_events)
    assert_no_raw_workflow_fields(import_events)
    assert_no_workflow_path_leak(import_events, context)

    summary = run_summary(workbench_api_env, context, run_id)
    _assert_import_workflow(summary["workflow"], run_id=run_id, project_id=context.project_id)

    report = create_report(workbench_api_env, context, run_id, "markdown")
    report_workflow = report["workflow"]
    assert report_workflow["kind"] == "report_generation"
    assert report_workflow["status"] == "succeeded"
    assert report_workflow["analysis_run_id"] == run_id
    assert report_workflow["report_id"] == report["id"]
    assert report_workflow["current_stage"] == "succeeded"
    assert report_workflow["progress_current"] == 3
    assert report_workflow["progress_total"] == 3
    assert report_workflow["latest_event"]["event_type"] == "succeeded"

    report_events = _workflow_events(
        workbench_api_env,
        context.headers,
        workflow_id=report_workflow["id"],
    )
    assert _event_types(report_events) >= {"created", "started", "artifact", "succeeded"}
    artifact_event = next(
        event for event in report_events["data"] if event["event_type"] == "artifact"
    )
    assert artifact_event["artifact_kind"] == "report"
    assert artifact_event["artifact_id"] == report["id"]
    assert artifact_event["details"]["format"] == "markdown"
    assert_no_raw_workflow_fields(report_events)
    assert_no_workflow_path_leak(report_events, context)

    listed_report = list_reports(workbench_api_env, context, run_id)["data"][0]
    assert listed_report["workflow"]["id"] == report_workflow["id"]
    assert listed_report["workflow"]["latest_event"]["event_type"] == "succeeded"

    project_workflows = _project_workflows(workbench_api_env, context.headers, context.project_id)
    workflow_kinds = {workflow["kind"] for workflow in project_workflows["data"]}
    assert {"import", "report_generation"} <= workflow_kinds


def test_provider_update_workflow_is_public_on_jobs_and_status(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    active_settings = workbench_api_env.client.app.state.workbench_settings
    workbench_api_env.client.app.state.workbench_settings = replace(
        active_settings,
        PROVIDER_SNAPSHOT_DIR=str(tmp_path / "workbench-provider-snapshots"),
        PROVIDER_CACHE_DIR=str(tmp_path / "workbench-provider-cache"),
    )
    try:
        response = workbench_api_env.client.post(
            "/api/v1/providers/update-jobs",
            headers=headers,
            json={
                "sources": ["kev"],
                "cve_ids": ["CVE-2024-3094"],
                "cache_only": True,
                "max_cves": 1,
            },
        )
        assert response.status_code == 200, response.text
        job = response.json()
        assert_no_raw_workflow_fields(job)

        workflow = job["workflow"]
        assert workflow["kind"] == "provider_update"
        assert workflow["status"] == "succeeded"
        assert workflow["analysis_run_id"] == job["id"]
        assert workflow["execution_mode"] == "request"
        assert workflow["current_stage"] == "succeeded"
        assert workflow["progress_current"] == 3
        assert workflow["progress_total"] == 3
        assert workflow["details"]["requested_sources"] == ["kev"]
        assert workflow["details"]["requested_cves"] == 1
        assert workflow["latest_event"]["event_type"] == "succeeded"

        events = _workflow_events(workbench_api_env, headers, workflow_id=workflow["id"])
        assert _event_types(events) >= {"created", "started", "stage", "artifact", "succeeded"}
        assert {"refresh_snapshot", "provider_lock_acquired", "succeeded"} <= _event_stages(events)
        artifact_event = next(
            event for event in events["data"] if event["event_type"] == "artifact"
        )
        assert artifact_event["artifact_kind"] == "provider_snapshot"
        assert artifact_event["artifact_id"] == job["metadata"]["provider_snapshot_id"]
        assert_no_raw_workflow_fields(events)

        listed = workbench_api_env.client.get(
            "/api/v1/providers/update-jobs",
            headers=headers,
        )
        assert listed.status_code == 200, listed.text
        listed_job = listed.json()["data"][0]
        assert listed_job["workflow"]["id"] == workflow["id"]
        assert listed_job["workflow"]["latest_event"]["event_type"] == "succeeded"

        status = workbench_api_env.client.get("/api/v1/providers/status", headers=headers)
        assert status.status_code == 200, status.text
        latest_update = status.json()["latest_update_job"]
        assert latest_update["id"] == job["id"]
        assert latest_update["workflow"]["id"] == workflow["id"]
        assert latest_update["workflow"]["status"] == "succeeded"
    finally:
        workbench_api_env.client.app.state.workbench_settings = active_settings


def test_failed_import_writes_failed_workflow_without_raw_error_fields(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    context = configure_workflow_context(workbench_api_env, tmp_path)
    failure = post_import(
        workbench_api_env,
        context,
        data={"input_type": "cve-list"},
        files={"file": ("bad-cves.txt", b"CVE-2024-3094\nnot-a-cve\n", "text/plain")},
        expected_status=422,
    )["detail"]
    run_id = failure["analysis_run_id"]

    summary = run_summary(workbench_api_env, context, run_id)
    workflow = summary["workflow"]
    assert workflow["kind"] == "import"
    assert workflow["status"] == "failed"
    assert workflow["analysis_run_id"] == run_id
    assert workflow["current_stage"] == "parse_upload"
    assert workflow["error_message"]
    assert workflow["error_details"]["stage"] == "parse_upload"
    assert workflow["error_details"]["error_type"] == "ImporterParseError"
    assert workflow["latest_event"]["event_type"] == "failed"

    events = _workflow_events(
        workbench_api_env,
        context.headers,
        workflow_id=workflow["id"],
    )
    assert "failed" in _event_types(events)
    assert "parse_upload" in _event_stages(events)
    assert_no_raw_workflow_fields(summary)
    assert_no_raw_workflow_fields(events)
    assert_no_workflow_path_leak(summary, context)
    assert_no_workflow_path_leak(events, context)


def _assert_import_workflow(
    workflow: dict[str, Any],
    *,
    run_id: str,
    project_id: str,
) -> None:
    assert workflow["kind"] == "import"
    assert workflow["status"] == "succeeded"
    assert workflow["analysis_run_id"] == run_id
    assert workflow["project_id"] == project_id
    assert workflow["current_stage"] == "succeeded"
    assert workflow["progress_current"] == 6
    assert workflow["progress_total"] == 6
    assert workflow["error_details"] == {}
    assert workflow["details"]["input_type"] == "cve-list"
    assert workflow["latest_event"]["event_type"] == "succeeded"


def _workflow_events(
    workbench_api_env: WorkbenchApiEnv,
    headers: dict[str, str],
    *,
    workflow_id: str,
) -> dict[str, Any]:
    response = workbench_api_env.client.get(
        f"/api/v1/workflows/{workflow_id}/events",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


def _project_workflows(
    workbench_api_env: WorkbenchApiEnv,
    headers: dict[str, str],
    project_id: str,
) -> dict[str, Any]:
    response = workbench_api_env.client.get(
        f"/api/v1/projects/{project_id}/workflows",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


def _event_types(events: dict[str, Any]) -> set[str]:
    return {event["event_type"] for event in events["data"]}


def _event_stages(events: dict[str, Any]) -> set[str]:
    return {event["stage"] for event in events["data"] if event.get("stage")}
