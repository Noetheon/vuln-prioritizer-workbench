from __future__ import annotations

import hashlib
import json
import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any

from utils.import_contracts import assert_no_sensitive_path_leak, configure_upload_dir
from utils.workbench_contracts import _configure_report_dir
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api, local_api_headers


@dataclass(frozen=True)
class WorkflowContext:
    headers: dict[str, str]
    project: dict[str, Any]
    report_dir: Path
    upload_dir: Path

    @property
    def project_id(self) -> str:
        return str(self.project["id"])


def configure_workflow_context(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    *,
    max_upload_mb: int = 25,
) -> WorkflowContext:
    upload_dir = configure_upload_dir(workbench_api_env, tmp_path, max_upload_mb=max_upload_mb)
    report_dir = _configure_report_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers=headers)
    return WorkflowContext(
        headers=headers,
        project=project,
        report_dir=report_dir,
        upload_dir=upload_dir,
    )


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def post_import(
    workbench_api_env: WorkbenchApiEnv,
    context: WorkflowContext,
    *,
    data: dict[str, Any],
    files: dict[str, tuple[str, bytes, str]],
    expected_status: int = 200,
) -> dict[str, Any]:
    response = workbench_api_env.client.post(
        f"/api/v1/projects/{context.project_id}/imports",
        headers=context.headers,
        data=data,
        files=files,
    )
    assert response.status_code == expected_status, response.text
    return response.json()


def run_summary(
    workbench_api_env: WorkbenchApiEnv,
    context: WorkflowContext,
    run_id: str,
) -> dict[str, Any]:
    response = workbench_api_env.client.get(
        f"/api/v1/runs/{run_id}/summary",
        headers=context.headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


def project_findings(
    workbench_api_env: WorkbenchApiEnv,
    context: WorkflowContext,
    *,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    response = workbench_api_env.client.get(
        f"/api/v1/projects/{context.project_id}/findings/",
        headers=context.headers,
        params=params or {"page": 1, "page_size": 100, "sort": "cve"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def finding_detail(
    workbench_api_env: WorkbenchApiEnv,
    context: WorkflowContext,
    finding_id: str,
) -> dict[str, Any]:
    response = workbench_api_env.client.get(
        f"/api/v1/findings/{finding_id}",
        headers=context.headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


def finding_by_cve(
    workbench_api_env: WorkbenchApiEnv,
    context: WorkflowContext,
    cve_id: str,
) -> dict[str, Any]:
    findings = project_findings(workbench_api_env, context)
    for finding in finding_items(findings):
        if finding["cve_id"] == cve_id:
            return finding_detail(workbench_api_env, context, str(finding["id"]))
    raise AssertionError(f"missing finding for {cve_id}")


def report_response(
    workbench_api_env: WorkbenchApiEnv,
    context: WorkflowContext,
    run_id: str,
    *,
    report_format: str,
    expected_status: int = 200,
    payload_overrides: dict[str, Any] | None = None,
) -> Any:
    payload = {"format": report_format}
    payload.update(payload_overrides or {})
    response = workbench_api_env.client.post(
        f"/api/v1/runs/{run_id}/reports",
        headers=context.headers,
        json=payload,
    )
    assert response.status_code == expected_status, response.text
    return response


def create_report(
    workbench_api_env: WorkbenchApiEnv,
    context: WorkflowContext,
    run_id: str,
    report_format: str,
    *,
    payload_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return report_response(
        workbench_api_env,
        context,
        run_id,
        report_format=report_format,
        payload_overrides=payload_overrides,
    ).json()


def list_reports(
    workbench_api_env: WorkbenchApiEnv,
    context: WorkflowContext,
    run_id: str,
) -> dict[str, Any]:
    response = workbench_api_env.client.get(
        f"/api/v1/runs/{run_id}/reports",
        headers=context.headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


def download_report(
    workbench_api_env: WorkbenchApiEnv,
    context: WorkflowContext,
    report: dict[str, Any],
) -> Any:
    response = workbench_api_env.client.get(report["download_url"], headers=context.headers)
    assert response.status_code == 200, response.text
    actual_hash = hashlib.sha256(response.content).hexdigest()
    assert actual_hash == report["sha256"]
    return response


def verify_report(
    workbench_api_env: WorkbenchApiEnv,
    context: WorkflowContext,
    report_id: str,
) -> dict[str, Any]:
    response = workbench_api_env.client.post(
        f"/api/v1/reports/{report_id}/verify",
        headers=context.headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


def downloaded_json(
    workbench_api_env: WorkbenchApiEnv,
    context: WorkflowContext,
    report: dict[str, Any],
) -> dict[str, Any]:
    response = download_report(workbench_api_env, context, report)
    return response.json()


def downloaded_text(
    workbench_api_env: WorkbenchApiEnv,
    context: WorkflowContext,
    report: dict[str, Any],
) -> str:
    response = download_report(workbench_api_env, context, report)
    return response.text


def downloaded_zip_members(
    workbench_api_env: WorkbenchApiEnv,
    context: WorkflowContext,
    report: dict[str, Any],
) -> dict[str, bytes]:
    response = download_report(workbench_api_env, context, report)
    with zipfile.ZipFile(BytesIO(response.content)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def assert_same_run_contract(
    *,
    import_payload: dict[str, Any],
    summary: dict[str, Any],
    findings: dict[str, Any],
    context: WorkflowContext,
    expected_status: str = "succeeded",
) -> None:
    run_id = (
        import_payload["analysis_run_id"]
        if "analysis_run_id" in import_payload
        else import_payload["id"]
    )
    assert summary["id"] == run_id
    assert summary["project_id"] == context.project_id
    assert summary["status"] == expected_status
    assert finding_count(findings) == summary["finding_count"]
    for finding in finding_items(findings):
        if "analysis_run_id" in finding:
            assert finding["analysis_run_id"] == run_id
        if "project_id" in finding:
            assert finding["project_id"] == context.project_id


def assert_no_workflow_path_leak(
    payload: Any,
    context: WorkflowContext,
    *extra_paths: Path,
) -> None:
    serialized = json.dumps(payload, default=str) if not isinstance(payload, str) else payload
    assert_no_sensitive_path_leak(
        serialized,
        context.upload_dir,
        context.report_dir,
        *extra_paths,
    )


def finding_items(findings_payload: dict[str, Any]) -> list[dict[str, Any]]:
    if "items" in findings_payload:
        return findings_payload["items"]
    return findings_payload["data"]


def finding_count(findings_payload: dict[str, Any]) -> int:
    if "total" in findings_payload:
        return findings_payload["total"]
    return findings_payload["count"]
