from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

import pytest
from sqlmodel import Session, select
from utils.import_contracts import (
    assert_no_sensitive_path_leak as _assert_no_sensitive_path_leak,
)
from utils.import_contracts import (
    configure_upload_dir as _configure_upload_dir,
)
from utils.import_contracts import (
    run_count as _run_count,
)
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
)

from app import models as app_models


def test_upload_rejects_oversized_file_without_persisting_run_or_file(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(workbench_api_env, tmp_path, max_upload_mb=1)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("large.txt", b"A" * (1024 * 1024 + 1), "text/plain")},
    )

    assert response.status_code == 413
    assert response.json()["code"] == "upload_too_large"
    assert "Upload exceeds configured limit" in response.text
    assert _run_count(workbench_api_env, uuid.UUID(project["id"])) == 0
    assert not upload_dir.exists()


def test_upload_rejects_aggregate_primary_and_sidecar_size_before_persisting(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(workbench_api_env, tmp_path, max_upload_mb=1)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    max_bytes = 1024 * 1024

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={
            "file": ("sample.txt", b"A" * (max_bytes // 2), "text/plain"),
            "asset_context_file": (
                "asset-context.csv",
                b"B" * ((max_bytes // 2) + 1),
                "text/csv",
            ),
        },
    )

    assert response.status_code == 413
    assert "Upload exceeds configured limit" in response.text
    assert _run_count(workbench_api_env, uuid.UUID(project["id"])) == 0
    assert not upload_dir.exists()


def test_upload_rejects_path_traversal_filename(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    outside = tmp_path / "evil.txt"

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("../../evil.txt", b"CVE-2024-3094\n", "text/plain")},
    )

    assert response.status_code == 422
    assert "Upload filename is not allowed" in response.text
    assert _run_count(workbench_api_env, uuid.UUID(project["id"])) == 0
    assert not outside.exists()
    assert not upload_dir.exists()


@pytest.mark.parametrize(
    ("field_name", "filename", "content_type", "expected_detail"),
    [
        (
            "asset_context_file",
            "../asset-context.csv",
            "text/csv",
            "Upload filename is not allowed",
        ),
        ("vex_file", "..\\openvex.json", "application/json", "Upload filename is not allowed"),
        ("asset_context_file", "asset-context.txt", "text/csv", "Asset context file must be a CSV"),
        (
            "asset_context_file",
            "asset-context.csv",
            "application/json",
            "Asset context content type must be text/csv",
        ),
        ("vex_file", "openvex.txt", "application/json", "VEX file must be a JSON document"),
        (
            "vex_file",
            "openvex.json",
            "text/plain",
            "VEX content type must be application/json",
        ),
    ],
)
def test_upload_rejects_unsafe_or_unsupported_sidecar_uploads(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    field_name: str,
    filename: str,
    content_type: str,
    expected_detail: str,
) -> None:
    upload_dir = _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={
            "file": ("sample.txt", b"CVE-2024-3094\n", "text/plain"),
            field_name: (filename, b"{}", content_type),
        },
    )

    assert response.status_code == 422
    assert expected_detail in response.text
    assert _run_count(workbench_api_env, uuid.UUID(project["id"])) == 0
    assert not upload_dir.exists()


@pytest.mark.parametrize(
    ("form_data", "expected_detail"),
    [
        (
            {
                "provider_snapshot_file": "/tmp/private-snapshot.json",
                "locked_provider_data": "true",
            },
            "Provider snapshot path is not allowed",
        ),
        (
            {
                "provider_snapshot_file": "../demo_provider_snapshot.json",
                "locked_provider_data": "true",
            },
            "Provider snapshot path is not allowed",
        ),
        (
            {
                "provider_snapshot_file": "demo_provider_snapshot.txt",
                "locked_provider_data": "true",
            },
            "Provider snapshot path is not allowed",
        ),
        (
            {"provider_snapshot_file": "missing.json", "locked_provider_data": "true"},
            "Provider snapshot file does not exist",
        ),
        (
            {"attack_mapping_file": "../mapping.json"},
            "ATT&CK artifact path is not allowed",
        ),
    ],
)
def test_upload_rejects_untrusted_provider_and_attack_artifact_paths(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    form_data: dict[str, str],
    expected_detail: str,
) -> None:
    upload_dir = _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list", **form_data},
        files={"file": ("sample.txt", b"CVE-2024-3094\n", "text/plain")},
    )

    assert response.status_code == 422
    assert expected_detail in response.text
    assert _run_count(workbench_api_env, uuid.UUID(project["id"])) == 0
    assert not upload_dir.exists()


def test_parse_errors_are_structured_and_failed_run_is_persisted(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    content = b"CVE-2024-3094\nnot-a-cve\n"
    expected_sha256 = hashlib.sha256(content).hexdigest()

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("bad.txt", content, "text/plain")},
    )

    assert response.status_code == 422
    assert response.json()["code"] == "import_parse_failed"
    detail = response.json()["detail"]
    assert detail["message"] == "Import parsing failed."
    assert detail["analysis_run_id"]
    assert detail["ignored_lines"] == 0
    assert detail["parse_errors"][0]["input_type"] == "cve-list"
    assert detail["parse_errors"][0]["filename"] == "bad.txt"
    assert detail["parse_errors"][0]["line"] == 2
    assert detail["parse_errors"][0]["field"] == "cve_id"
    assert detail["parse_errors"][0]["value"] == "not-a-cve"
    assert "line 2" in detail["parse_errors"][0]["message"]
    assert "not-a-cve" in detail["parse_errors"][0]["message"]
    _assert_no_sensitive_path_leak(detail["parse_errors"], tmp_path, upload_dir)

    run = workbench_api_env.client.get(
        f"/api/v1/runs/{detail['analysis_run_id']}",
        headers=headers,
    )
    assert run.status_code == 200
    payload = run.json()
    assert payload["status"] == "failed"
    assert [item["status"] for item in payload["import_job"]["status_history"]] == [
        "pending",
        "running",
        "failed",
    ]
    assert payload["workflow_error"]["parse_errors"] == detail["parse_errors"]
    _assert_no_sensitive_path_leak(payload["workflow_error"]["parse_errors"], tmp_path, upload_dir)
    assert payload["input_upload"]["sha256"] == expected_sha256
    upload_ref = payload["input_upload"]["path"]
    assert not Path(upload_ref).is_absolute()
    assert (upload_dir / upload_ref).read_bytes() == content

    metadata = workbench_api_env.client.get(
        f"/api/v1/runs/{detail['analysis_run_id']}/workflow-metadata",
        headers=headers,
    )
    assert metadata.status_code == 200
    metadata_payload = metadata.json()
    assert metadata_payload["status"] == "failed"
    assert metadata_payload["summary"]["parse_errors"] == detail["parse_errors"]
    assert metadata_payload["error"]["parse_errors"] == detail["parse_errors"]
    assert metadata_payload["summary"]["input_upload"]["sha256"] == expected_sha256
    _assert_no_sensitive_path_leak(metadata_payload, tmp_path, upload_dir)

    summary = workbench_api_env.client.get(
        f"/api/v1/runs/{detail['analysis_run_id']}/summary",
        headers=headers,
    )
    assert summary.status_code == 200
    summary_payload = summary.json()
    assert summary_payload["status"] == "failed"
    assert summary_payload["created_findings"] == 0
    assert summary_payload["updated_findings"] == 0
    assert summary_payload["ignored_lines"] == 0
    assert summary_payload["parse_errors"] == detail["parse_errors"]
    with Session(workbench_api_env.engine) as session:
        import_event = session.exec(
            select(app_models.AuditEvent).where(
                app_models.AuditEvent.action == "import.run",
                app_models.AuditEvent.resource_id == detail["analysis_run_id"],
            )
        ).one()
    assert import_event.status == "failure"
    assert import_event.project_id == uuid.UUID(project["id"])
    assert import_event.detail_json == {"stage": "parse", "input_type": "cve-list"}


def test_xml_parse_errors_redact_local_upload_paths(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "nessus-xml"},
        files={
            "file": (
                "broken.nessus",
                b"<NessusClientData_v2><Report>",
                "application/xml",
            ),
        },
    )

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["message"] == "Import parsing failed."
    assert detail["parse_errors"][0]["filename"] == "broken.nessus"
    assert detail["parse_errors"][0]["input_type"] == "nessus-xml"
    _assert_no_sensitive_path_leak(detail["parse_errors"], tmp_path, upload_dir)

    run = workbench_api_env.client.get(
        f"/api/v1/runs/{detail['analysis_run_id']}",
        headers=headers,
    )
    assert run.status_code == 200
    run_payload = run.json()
    assert run_payload["status"] == "failed"
    assert run_payload["workflow_error"]["parse_errors"] == detail["parse_errors"]
    _assert_no_sensitive_path_leak(
        run_payload["workflow_error"]["parse_errors"], tmp_path, upload_dir
    )


@pytest.mark.parametrize(
    ("filename", "content_type", "content", "expected_status", "expected_detail"),
    [
        (
            "../assets.csv",
            "text/csv",
            b"target_kind,target_ref,asset_id\n",
            422,
            "Upload filename is not allowed",
        ),
        (
            "assets.txt",
            "text/csv",
            b"target_kind,target_ref,asset_id\n",
            422,
            "Asset context file must be a CSV",
        ),
        (
            "assets.csv",
            "application/json",
            b"target_kind,target_ref,asset_id\n",
            422,
            "Asset context content type must be text/csv",
        ),
        (
            "assets.csv",
            "text/csv",
            b"target_kind,target_ref,asset_id,match_mode\nhost,^(a+)+$,asset-redos,regex\n",
            422,
            "regex at row 1 is unsafe",
        ),
        (
            "assets.csv",
            "text/csv",
            b"A" * ((1024 * 1024) + 1),
            413,
            "Upload exceeds configured limit",
        ),
    ],
)
def test_asset_context_import_rejects_unsafe_uploads(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    filename: str,
    content_type: str,
    content: bytes,
    expected_status: int,
    expected_detail: str,
) -> None:
    _configure_upload_dir(workbench_api_env, tmp_path, max_upload_mb=1)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/assets/import",
        headers=headers,
        files={"asset_context_file": (filename, content, content_type)},
    )

    assert response.status_code == expected_status
    assert expected_detail in response.text
