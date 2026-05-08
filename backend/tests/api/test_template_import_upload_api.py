from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from dataclasses import replace
from pathlib import Path

import pytest
from sqlmodel import Session, select
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from utils.template_workbench import (
    TemplateApiEnv,
    auth_headers,
    create_project_via_api,
)

from app import models as app_models
from app.core.config import Settings
from app.core.db import ensure_configured_superuser
from app.domain.import_asset_context import (
    canonicalize_asset_criticality_value,
    canonicalize_asset_environment_value,
    canonicalize_asset_exposure_value,
)
from app.main import _upload_size_guard
from app.services import TemplateAnalysisError
from app.services import import_uploads as upload_helpers
from app.services.import_errors import ImportServiceError
from app.services.import_execution import (
    ImportUploadContent,
    ProjectImportUploadRequest,
    execute_project_import_upload,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SAMPLE_CVES = PROJECT_ROOT / "data" / "sample_cves.txt"
TRIVY_REPORT = PROJECT_ROOT / "data" / "input_fixtures" / "trivy_report.json"
OPENVEX = PROJECT_ROOT / "data" / "input_fixtures" / "openvex_statements.json"
CYCLONEDX_VEX = PROJECT_ROOT / "data" / "input_fixtures" / "cyclonedx_vex.json"
ATTACK_MAPPING = PROJECT_ROOT / "data" / "attack" / "local_curated_low_confidence_vpw058.yml"


def test_import_asset_context_adapter_reuses_core_alias_canonicalization() -> None:
    assert canonicalize_asset_exposure_value("private") == "internal"
    assert canonicalize_asset_exposure_value("internal") == "internal"
    assert canonicalize_asset_environment_value("qa") == "test"
    assert canonicalize_asset_environment_value("test") == "test"
    assert canonicalize_asset_criticality_value("crit") == "critical"
    assert canonicalize_asset_criticality_value("critical") == "critical"


def test_import_upload_helper_rejects_oversized_chunks_and_protocol_default(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    class ChunkedUpload:
        def __init__(self, chunks: list[bytes]) -> None:
            self.chunks = chunks

        async def read(self, size: int = -1) -> bytes:
            return self.chunks.pop(0) if self.chunks else b""

    active_settings = replace(
        template_api_env.client.app.state.workbench_settings,
        IMPORT_UPLOAD_DIR=str(tmp_path / "uploads"),
        MAX_UPLOAD_MB=1,
    )

    assert (
        asyncio.run(
            upload_helpers.read_bounded_upload(
                ChunkedUpload([b"hello", b"world"]),
                settings=active_settings,
                max_bytes=16,
            )
        )
        == b"helloworld"
    )
    with pytest.raises(ImportServiceError, match="Upload exceeds configured limit"):
        asyncio.run(
            upload_helpers.read_bounded_upload(
                ChunkedUpload([b"abc", b"def"]),
                settings=active_settings,
                max_bytes=5,
            )
        )
    with pytest.raises(NotImplementedError):
        asyncio.run(upload_helpers.ReadableUpload.read(object()))  # type: ignore[misc]


def test_upload_middleware_rejects_streaming_body_without_content_length() -> None:
    response = asyncio.run(
        _run_upload_size_guard(
            [
                {
                    "type": "http.request",
                    "body": b"A" * (1024 * 1024),
                    "more_body": True,
                },
                {
                    "type": "http.request",
                    "body": b"B" * (128 * 1024),
                    "more_body": False,
                },
            ],
        )
    )

    assert response.status_code == 413


def test_upload_middleware_allows_streaming_body_within_limit() -> None:
    response = asyncio.run(
        _run_upload_size_guard(
            [
                {
                    "type": "http.request",
                    "body": b"CVE-2024-3094\n",
                    "more_body": False,
                },
            ],
        )
    )

    assert response.status_code == 200


def test_import_upload_helper_edge_validations_and_safe_names(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    active_settings = replace(
        template_api_env.client.app.state.workbench_settings,
        IMPORT_UPLOAD_DIR=str(tmp_path / "uploads"),
        MAX_UPLOAD_MB=1,
    )

    with pytest.raises(ImportServiceError, match="Upload exceeds configured limit"):
        upload_helpers.validate_aggregate_upload_size(
            settings=active_settings,
            payloads=[b"x" * active_settings.max_upload_bytes, b"y"],
        )
    upload_helpers.validate_asset_context_upload("context.csv", "application/octet-stream")
    upload_helpers.validate_vex_upload("openvex.json", "")
    assert (
        upload_helpers.sanitize_context_filename(
            "input.txt",
            reserved_filename="input.txt",
        )
        == "asset_context_input.txt"
    )
    assert (
        upload_helpers.sanitize_vex_filename(
            "input.txt",
            reserved_filenames={"input.txt", None},
        )
        == "vex_input.txt"
    )
    assert upload_helpers.ignored_line_count("cve-list", b"\xff\xfe") == 0
    upload_helpers.validate_mime_hint("application/octet-stream", input_type="trivy-json")
    with pytest.raises(ImportServiceError, match="Upload filename is not allowed"):
        upload_helpers.reject_unsafe_upload_filename("bad\x00name.txt")
    with pytest.raises(ImportServiceError, match="input_type is required"):
        upload_helpers.normalize_input_type("   ")


def test_import_upload_store_rejects_escape_and_cleans_failed_write(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    active_settings = replace(
        template_api_env.client.app.state.workbench_settings,
        IMPORT_UPLOAD_DIR=str(tmp_path / "uploads"),
    )
    project_id = uuid.uuid4()
    run_id = uuid.uuid4()

    with pytest.raises(ImportServiceError, match="Upload path is not allowed"):
        upload_helpers.store_upload(
            active_settings,
            project_id=project_id,
            run_id=run_id,
            filename="../../../escape.txt",
            content=b"blocked",
        )

    target_dir = active_settings.import_upload_dir_path / str(project_id) / str(run_id)
    with pytest.raises(IsADirectoryError):
        upload_helpers.store_upload(
            active_settings,
            project_id=project_id,
            run_id=run_id,
            filename=".",
            content=b"cannot write to directory",
        )
    assert not target_dir.exists()


def test_valid_cve_list_upload_creates_analysis_run_and_stores_sha256(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    content = b"CVE-2024-3094\nCVE-2021-44228\n"
    expected_sha256 = hashlib.sha256(content).hexdigest()

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("Team Scan (prod).txt", content, "text/plain")},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["project_id"] == project["id"]
    assert payload["input_type"] == "cve-list"
    assert payload["filename"] == "Team_Scan__prod_.txt"
    assert payload["status"] == "succeeded"
    assert payload["summary_json"]["input_sha256"] == expected_sha256
    assert payload["summary_json"]["occurrence_count"] == 2
    assert payload["summary_json"]["finding_count"] == 2
    assert payload["summary_json"]["dedup_summary"]["created_findings"] == 2
    assert payload["summary_json"]["dedup_summary"]["reused_findings"] == 0
    assert payload["provider_snapshot_id"]
    assert payload["summary_json"]["provider_snapshot_id"] == payload["provider_snapshot_id"]
    assert payload["summary_json"]["analysis_service"]["pipeline"] == (
        "parse-persist-enrich-score-explain"
    )
    assert payload["summary_json"]["counts_by_priority"] == {
        "Critical": 2,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }
    assert payload["summary_json"]["kev_hits"] >= 1
    assert payload["summary_json"]["created_findings"] == 2
    assert payload["summary_json"]["updated_findings"] == 0
    assert payload["summary_json"]["ignored_lines"] == 0
    assert payload["summary_json"]["input_upload"]["sha256"] == expected_sha256
    assert payload["summary_json"]["input_upload"]["original_filename"] == "Team Scan (prod).txt"
    assert payload["summary_json"]["input_upload"]["stored_filename"] == "Team_Scan__prod_.txt"
    stored_ref = payload["summary_json"]["input_upload"]["path"]
    assert stored_ref == f"{project['id']}/{payload['id']}/Team_Scan__prod_.txt"
    assert payload["summary_json"]["input_upload"]["storage_ref"] == stored_ref
    assert not Path(stored_ref).is_absolute()
    stored_path = upload_dir / stored_ref
    assert stored_path == upload_dir / project["id"] / payload["id"] / "Team_Scan__prod_.txt"
    assert stored_path.read_bytes() == content
    assert payload["summary_json"]["import_job"]["status"] == "succeeded"
    assert payload["summary_json"]["import_job"]["execution_mode"] == "request"
    assert [item["status"] for item in payload["summary_json"]["import_job"]["status_history"]] == [
        "pending",
        "running",
        "succeeded",
    ]
    assert payload["summary_json"]["parse_errors"] == []

    runs = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/runs/",
        headers=headers,
    )
    assert runs.status_code == 200
    assert runs.json()["count"] == 1
    assert runs.json()["data"][0]["id"] == payload["id"]
    assert runs.json()["data"][0]["status"] == "succeeded"
    with Session(template_api_env.engine) as session:
        import_event = session.exec(
            select(app_models.AuditEvent).where(
                app_models.AuditEvent.action == "import.run",
                app_models.AuditEvent.resource_id == payload["id"],
            )
        ).one()
    assert import_event.status == "success"
    assert import_event.project_id == uuid.UUID(project["id"])
    assert import_event.detail_json == {"stage": "succeeded", "input_type": "cve-list"}

    findings = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200
    finding_payloads = findings.json()["data"]
    assert findings.json()["count"] == 2
    assert {item["priority"] for item in finding_payloads} == {"critical"}
    assert all(item["risk_score"] is not None for item in finding_payloads)
    assert all(item["operational_rank"] > 0 for item in finding_payloads)
    assert all(item["explanation_json"]["explanation"]["reasons"] for item in finding_payloads)
    assert all(
        item["explanation_json"]["decision_guidance"]["decision_statement"]
        for item in finding_payloads
    )

    summary = template_api_env.client.get(
        f"/api/v1/runs/{payload['id']}/summary",
        headers=headers,
    )
    assert summary.status_code == 200
    summary_payload = summary.json()
    assert summary_payload["id"] == payload["id"]
    assert summary_payload["project_id"] == project["id"]
    assert summary_payload["status"] == "succeeded"
    assert summary_payload["created_findings"] == 2
    assert summary_payload["updated_findings"] == 0
    assert summary_payload["ignored_lines"] == 0
    assert summary_payload["occurrence_count"] == 2
    assert summary_payload["finding_count"] == 2
    assert summary_payload["provider_snapshot_id"] == payload["provider_snapshot_id"]
    assert summary_payload["counts_by_priority"] == payload["summary_json"]["counts_by_priority"]
    assert summary_payload["kev_hits"] == payload["summary_json"]["kev_hits"]
    assert summary_payload["parse_errors"] == []
    assert summary_payload["input_upload"]["sha256"] == expected_sha256


def test_import_upload_service_can_defer_and_resume_background_execution(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    active_settings = template_api_env.client.app.state.workbench_settings
    upload = ProjectImportUploadRequest(
        input_type="cve-list",
        file=ImportUploadContent(
            filename="background-cves.txt",
            content_type="text/plain",
            content=b"CVE-2024-3094\n",
        ),
    )

    with Session(template_api_env.engine) as session:
        current_user = ensure_configured_superuser(session, active_settings=active_settings)
        deferred_run = asyncio.run(
            execute_project_import_upload(
                project_id=uuid.UUID(project["id"]),
                session=session,
                current_user=current_user,
                settings=active_settings,
                upload=upload,
                defer_execution=True,
                execution_mode="background",
            )
        )
        deferred_summary = deferred_run.summary_json

        assert deferred_run.status == app_models.AnalysisRunStatus.PENDING
        assert deferred_summary["import_job"]["status"] == "pending"
        assert deferred_summary["import_job"]["execution_mode"] == "background"
        assert [item["status"] for item in deferred_summary["import_job"]["status_history"]] == [
            "pending"
        ]
        stored_ref = deferred_summary["input_upload"]["storage_ref"]
        assert (upload_dir / stored_ref).read_bytes() == b"CVE-2024-3094\n"

        resumed_run = asyncio.run(
            execute_project_import_upload(
                project_id=uuid.UUID(project["id"]),
                session=session,
                current_user=current_user,
                settings=active_settings,
                upload=upload,
                existing_run_id=deferred_run.id,
                execution_mode="background",
            )
        )

        assert resumed_run.id == deferred_run.id
        assert resumed_run.status == app_models.AnalysisRunStatus.SUCCEEDED
        assert resumed_run.summary_json["import_job"]["execution_mode"] == "background"
        assert [
            item["status"] for item in resumed_run.summary_json["import_job"]["status_history"]
        ] == ["pending", "running", "succeeded"]
        assert resumed_run.summary_json["created_findings"] == 1


def test_template_import_uses_demo_snapshot_without_network_or_keys(
    monkeypatch: pytest.MonkeyPatch,
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    for env_name in ("NVD_API_KEY", "FIRST_API_KEY"):
        monkeypatch.delenv(env_name, raising=False)
    for proxy_name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(proxy_name, "http://127.0.0.1:9")
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={
            "input_type": "cve-list",
            "provider_snapshot_file": "demo_provider_snapshot.json",
            "locked_provider_data": "true",
        },
        files={"file": ("sample_cves.txt", SAMPLE_CVES.read_bytes(), "text/plain")},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    summary = payload["summary_json"]
    assert payload["status"] == "succeeded"
    assert summary["locked_provider_data"] is True
    assert summary["provider_snapshot_file"] == "demo_provider_snapshot.json"
    assert summary["provider_snapshot_id"] == payload["provider_snapshot_id"]
    assert summary["finding_count"] > 0
    assert summary["kev_hits"] > 0
    with Session(template_api_env.engine) as session:
        snapshot = session.get(
            app_models.ProviderSnapshot,
            uuid.UUID(payload["provider_snapshot_id"]),
        )
        assert snapshot is not None
        assert snapshot.content_hash
        assert set(snapshot.source_hashes_json) == {"provider_snapshot"}


def test_attack_import_exposes_template_finding_ttp_context(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={
            "input_type": "trivy-json",
            "attack_source": "local-curated",
            "attack_mapping_file": ATTACK_MAPPING.name,
        },
        files={"file": ("trivy.json", TRIVY_REPORT.read_bytes(), "application/json")},
    )

    assert response.status_code == 200, response.text
    run_payload = response.json()
    assert run_payload["summary_json"]["attack_mapped_cves"] == 1
    assert run_payload["summary_json"]["attack_source"] == "local-curated"

    findings = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
        params={"sort": "cve"},
    )
    assert findings.status_code == 200
    finding_items = findings.json()["data"]
    mapped = next(item for item in finding_items if item["cve_id"] == "CVE-2023-34362")
    unmapped = next(item for item in finding_items if item["cve_id"] == "CVE-2024-3094")

    mapped_detail = template_api_env.client.get(
        f"/api/v1/findings/{mapped['id']}",
        headers=headers,
    )
    assert mapped_detail.status_code == 200
    attack_context = mapped_detail.json()["attack_context"]
    assert attack_context["mapped"] is True
    assert attack_context["source"] == "local-curated"
    assert attack_context["confidence"] == "low"
    assert attack_context["low_confidence"] is True
    assert attack_context["review_status"] == "needs_review"
    assert attack_context["mappings"][0]["technique_id"] == "T1190"
    assert "reviewed" in attack_context["mappings"][0]["rationale"].lower()
    assert "payload" not in attack_context["mappings"][0]["rationale"].lower()
    assert attack_context["techniques"][0]["technique_id"] == "T1190"
    assert "initial-access" in attack_context["tactics"]
    assert "defensive triage" in attack_context["defensive_note"]

    unmapped_detail = template_api_env.client.get(
        f"/api/v1/findings/{unmapped['id']}",
        headers=headers,
    )
    assert unmapped_detail.status_code == 200
    empty_context = unmapped_detail.json()["attack_context"]
    assert empty_context["mapped"] is False
    assert empty_context["mappings"] == []
    assert empty_context["techniques"] == []


def test_attack_summary_api_rolls_up_top_techniques_and_confidence(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    import_response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={
            "input_type": "trivy-json",
            "attack_source": "local-curated",
            "attack_mapping_file": ATTACK_MAPPING.name,
        },
        files={"file": ("trivy.json", TRIVY_REPORT.read_bytes(), "application/json")},
    )
    assert import_response.status_code == 200, import_response.text

    response = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/attack/summary",
        headers=headers,
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["project_id"] == project["id"]
    assert payload["finding_count"] == 3
    assert payload["mapped_finding_count"] == 1
    assert payload["unmapped_finding_count"] == 2
    assert payload["mapped_coverage_percent"] == 33.3
    assert payload["confidence_distribution"] == {
        "high": 0,
        "medium": 0,
        "low": 1,
        "unknown": 0,
    }
    assert payload["review_status_counts"]["needs_review"] == 1
    assert payload["source_counts"] == {"local-curated": 1}
    assert payload["top_techniques"][0]["technique_id"] == "T1190"
    assert payload["top_techniques"][0]["name"] == "Exploit Public-Facing Application"
    assert payload["top_techniques"][0]["finding_count"] == 1
    assert payload["top_techniques"][0]["confidence_counts"]["low"] == 1
    assert "initial-access" in payload["top_techniques"][0]["tactics"]
    assert payload["top_tactics"][0]["tactic"] == "initial-access"
    assert "defensive triage context only" in payload["defensive_note"]


def test_decision_api_endpoints_expose_explain_summary_and_cvss_comparison(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    content = b"CVE-2021-44228\nCVE-2024-3094\n"

    import_response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("decision-api.txt", content, "text/plain")},
    )
    assert import_response.status_code == 200
    run_payload = import_response.json()
    assert not Path(run_payload["summary_json"]["input_upload"]["path"]).is_absolute()

    findings_response = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings_response.status_code == 200
    findings_payload = findings_response.json()
    assert findings_payload["count"] == 2
    finding_id = findings_payload["data"][0]["id"]

    explain_response = template_api_env.client.get(
        f"/api/v1/findings/{finding_id}/explain",
        headers=headers,
    )
    assert explain_response.status_code == 200
    explain_payload = explain_response.json()
    assert explain_payload["finding_id"] == finding_id
    assert explain_payload["project_id"] == project["id"]
    assert explain_payload["priority"] == "critical"
    assert explain_payload["decision_explanation"]["reason_codes"]
    assert explain_payload["decision_guidance"]["decision_statement"]
    assert explain_payload["provider_evidence"]["nvd"]
    assert explain_payload["data_quality_confidence"] in {"high", "medium", "low"}

    project_summary_response = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/summary",
        headers=headers,
    )
    assert project_summary_response.status_code == 200
    project_summary = project_summary_response.json()
    assert project_summary["project_id"] == project["id"]
    assert project_summary["finding_count"] == 2
    assert project_summary["open_finding_count"] == 2
    assert project_summary["counts_by_priority"] == {
        "Critical": 2,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }
    assert project_summary["counts_by_status"] == {
        "open": 2,
        "in_review": 0,
        "remediating": 0,
        "fixed": 0,
        "accepted": 0,
        "suppressed": 0,
    }
    assert project_summary["kev_hits"] >= 1
    assert project_summary["epss_hits"] == 2
    assert project_summary["cvss_known_count"] == 2
    assert project_summary["latest_run_id"] == run_payload["id"]
    assert project_summary["latest_run_status"] == "succeeded"

    comparison_response = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/compare/cvss-only",
        headers=headers,
    )
    assert comparison_response.status_code == 200
    comparison_payload = comparison_response.json()
    assert comparison_payload["project_id"] == project["id"]
    assert comparison_payload["methodology"]["baseline"] == "cvss-only"
    assert comparison_payload["summary"]["total"] == 2
    assert comparison_payload["counts"]["enriched"] == {
        "Critical": 2,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }
    assert {item["cve_id"] for item in comparison_payload["comparisons"]} == {
        "CVE-2021-44228",
        "CVE-2024-3094",
    }


def test_double_import_deduplicates_findings_and_appends_occurrences(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    content = "\n".join(
        [
            "cve_id,asset_ref,component,version,purl,severity,owner,business_service,exposure",
            (
                "CVE-2024-3094,build-host-1,xz,5.6.0,"
                "pkg:apk/alpine/xz@5.6.0-r0,CRITICAL,team-platform,payments,public"
            ),
            (
                "CVE-2024-4577,web-tier,php-cgi,8.3.7,"
                "pkg:deb/debian/php-cgi@8.3.7,HIGH,team-web,checkout,internal"
            ),
            "",
        ]
    ).encode()

    first = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("occurrences.csv", content, "text/csv")},
    )
    assert first.status_code == 200, first.text
    first_payload = first.json()
    assert first_payload["summary_json"]["dedup_summary"]["created_findings"] == 2
    assert first_payload["summary_json"]["dedup_summary"]["reused_findings"] == 0
    assert {
        item["action"] for item in first_payload["summary_json"]["dedup_summary"]["decisions"]
    } == {"created"}

    first_findings, first_occurrence_count = _finding_state(template_api_env, project_id)
    first_decisions = _decision_state(first_findings)
    first_seen = {finding.cve_id: finding.first_seen_at for finding in first_findings}
    first_last_seen = {finding.cve_id: finding.last_seen_at for finding in first_findings}
    first_dedup_keys = {finding.cve_id: finding.dedup_key for finding in first_findings}

    second = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("occurrences.csv", content, "text/csv")},
    )
    assert second.status_code == 200, second.text
    second_payload = second.json()
    dedup_summary = second_payload["summary_json"]["dedup_summary"]
    assert second_payload["summary_json"]["occurrence_count"] == 2
    assert second_payload["summary_json"]["finding_count"] == 2
    assert second_payload["summary_json"]["created_findings"] == 0
    assert second_payload["summary_json"]["updated_findings"] == 2
    assert dedup_summary["created_findings"] == 0
    assert dedup_summary["updated_findings"] == 2
    assert dedup_summary["reused_findings"] == 2
    assert dedup_summary["decision_count"] == 2
    assert {item["action"] for item in dedup_summary["decisions"]} == {"reused"}
    assert all(item["dedup_key"].startswith("vpw019:") for item in dedup_summary["decisions"])
    assert all(
        item["asset_ref"] in {"build-host-1", "web-tier"} for item in dedup_summary["decisions"]
    )

    second_findings, second_occurrence_count = _finding_state(template_api_env, project_id)
    second_decisions = _decision_state(second_findings)
    assert len(first_findings) == 2
    assert first_occurrence_count == 2
    assert len(second_findings) == 2
    assert second_occurrence_count == 4
    assert second_decisions == first_decisions
    assert {finding.cve_id: finding.first_seen_at for finding in second_findings} == first_seen
    assert {finding.cve_id: finding.dedup_key for finding in second_findings} == first_dedup_keys
    assert all(
        finding.last_seen_at > first_last_seen[finding.cve_id] for finding in second_findings
    )
    findings_response = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
        params={"sort": "cve"},
    )
    assert findings_response.status_code == 200, findings_response.text
    findings_by_cve = {item["cve_id"]: item for item in findings_response.json()["data"]}
    assert findings_by_cve["CVE-2024-3094"]["component_name"] == "xz"
    assert findings_by_cve["CVE-2024-3094"]["component_version"] == "5.6.0"
    assert findings_by_cve["CVE-2024-3094"]["asset_key"] == "build-host-1"
    assert findings_by_cve["CVE-2024-3094"]["owner"] == "team-platform"
    assert findings_by_cve["CVE-2024-3094"]["business_service"] == "payments"
    assert findings_by_cve["CVE-2024-3094"]["exposure"] == "internet-facing"
    assert findings_by_cve["CVE-2024-4577"]["owner"] == "team-web"
    assert findings_by_cve["CVE-2024-4577"]["business_service"] == "checkout"
    assert findings_by_cve["CVE-2024-4577"]["exposure"] == "internal"

    findings = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200
    assert findings.json()["count"] == 2

    summary = template_api_env.client.get(
        f"/api/v1/runs/{second_payload['id']}/summary",
        headers=headers,
    )
    assert summary.status_code == 200
    summary_payload = summary.json()
    assert summary_payload["created_findings"] == 0
    assert summary_payload["updated_findings"] == 2
    assert summary_payload["occurrence_count"] == 2
    assert summary_payload["finding_count"] == 2
    assert summary_payload["dedup_summary"]["reused_findings"] == 2
    assert {item["action"] for item in summary_payload["dedup_summary"]["decisions"]} == {"reused"}
    assert (
        summary_payload["counts_by_priority"]
        == second_payload["summary_json"]["counts_by_priority"]
    )


def test_same_batch_duplicate_bulk_import_reuses_finding_and_appends_occurrences(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    duplicate_rows = [
        "CVE-2024-3094,duplicate-host,CRITICAL,team-platform,payments,public" for _ in range(1000)
    ]
    content = "\n".join(
        [
            "cve_id,asset_ref,severity,owner,business_service,exposure",
            *duplicate_rows,
            "",
        ]
    ).encode()

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("duplicate-occurrences.csv", content, "text/csv")},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    dedup_summary = payload["summary_json"]["dedup_summary"]
    assert payload["summary_json"]["occurrence_count"] == 1000
    assert payload["summary_json"]["finding_count"] == 1
    assert payload["summary_json"]["created_findings"] == 1
    assert payload["summary_json"]["updated_findings"] == 999
    assert dedup_summary["created_findings"] == 1
    assert dedup_summary["updated_findings"] == 999
    assert dedup_summary["reused_findings"] == 999
    assert dedup_summary["decision_count"] == 1000
    assert dedup_summary["omitted_decisions"] == 500
    assert {item["action"] for item in dedup_summary["decisions"]} == {
        "created",
        "reused",
    }
    assert len({item["dedup_key"] for item in dedup_summary["decisions"]}) == 1

    findings, occurrence_count = _finding_state(template_api_env, project_id)
    assert len(findings) == 1
    assert occurrence_count == 1000
    assert findings[0].cve_id == "CVE-2024-3094"
    assert findings[0].asset_id is not None
    with Session(template_api_env.engine) as session:
        asset = session.get(app_models.Asset, findings[0].asset_id)
    assert asset is not None
    assert asset.asset_key == "duplicate-host"


def test_import_upload_applies_asset_context_sidecar_to_template_findings(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    occurrence_csv = "\n".join(
        [
            "cve_id,asset_ref,component,version,purl,severity",
            "CVE-2024-3094,web-tier,xz,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,CRITICAL",
            "",
        ]
    ).encode()
    asset_context_csv = "\n".join(
        [
            (
                "target_kind,target_ref,asset_id,owner,business_service,"
                "criticality,exposure,environment"
            ),
            "generic,web-tier,asset-web-1,team-platform,payments,critical,public,prod",
            "",
        ]
    ).encode()
    expected_sidecar_sha256 = hashlib.sha256(asset_context_csv).hexdigest()

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={
            "file": ("occurrences.csv", occurrence_csv, "text/csv"),
            "asset_context_file": ("asset-context.csv", asset_context_csv, "text/csv"),
        },
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    sidecar_upload = payload["summary_json"]["asset_context_upload"]
    assert sidecar_upload["sha256"] == expected_sidecar_sha256
    assert sidecar_upload["stored_filename"] == "asset-context.csv"
    assert not Path(sidecar_upload["path"]).is_absolute()
    assert (upload_dir / sidecar_upload["path"]).read_bytes() == asset_context_csv
    assert payload["summary_json"]["asset_context"]["loaded_rows"] == 1
    assert payload["summary_json"]["asset_context"]["matched_occurrences"] == 1
    assert payload["summary_json"]["dedup_summary"]["decisions"][0]["asset_ref"] == "asset-web-1"

    findings = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200, findings.text
    finding = findings.json()["data"][0]
    assert finding["asset_key"] == "asset-web-1"
    assert finding["owner"] == "team-platform"
    assert finding["business_service"] == "payments"
    assert finding["asset_environment"] == "production"
    assert finding["asset_criticality"] == "critical"
    assert finding["exposure"] == "internet-facing"
    assert finding["risk_score"] == 100.0

    detail = template_api_env.client.get(f"/api/v1/findings/{finding['id']}", headers=headers)
    assert detail.status_code == 200
    explanation = detail.json()["explanation_json"]
    assert explanation["operational_score"] == 100
    assert "internet-facing asset context: +8" in explanation["operational_score_reasons"]
    assert "production asset context: +5" in explanation["operational_score_reasons"]
    assert "critical asset criticality: +7" in explanation["operational_score_reasons"]
    assert explanation["highest_asset_criticality"] == "critical"
    assert explanation["provenance"]["asset_ids"] == ["asset-web-1"]
    assert explanation["provenance"]["highest_asset_exposure"] == "internet-facing"
    assert explanation["provenance"]["asset_owners"] == ["team-platform"]
    assert explanation["provenance"]["asset_business_services"] == ["payments"]
    occurrence = detail.json()["occurrences"][0]
    assert occurrence["asset_ref"] == "asset-web-1"
    assert occurrence["target_ref"] == "web-tier"
    assert occurrence["asset_owner"] == "team-platform"
    assert occurrence["asset_business_service"] == "payments"
    assert occurrence["asset_exposure"] == "internet-facing"


def test_generic_import_persists_core_canonical_asset_context_aliases(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    occurrence_csv = "\n".join(
        [
            ("cve_id,asset_ref,component,version,purl,severity,criticality,exposure,environment"),
            (
                "CVE-2024-3094,build-host-1,xz,5.6.0,"
                "pkg:apk/alpine/xz@5.6.0-r0,CRITICAL,crit,private,qa"
            ),
            "",
        ]
    ).encode()

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("asset-aliases.csv", occurrence_csv, "text/csv")},
    )

    assert response.status_code == 200, response.text
    findings = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200, findings.text
    finding = findings.json()["data"][0]
    assert finding["asset_key"] == "build-host-1"
    assert finding["asset_environment"] == "test"
    assert finding["asset_criticality"] == "critical"
    assert finding["exposure"] == "internal"

    detail = template_api_env.client.get(f"/api/v1/findings/{finding['id']}", headers=headers)
    assert detail.status_code == 200, detail.text
    explanation = detail.json()["explanation_json"]
    assert explanation["highest_asset_criticality"] == "critical"
    assert explanation["provenance"]["highest_asset_exposure"] == "internal"
    assert explanation["provenance"]["asset_environments"] == ["test"]
    occurrence = detail.json()["occurrences"][0]
    assert occurrence["asset_exposure"] == "internal"

    with Session(template_api_env.engine) as session:
        asset = session.exec(
            select(app_models.Asset).where(app_models.Asset.project_id == project_id)
        ).one()
        assert asset.environment == app_models.AssetEnvironment.TEST
        assert asset.exposure == app_models.AssetExposure.INTERNAL
        assert asset.criticality == app_models.AssetCriticality.CRITICAL


def test_import_upload_applies_openvex_sidecar_to_template_findings(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    occurrence_csv = "\n".join(
        [
            "cve_id,asset_ref,component,version,purl,severity",
            (
                "CVE-2021-44228,log4j-service,log4j-core,2.14.1,"
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1,CRITICAL"
            ),
            "",
        ]
    ).encode()
    vex_bytes = OPENVEX.read_bytes()
    expected_vex_sha256 = hashlib.sha256(vex_bytes).hexdigest()

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={
            "file": ("occurrences.csv", occurrence_csv, "text/csv"),
            "vex_file": ("openvex.json", vex_bytes, "application/json"),
        },
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    vex_upload = payload["summary_json"]["vex_upload"]
    assert vex_upload["sha256"] == expected_vex_sha256
    assert vex_upload["stored_filename"] == "openvex.json"
    assert not Path(vex_upload["path"]).is_absolute()
    assert (upload_dir / vex_upload["path"]).read_bytes() == vex_bytes
    assert payload["summary_json"]["vex"]["statement_count"] == 4
    assert payload["summary_json"]["vex"]["matched_occurrences"] == 1
    assert payload["summary_json"]["suppressed_by_vex"] == 1
    assert payload["summary_json"]["vex_conflict_count"] == 0

    findings = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200, findings.text
    finding = findings.json()["data"][0]
    assert finding["status"] == "fixed"
    assert finding["suppressed_by_vex"] is True
    assert finding["explanation_json"]["priority_state"] == "Fixed"
    assert finding["explanation_json"]["provenance"]["vex_statuses"] == {"fixed": 1}
    vex_reason = next(
        reason
        for reason in finding["explanation_json"]["explanation"]["reasons"]
        if reason["code"] == "governance.vex_status"
    )
    assert "fixed: 1" in vex_reason["message"]
    assert "Upgrade completed for the scoped component." in vex_reason["message"]

    detail = template_api_env.client.get(f"/api/v1/findings/{finding['id']}", headers=headers)
    assert detail.status_code == 200
    occurrence = detail.json()["occurrences"][0]
    assert occurrence["vex_status"] == "fixed"
    assert occurrence["vex_match_type"] == "purl"
    assert occurrence["vex_source_format"] == "openvex-json"
    assert occurrence["vex_source_path"] == "openvex.json"
    assert occurrence["vex_action_statement"] == "Upgrade completed for the scoped component."
    _assert_no_sensitive_path_leak(occurrence, tmp_path, upload_dir)


def test_import_upload_applies_cyclonedx_vex_sidecar_to_template_findings(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    occurrence_csv = "\n".join(
        [
            "cve_id,asset_ref,component,version,purl,severity",
            (
                "CVE-2023-34362,moveit-service,moveit-transfer,2023.0.0,"
                "pkg:pypi/moveit-transfer@2023.0.0,HIGH"
            ),
            ("CVE-2024-4577,php-service,php-cgi,8.1.28,pkg:generic/php-cgi@8.1.28,HIGH"),
            "",
        ]
    ).encode()
    vex_bytes = CYCLONEDX_VEX.read_bytes()

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={
            "file": ("occurrences.csv", occurrence_csv, "text/csv"),
            "vex_file": ("cyclonedx-vex.json", vex_bytes, "application/json"),
        },
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    vex_upload = payload["summary_json"]["vex_upload"]
    assert vex_upload["input_type"] == "vex-json"
    assert vex_upload["stored_filename"] == "cyclonedx-vex.json"
    assert not Path(vex_upload["path"]).is_absolute()
    assert payload["summary_json"]["vex"]["statement_count"] == 3
    assert payload["summary_json"]["vex"]["matched_occurrences"] == 2
    assert payload["summary_json"]["suppressed_by_vex"] == 2

    findings = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200, findings.text
    by_cve = {finding["cve_id"]: finding for finding in findings.json()["data"]}
    assert by_cve["CVE-2023-34362"]["status"] == "suppressed"
    assert by_cve["CVE-2023-34362"]["suppressed_by_vex"] is True
    assert by_cve["CVE-2023-34362"]["explanation_json"]["provenance"]["vex_statuses"] == {
        "not_affected": 1
    }
    assert by_cve["CVE-2024-4577"]["status"] == "fixed"
    assert by_cve["CVE-2024-4577"]["explanation_json"]["priority_state"] == "Fixed"

    detail = template_api_env.client.get(
        f"/api/v1/findings/{by_cve['CVE-2023-34362']['id']}",
        headers=headers,
    )
    assert detail.status_code == 200
    occurrence = detail.json()["occurrences"][0]
    assert occurrence["vex_status"] == "not_affected"
    assert occurrence["vex_match_type"] == "purl"
    assert occurrence["vex_source_format"] == "cyclonedx-vex-json"
    assert occurrence["vex_justification"] == "vulnerable_code_not_present"


def test_import_upload_rejects_invalid_vex_sidecar_with_clear_error(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={
            "file": (
                "occurrences.csv",
                b"cve_id,asset_ref\nCVE-2024-3094,web-tier\n",
                "text/csv",
            ),
            "vex_file": ("bad-openvex.json", b'{"statements": {}}', "application/json"),
        },
    )

    assert response.status_code == 422, response.text
    assert response.json()["code"] == "import_vex_parse_failed"
    assert response.json()["details"]["analysis_run_id"]
    detail = response.json()["detail"]
    assert detail["message"] == "VEX parsing failed."
    assert detail["analysis_run_id"]
    assert detail["vex_error"]["stage"] == "vex_parse"
    assert "OpenVEX JSON `statements`" in detail["vex_error"]["message"]
    assert "uploaded file" in detail["vex_error"]["message"]
    _assert_no_sensitive_path_leak(detail["vex_error"], tmp_path, upload_dir)

    run = template_api_env.client.get(
        f"/api/v1/runs/{detail['analysis_run_id']}",
        headers=headers,
    )
    assert run.status_code == 200
    run_payload = run.json()
    assert run_payload["status"] == "failed"
    assert run_payload["summary_json"]["vex_error"]["stage"] == "vex_parse"
    _assert_no_sensitive_path_leak(run_payload["error_json"]["vex_error"], tmp_path, upload_dir)
    _assert_no_sensitive_path_leak(run_payload["summary_json"]["vex_error"], tmp_path, upload_dir)
    assert run_payload["summary_json"]["created_findings"] == 0
    assert run_payload["summary_json"]["updated_findings"] == 0

    findings = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200
    assert findings.json()["count"] == 0


def test_import_upload_rejects_invalid_asset_context_sidecar_with_clear_error(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={
            "file": (
                "occurrences.csv",
                b"cve_id,asset_ref\nCVE-2024-3094,web-tier\n",
                "text/csv",
            ),
            "asset_context_file": (
                "bad-asset-context.csv",
                b"target_kind,target_ref\nhost,web-tier\n",
                "text/csv",
            ),
        },
    )

    assert response.status_code == 422, response.text
    assert response.json()["code"] == "import_asset_context_parse_failed"
    assert response.json()["details"]["analysis_run_id"]
    detail = response.json()["detail"]
    assert detail["message"] == "Asset context parsing failed."
    assert detail["analysis_run_id"]
    assert detail["asset_context_error"]["stage"] == "asset_context_parse"
    assert "asset_id" in detail["asset_context_error"]["message"]
    _assert_no_sensitive_path_leak(detail["asset_context_error"], tmp_path, upload_dir)

    run = template_api_env.client.get(
        f"/api/v1/runs/{detail['analysis_run_id']}",
        headers=headers,
    )
    assert run.status_code == 200
    run_payload = run.json()
    assert run_payload["status"] == "failed"
    assert run_payload["summary_json"]["asset_context_error"]["stage"] == ("asset_context_parse")
    _assert_no_sensitive_path_leak(
        run_payload["error_json"]["asset_context_error"],
        tmp_path,
        upload_dir,
    )
    _assert_no_sensitive_path_leak(
        run_payload["summary_json"]["asset_context_error"],
        tmp_path,
        upload_dir,
    )
    assert run_payload["summary_json"]["created_findings"] == 0
    assert run_payload["summary_json"]["updated_findings"] == 0

    findings = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200
    assert findings.json()["count"] == 0


def test_analysis_failure_persists_failed_run_without_partial_findings(
    monkeypatch: pytest.MonkeyPatch,
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    def _fail_analysis(*args: object, **kwargs: object) -> object:
        raise TemplateAnalysisError(f"scoring failed for {upload_dir / 'private.json'}")

    monkeypatch.setattr(
        "app.services.import_execution.AnalysisService.analyze_import",
        _fail_analysis,
    )

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("sample.txt", b"CVE-2024-3094\n", "text/plain")},
    )

    assert response.status_code == 422
    assert response.json()["code"] == "import_analysis_failed"
    assert response.json()["details"]["analysis_run_id"]
    detail = response.json()["detail"]
    assert detail["message"] == "Import analysis failed."
    assert detail["analysis_error"]["stage"] == "enrich_score_explain"
    assert "scoring failed" in detail["analysis_error"]["message"]
    assert "uploaded file" in detail["analysis_error"]["message"]
    _assert_no_sensitive_path_leak(detail["analysis_error"], tmp_path, upload_dir)

    run = template_api_env.client.get(
        f"/api/v1/runs/{detail['analysis_run_id']}",
        headers=headers,
    )
    assert run.status_code == 200
    run_payload = run.json()
    assert run_payload["status"] == "failed"
    assert run_payload["summary_json"]["analysis_error"]["stage"] == "enrich_score_explain"
    _assert_no_sensitive_path_leak(
        run_payload["summary_json"]["analysis_error"],
        tmp_path,
        upload_dir,
    )
    _assert_no_sensitive_path_leak(
        run_payload["error_json"]["analysis_error"],
        tmp_path,
        upload_dir,
    )
    assert run_payload["summary_json"]["created_findings"] == 0
    assert run_payload["summary_json"]["updated_findings"] == 0

    findings = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200
    assert findings.json()["count"] == 0


def test_same_cve_on_different_assets_creates_distinct_findings(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    content = "\n".join(
        [
            "cve_id,asset_ref,component,version,purl,severity",
            "CVE-2024-3094,build-host-1,xz,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,CRITICAL",
            "CVE-2024-3094,build-host-2,xz,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,CRITICAL",
            "",
        ]
    ).encode()

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("same-cve-assets.csv", content, "text/csv")},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["summary_json"]["finding_count"] == 2
    assert payload["summary_json"]["analysis_semantics"] == {
        "analysis_decision_scope": "cve_baseline_with_occurrence_overlays",
        "persistence_scope": "asset_component_occurrence",
        "occurrence_overlay_fields": [
            "asset_context",
            "component_identity",
            "source_identity",
            "vex_status",
        ],
        "finding_dedup_key_version": "vpw019-v1",
        "cve_count": 1,
        "occurrence_count": 2,
        "finding_count": 2,
        "same_cve_can_create_distinct_asset_findings": True,
    }
    assert payload["summary_json"]["dedup_summary"]["created_findings"] == 2
    assert {
        item["asset_ref"] for item in payload["summary_json"]["dedup_summary"]["decisions"]
    } == {"build-host-1", "build-host-2"}

    findings, occurrence_count = _finding_state(template_api_env, project_id)
    assert len(findings) == 2
    assert occurrence_count == 2
    assert len({finding.dedup_key for finding in findings}) == 2


def test_same_cve_vex_status_remains_occurrence_scoped(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    content = "\n".join(
        [
            "cve_id,asset_ref,component,version,purl,severity",
            (
                "CVE-2021-44228,log4j-fixed,log4j-core,2.14.1,"
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1,CRITICAL"
            ),
            (
                "CVE-2021-44228,log4j-open,log4j-core,2.13.0,"
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.13.0,CRITICAL"
            ),
            "",
        ]
    ).encode()
    vex = json.dumps(
        {
            "statements": [
                {
                    "action_statement": "Upgrade completed for the scoped component.",
                    "products": [
                        {
                            "identifiers": {
                                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                            },
                        },
                    ],
                    "status": "fixed",
                    "vulnerability": {"name": "CVE-2021-44228"},
                }
            ]
        }
    ).encode()

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={
            "file": ("same-cve-vex.csv", content, "text/csv"),
            "vex_file": ("same-cve-vex.json", vex, "application/json"),
        },
    )

    assert response.status_code == 200, response.text
    findings = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200, findings.text
    by_asset = {item["asset_key"]: item for item in findings.json()["data"]}

    assert by_asset["log4j-fixed"]["status"] == "fixed"
    assert by_asset["log4j-fixed"]["suppressed_by_vex"] is True
    assert by_asset["log4j-fixed"]["explanation_json"]["provenance"]["vex_statuses"] == {"fixed": 1}
    assert by_asset["log4j-fixed"]["explanation_json"]["occurrence_scope"]["asset_ref"] == (
        "log4j-fixed"
    )
    assert by_asset["log4j-open"]["status"] == "open"
    assert by_asset["log4j-open"]["suppressed_by_vex"] is False
    assert by_asset["log4j-open"]["explanation_json"]["provenance"]["vex_statuses"] == {}
    assert by_asset["log4j-open"]["explanation_json"]["occurrence_scope"]["asset_ref"] == (
        "log4j-open"
    )


@pytest.mark.parametrize(
    ("input_type", "filename", "content_type", "detail"),
    [
        ("unknown", "scan.txt", "text/plain", "Unsupported input type"),
        ("cve-list", "scan.json", "text/plain", "File extension does not match input type"),
        (
            "cve-list",
            "scan.txt",
            "application/json",
            "Upload content type does not match input type",
        ),
    ],
)
def test_upload_rejects_unknown_input_type_bad_extension_and_mime(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
    input_type: str,
    filename: str,
    content_type: str,
    detail: str,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": input_type},
        files={"file": (filename, b"CVE-2024-3094\n", content_type)},
    )

    assert response.status_code == 422
    assert detail in response.text
    assert _run_count(template_api_env, uuid.UUID(project["id"])) == 0


def test_upload_rejects_oversized_file_without_persisting_run_or_file(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path, max_upload_mb=1)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("large.txt", b"A" * (1024 * 1024 + 1), "text/plain")},
    )

    assert response.status_code == 413
    assert response.json()["code"] == "upload_too_large"
    assert "Upload exceeds configured limit" in response.text
    assert _run_count(template_api_env, uuid.UUID(project["id"])) == 0
    assert not upload_dir.exists()


def test_upload_rejects_aggregate_primary_and_sidecar_size_before_persisting(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path, max_upload_mb=1)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    max_bytes = 1024 * 1024

    response = template_api_env.client.post(
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
    assert _run_count(template_api_env, uuid.UUID(project["id"])) == 0
    assert not upload_dir.exists()


def test_upload_rejects_path_traversal_filename(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    outside = tmp_path / "evil.txt"

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("../../evil.txt", b"CVE-2024-3094\n", "text/plain")},
    )

    assert response.status_code == 422
    assert "Upload filename is not allowed" in response.text
    assert _run_count(template_api_env, uuid.UUID(project["id"])) == 0
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
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
    field_name: str,
    filename: str,
    content_type: str,
    expected_detail: str,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    response = template_api_env.client.post(
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
    assert _run_count(template_api_env, uuid.UUID(project["id"])) == 0
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
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
    form_data: dict[str, str],
    expected_detail: str,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list", **form_data},
        files={"file": ("sample.txt", b"CVE-2024-3094\n", "text/plain")},
    )

    assert response.status_code == 422
    assert expected_detail in response.text
    assert _run_count(template_api_env, uuid.UUID(project["id"])) == 0
    assert not upload_dir.exists()


def test_parse_errors_are_structured_and_failed_run_is_persisted(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    content = b"CVE-2024-3094\nnot-a-cve\n"
    expected_sha256 = hashlib.sha256(content).hexdigest()

    response = template_api_env.client.post(
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

    run = template_api_env.client.get(
        f"/api/v1/runs/{detail['analysis_run_id']}",
        headers=headers,
    )
    assert run.status_code == 200
    payload = run.json()
    assert payload["status"] == "failed"
    assert [item["status"] for item in payload["error_json"]["import_job"]["status_history"]] == [
        "pending",
        "running",
        "failed",
    ]
    assert payload["error_json"]["parse_errors"] == detail["parse_errors"]
    assert payload["summary_json"]["parse_errors"] == detail["parse_errors"]
    _assert_no_sensitive_path_leak(payload["error_json"]["parse_errors"], tmp_path, upload_dir)
    _assert_no_sensitive_path_leak(payload["summary_json"]["parse_errors"], tmp_path, upload_dir)
    assert payload["summary_json"]["input_upload"]["sha256"] == expected_sha256
    upload_ref = payload["summary_json"]["input_upload"]["path"]
    assert not Path(upload_ref).is_absolute()
    assert (upload_dir / upload_ref).read_bytes() == content

    summary = template_api_env.client.get(
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
    with Session(template_api_env.engine) as session:
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
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    response = template_api_env.client.post(
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

    run = template_api_env.client.get(
        f"/api/v1/runs/{detail['analysis_run_id']}",
        headers=headers,
    )
    assert run.status_code == 200
    run_payload = run.json()
    assert run_payload["status"] == "failed"
    assert run_payload["error_json"]["parse_errors"] == detail["parse_errors"]
    assert run_payload["summary_json"]["parse_errors"] == detail["parse_errors"]
    _assert_no_sensitive_path_leak(run_payload["error_json"]["parse_errors"], tmp_path, upload_dir)
    _assert_no_sensitive_path_leak(
        run_payload["summary_json"]["parse_errors"], tmp_path, upload_dir
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
            b"A" * ((1024 * 1024) + 1),
            413,
            "Upload exceeds configured limit",
        ),
    ],
)
def test_asset_context_import_rejects_unsafe_uploads(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
    filename: str,
    content_type: str,
    content: bytes,
    expected_status: int,
    expected_detail: str,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path, max_upload_mb=1)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/assets/import",
        headers=headers,
        files={"asset_context_file": (filename, content, content_type)},
    )

    assert response.status_code == expected_status
    assert expected_detail in response.text


def test_summary_tracks_ignored_cve_list_lines(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    content = b"# comment\n\nCVE-2024-3094\n"

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("with-ignored-lines.txt", content, "text/plain")},
    )

    assert response.status_code == 200, response.text
    run_id = response.json()["id"]
    summary = template_api_env.client.get(f"/api/v1/runs/{run_id}/summary", headers=headers)
    assert summary.status_code == 200
    summary_payload = summary.json()
    assert summary_payload["ignored_lines"] == 2
    assert summary_payload["created_findings"] == 1
    assert summary_payload["updated_findings"] == 0
    assert summary_payload["parse_errors"] == []


def _configure_upload_dir(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
    *,
    max_upload_mb: int = 25,
) -> Path:
    upload_dir = tmp_path / "template-import-uploads"
    active_settings = template_api_env.client.app.state.workbench_settings
    template_api_env.client.app.state.workbench_settings = replace(
        active_settings,
        IMPORT_UPLOAD_DIR=str(upload_dir),
        PROVIDER_SNAPSHOT_DIR=str(PROJECT_ROOT / "data"),
        ATTACK_ARTIFACT_DIR=str(PROJECT_ROOT / "data" / "attack"),
        DEMO_PROVIDER_SNAPSHOT_ENABLED=True,
        MAX_UPLOAD_MB=max_upload_mb,
    )
    return upload_dir.resolve(strict=False)


async def _run_upload_size_guard(messages: list[dict[str, object]]) -> Response:
    app = Starlette()
    app.state.workbench_settings = Settings(MAX_UPLOAD_MB=1)
    message_iter = iter(messages)

    async def receive() -> dict[str, object]:
        return next(message_iter)

    request = Request(
        {
            "app": app,
            "client": ("testclient", 50000),
            "headers": [],
            "method": "POST",
            "path": f"/api/v1/projects/{uuid.uuid4()}/imports",
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
            "type": "http",
        },
        receive,
    )

    async def call_next(streamed_request: Request) -> Response:
        await streamed_request.body()
        return Response("accepted")

    return await _upload_size_guard(request, call_next)


def _assert_no_sensitive_path_leak(payload: object, *paths: Path) -> None:
    text = json.dumps(payload, sort_keys=True)
    forbidden_fragments = [
        "/Users/",
        "/private/",
        "/tmp/",
        "/var/",
        "\\Users\\",
    ]
    for path in paths:
        forbidden_fragments.append(str(path))
    for fragment in forbidden_fragments:
        assert fragment not in text


def _run_count(template_api_env: TemplateApiEnv, project_id: uuid.UUID) -> int:
    with Session(template_api_env.engine) as session:
        return len(
            template_api_env.repositories.RunRepository(session).list_analysis_runs(project_id)
        )


def _finding_state(
    template_api_env: TemplateApiEnv,
    project_id: uuid.UUID,
) -> tuple[list[app_models.Finding], int]:
    with Session(template_api_env.engine) as session:
        findings = list(
            session.exec(
                select(app_models.Finding)
                .where(app_models.Finding.project_id == project_id)
                .order_by(app_models.Finding.cve_id)
            )
        )
        occurrence_count = len(
            session.exec(
                select(app_models.FindingOccurrence)
                .join(app_models.Finding)
                .where(app_models.Finding.project_id == project_id)
            ).all()
        )
        return findings, occurrence_count


def _decision_state(findings: list[app_models.Finding]) -> dict[str, dict[str, object]]:
    values: dict[str, dict[str, object]] = {}
    for finding in findings:
        explanation = finding.explanation_json.get("explanation", {})
        guidance = finding.explanation_json.get("decision_guidance", {})
        values[finding.cve_id] = {
            "priority": str(finding.priority),
            "priority_rank": finding.priority_rank,
            "risk_score": finding.risk_score,
            "operational_rank": finding.operational_rank,
            "reason_codes": tuple(explanation.get("reason_codes", [])),
            "decision_template": guidance.get("template"),
        }
    return values
