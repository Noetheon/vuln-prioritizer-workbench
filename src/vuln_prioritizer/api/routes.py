"""JSON API routes for the Workbench MVP."""

from __future__ import annotations

import hashlib
import secrets
from pathlib import Path
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.orm import Session

from vuln_prioritizer import __version__
from vuln_prioritizer.api.deps import get_db_session, get_workbench_settings
from vuln_prioritizer.api.schemas import (
    AnalysisRunResponse,
    ApiTokenCreateRequest,
    ApiTokenCreateResponse,
    ApiTokenResponse,
    ArtifactCleanupResponse,
    ArtifactRetentionRequest,
    ArtifactRetentionResponse,
    AssetResponse,
    AssetUpdateRequest,
    AttackReviewQueueResponse,
    AttackReviewUpdateRequest,
    AuditEventResponse,
    CoverageGapResponse,
    DetectionControlAttachmentResponse,
    DetectionControlHistoryResponse,
    DetectionControlImportResponse,
    DetectionControlPatchRequest,
    DetectionControlRequest,
    DetectionControlResponse,
    EvidenceBundleResponse,
    EvidenceBundleVerificationResponse,
    FindingAttackContextResponse,
    FindingResponse,
    FindingsListResponse,
    FindingStatusUpdateRequest,
    GitHubIssueExportRequest,
    GitHubIssueExportResponse,
    GitHubIssuePreviewRequest,
    GitHubIssuePreviewResponse,
    GovernanceRollupsResponse,
    ProjectConfigDiffResponse,
    ProjectConfigRequest,
    ProjectConfigResponse,
    ProjectCreateRequest,
    ProjectResponse,
    ProviderStatusResponse,
    ProviderUpdateJobRequest,
    ProviderUpdateJobResponse,
    ReportCreateRequest,
    ReportResponse,
    TechniqueDetailResponse,
    TicketSyncExportRequest,
    TicketSyncPreviewRequest,
    TicketSyncResponse,
    TopTechniquesResponse,
    WaiverRequest,
    WaiverResponse,
    WorkbenchJobCreateRequest,
    WorkbenchJobListResponse,
    WorkbenchJobResponse,
)
from vuln_prioritizer.api.security import api_token_digest
from vuln_prioritizer.api.workbench_detection import (
    WEAK_DETECTION_COVERAGE_LEVELS,
    _coverage_gap_payload,
    _coverage_gap_score,
    _detection_control_payload,
    _detection_control_values,
    _parse_detection_control_rows,
    _technique_id_from_dict,
    _technique_metadata_from_contexts,
)
from vuln_prioritizer.api.workbench_findings import _filter_findings, _sort_findings
from vuln_prioritizer.api.workbench_github import (
    _create_github_issue,
    _github_export_token,
    _github_issue_preview_payload,
    _github_repository_path,
)
from vuln_prioritizer.api.workbench_payloads import (
    _analysis_run_payload,
    _api_token_payload,
    _artifact_retention_payload,
    _asset_payload,
    _attack_context_payload,
    _attack_review_queue_item_payload,
    _audit_event_payload,
    _detection_control_attachment_payload,
    _detection_control_history_payload,
    _evidence_bundle_payload,
    _finding_payload,
    _governance_payload,
    _project_config_payload,
    _project_payload,
    _report_payload,
    _workbench_job_payload,
)
from vuln_prioritizer.api.workbench_providers import (
    _create_provider_update_job_record,
    _provider_status_payload,
    _provider_update_job_payload,
)
from vuln_prioritizer.api.workbench_tickets import (
    _create_jira_issue,
    _create_servicenow_ticket,
    _jira_project_key,
    _servicenow_table,
    _ticket_base_url,
    _ticket_preview_payload,
    _ticket_sync_token,
)
from vuln_prioritizer.api.workbench_uploads import (
    _artifact_response,
    _cleanup_saved_uploads,
    _delete_download_artifact,
    _read_bounded_upload,
    _resolve_attack_artifact_path,
    _resolve_download_artifact,
    _resolve_provider_snapshot_path,
    _save_optional_context_upload,
    _save_upload,
)
from vuln_prioritizer.api.workbench_waivers import (
    _count_matching_waiver_findings,
    _strip_or_none,
    _sync_project_waivers,
    _validated_waiver_values,
    _waiver_payload,
)
from vuln_prioritizer.attack_sources import ATTACK_SOURCE_NONE, WORKBENCH_ALLOWED_MAPPING_SOURCES
from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.config import DEFAULT_CACHE_TTL_HOURS
from vuln_prioritizer.db.migrations import CURRENT_REVISION
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.runtime_config import RuntimeConfigDocument
from vuln_prioritizer.services.workbench_analysis import (
    WorkbenchAnalysisError,
    run_workbench_import,
)
from vuln_prioritizer.services.workbench_artifacts import cleanup_project_artifacts
from vuln_prioritizer.services.workbench_attack import (
    navigator_layer_from_contexts,
    top_technique_rows,
)
from vuln_prioritizer.services.workbench_executive_report import (
    WorkbenchExecutiveReportError,
    build_run_executive_report_model,
)
from vuln_prioritizer.services.workbench_governance import build_governance_summary
from vuln_prioritizer.services.workbench_jobs import run_sync_workbench_job
from vuln_prioritizer.services.workbench_reports import (
    ReportFormat,
    WorkbenchReportError,
    create_run_evidence_bundle,
    create_run_report,
    verify_run_evidence_bundle,
)
from vuln_prioritizer.workbench_config import WorkbenchSettings

api_router = APIRouter(prefix="/api")

API_TOKEN_PREFIX = "vpr_"
ATTACK_REVIEW_SOURCES = set(WORKBENCH_ALLOWED_MAPPING_SOURCES) | {ATTACK_SOURCE_NONE}


@api_router.get("/health")
def health(
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    return {
        "status": "ok",
        "database": "ok",
        "projects": len(repo.list_projects()),
        "upload_dir": str(settings.upload_dir),
        "report_dir": str(settings.report_dir),
    }


@api_router.get("/version")
def version() -> dict[str, Any]:
    return {"version": __version__, "app": "Vuln Prioritizer Workbench"}


@api_router.get("/diagnostics")
def diagnostics(
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    projects = repo.list_projects()
    reports = [
        report.path for project in projects for report in repo.list_project_reports(project.id)
    ]
    bundles = [
        bundle.path
        for project in projects
        for bundle in repo.list_project_evidence_bundles(project.id)
    ]
    cache = FileCache(settings.provider_cache_dir, DEFAULT_CACHE_TTL_HOURS)
    return {
        "status": "ok",
        "database": "ok",
        "migration_revision": CURRENT_REVISION,
        "projects": len(projects),
        "upload_dir": str(settings.upload_dir),
        "report_dir": str(settings.report_dir),
        "provider_snapshot_dir": str(settings.provider_snapshot_dir),
        "provider_cache_dir": str(settings.provider_cache_dir),
        "directories": {
            "upload": _directory_diagnostics(settings.upload_dir),
            "report": _directory_diagnostics(settings.report_dir),
            "provider_snapshot": _directory_diagnostics(settings.provider_snapshot_dir),
            "provider_cache": _directory_diagnostics(settings.provider_cache_dir),
        },
        "provider_cache": {
            source: cache.inspect_namespace(source) for source in ("nvd", "epss", "kev")
        },
        "jobs": {
            "queued": len(repo.list_workbench_jobs(status="queued", limit=500)),
            "running": len(repo.list_workbench_jobs(status="running", limit=500)),
            "failed": len(repo.list_workbench_jobs(status="failed", limit=500)),
        },
        "artifact_disk_usage_bytes": _artifact_disk_usage(reports + bundles),
        "max_upload_bytes": settings.max_upload_bytes,
        "api_tokens_active": repo.has_active_api_tokens(),
    }


@api_router.post("/tokens", response_model=ApiTokenCreateResponse)
def create_api_token(
    payload: ApiTokenCreateRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Token name is required.")
    token_value = API_TOKEN_PREFIX + secrets.token_urlsafe(32)
    token = WorkbenchRepository(session).create_api_token(
        name=name,
        token_hash=_api_token_hash(token_value),
    )
    WorkbenchRepository(session).create_audit_event(
        event_type="api_token.created",
        target_type="api_token",
        target_id=token.id,
        actor=name,
        message=f"API token {name!r} was created.",
    )
    session.commit()
    return {
        "id": token.id,
        "name": token.name,
        "token": token_value,
        "created_at": token.created_at.isoformat(),
    }


@api_router.get("/tokens", response_model=dict[str, list[ApiTokenResponse]])
def list_api_tokens(session: Annotated[Session, Depends(get_db_session)]) -> dict[str, Any]:
    return {
        "items": [
            _api_token_payload(token) for token in WorkbenchRepository(session).list_api_tokens()
        ]
    }


@api_router.delete("/tokens/{token_id}", response_model=ApiTokenResponse)
def revoke_api_token(
    token_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    token = repo.get_api_token(token_id)
    if token is None:
        raise HTTPException(status_code=404, detail="API token not found.")
    repo.revoke_api_token(token)
    repo.create_audit_event(
        event_type="api_token.revoked",
        target_type="api_token",
        target_id=token.id,
        actor=token.name,
        message=f"API token {token.name!r} was revoked.",
    )
    session.commit()
    return _api_token_payload(token)


@api_router.get("/projects")
def list_projects(session: Annotated[Session, Depends(get_db_session)]) -> dict[str, Any]:
    projects = WorkbenchRepository(session).list_projects()
    return {"items": [_project_payload(project) for project in projects]}


@api_router.post("/projects", response_model=ProjectResponse)
def create_project(
    payload: ProjectCreateRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Project name is required.")
    repo = WorkbenchRepository(session)
    if repo.get_project_by_name(name) is not None:
        raise HTTPException(status_code=409, detail="Project already exists.")
    project = repo.create_project(name=name, description=payload.description)
    repo.create_audit_event(
        project_id=project.id,
        event_type="project.created",
        target_type="project",
        target_id=project.id,
        message=f"Project {name!r} was created.",
    )
    session.commit()
    return _project_payload(project)


@api_router.get("/projects/{project_id}", response_model=ProjectResponse)
def get_project(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    project = WorkbenchRepository(session).get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return _project_payload(project)


@api_router.get(
    "/projects/{project_id}/audit-events",
    response_model=dict[str, list[AuditEventResponse]],
)
def list_project_audit_events(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return {
        "items": [
            _audit_event_payload(event)
            for event in repo.list_project_audit_events(project_id, limit=limit)
        ]
    }


@api_router.get("/audit-events", response_model=dict[str, list[AuditEventResponse]])
def list_audit_events(
    session: Annotated[Session, Depends(get_db_session)],
    project_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    return {
        "items": [
            _audit_event_payload(event)
            for event in WorkbenchRepository(session).list_audit_events(
                project_id=project_id,
                limit=limit,
            )
        ]
    }


@api_router.get("/projects/{project_id}/assets")
def list_project_assets(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    findings = repo.list_project_findings(project_id)
    finding_counts: dict[str, int] = {}
    for finding in findings:
        if finding.asset_id:
            finding_counts[finding.asset_id] = finding_counts.get(finding.asset_id, 0) + 1
    return {
        "items": [
            _asset_payload(asset, finding_count=finding_counts.get(asset.id, 0))
            for asset in repo.list_project_assets(project_id)
        ]
    }


@api_router.get("/assets/{asset_row_id}", response_model=AssetResponse)
def get_asset(
    asset_row_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    asset = WorkbenchRepository(session).get_asset(asset_row_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    return _asset_payload(asset, finding_count=len(asset.findings))


@api_router.patch("/assets/{asset_row_id}", response_model=AssetResponse)
def update_asset(
    asset_row_id: str,
    payload: AssetUpdateRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    asset = repo.get_asset(asset_row_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    previous = _asset_audit_snapshot(asset)
    updated_fields = payload.model_fields_set
    updated = repo.update_asset(
        asset,
        asset_id=(
            _strip_or_none(payload.asset_id) or asset.asset_id
            if "asset_id" in updated_fields
            else asset.asset_id
        ),
        target_ref=(
            _strip_or_none(payload.target_ref)
            if "target_ref" in updated_fields
            else asset.target_ref
        ),
        owner=_strip_or_none(payload.owner) if "owner" in updated_fields else asset.owner,
        business_service=(
            _strip_or_none(payload.business_service)
            if "business_service" in updated_fields
            else asset.business_service
        ),
        environment=(
            _strip_or_none(payload.environment)
            if "environment" in updated_fields
            else asset.environment
        ),
        exposure=(
            _strip_or_none(payload.exposure) if "exposure" in updated_fields else asset.exposure
        ),
        criticality=(
            _strip_or_none(payload.criticality)
            if "criticality" in updated_fields
            else asset.criticality
        ),
    )
    repo.create_audit_event(
        project_id=updated.project_id,
        event_type="asset.updated",
        target_type="asset",
        target_id=updated.id,
        actor=updated.owner,
        message=f"Asset {updated.asset_id!r} was updated.",
        metadata_json={
            "previous": previous,
            "current": _asset_audit_snapshot(updated),
            "updated_fields": sorted(updated_fields),
        },
    )
    session.commit()
    return _asset_payload(updated, finding_count=len(updated.findings))


@api_router.get("/projects/{project_id}/waivers")
def list_project_waivers(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    findings = repo.list_project_findings(project_id)
    return {
        "items": [
            _waiver_payload(
                waiver, matched_findings=_count_matching_waiver_findings(waiver, findings)
            )
            for waiver in repo.list_project_waivers(project_id)
        ]
    }


@api_router.post("/projects/{project_id}/waivers", response_model=WaiverResponse)
def create_project_waiver(
    project_id: str,
    payload: WaiverRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    values = _validated_waiver_values(payload, project_id=project_id, repo=repo)
    waiver = repo.create_waiver(project_id=project_id, **values)
    matched = _sync_project_waivers(repo, project_id)
    repo.create_audit_event(
        project_id=project_id,
        event_type="waiver.created",
        target_type="waiver",
        target_id=waiver.id,
        actor=waiver.owner,
        message="Waiver was created.",
        metadata_json={"matched_findings": matched.get(waiver.id, 0)},
    )
    session.commit()
    return _waiver_payload(waiver, matched_findings=matched.get(waiver.id, 0))


@api_router.patch("/waivers/{waiver_id}", response_model=WaiverResponse)
def update_project_waiver(
    waiver_id: str,
    payload: WaiverRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    waiver = repo.get_waiver(waiver_id)
    if waiver is None:
        raise HTTPException(status_code=404, detail="Waiver not found.")
    values = _validated_waiver_values(payload, project_id=waiver.project_id, repo=repo)
    updated = repo.update_waiver(waiver, **values)
    matched = _sync_project_waivers(repo, updated.project_id)
    repo.create_audit_event(
        project_id=updated.project_id,
        event_type="waiver.updated",
        target_type="waiver",
        target_id=updated.id,
        actor=updated.owner,
        message="Waiver was updated.",
        metadata_json={"matched_findings": matched.get(updated.id, 0)},
    )
    session.commit()
    return _waiver_payload(updated, matched_findings=matched.get(updated.id, 0))


@api_router.delete("/waivers/{waiver_id}")
def delete_project_waiver(
    waiver_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    waiver = repo.get_waiver(waiver_id)
    if waiver is None:
        raise HTTPException(status_code=404, detail="Waiver not found.")
    project_id = waiver.project_id
    repo.delete_waiver(waiver)
    _sync_project_waivers(repo, project_id)
    repo.create_audit_event(
        project_id=project_id,
        event_type="waiver.deleted",
        target_type="waiver",
        target_id=waiver_id,
        message="Waiver was deleted.",
    )
    session.commit()
    return {"deleted": True}


@api_router.get("/projects/{project_id}/runs")
def list_project_runs(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return {"items": [_analysis_run_payload(run) for run in repo.list_analysis_runs(project_id)]}


@api_router.post("/projects/{project_id}/imports", response_model=AnalysisRunResponse)
async def import_findings(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    input_format: Annotated[str, Form()],
    file: Annotated[UploadFile | None, File()] = None,
    files: Annotated[list[UploadFile] | None, File()] = None,
    input_formats: Annotated[list[str] | None, Form()] = None,
    provider_snapshot_file: Annotated[str | None, Form()] = None,
    locked_provider_data: Annotated[bool, Form()] = False,
    attack_source: Annotated[str, Form()] = "none",
    attack_mapping_file: Annotated[str | None, Form()] = None,
    attack_technique_metadata_file: Annotated[str | None, Form()] = None,
    asset_context_file: Annotated[UploadFile | None, File()] = None,
    vex_file: Annotated[UploadFile | None, File()] = None,
    waiver_file: Annotated[UploadFile | None, File()] = None,
    defensive_context_file: Annotated[UploadFile | None, File()] = None,
) -> dict[str, Any]:
    upload_paths: list[Path] = []
    asset_context_path: Path | None = None
    vex_path: Path | None = None
    waiver_path: Path | None = None
    defensive_context_path: Path | None = None
    try:
        selected_files = _selected_import_files(file=file, files=files)
        selected_formats = _selected_import_formats(
            input_format=input_format,
            input_formats=input_formats,
            file_count=len(selected_files),
        )
        upload_paths = [
            await _save_upload(item, input_format=item_format, settings=settings)
            for item, item_format in zip(selected_files, selected_formats, strict=True)
        ]
        asset_context_path = await _save_optional_context_upload(
            asset_context_file,
            kind="asset-context",
            settings=settings,
        )
        vex_path = await _save_optional_context_upload(vex_file, kind="vex", settings=settings)
        waiver_path = await _save_optional_context_upload(
            waiver_file,
            kind="waiver",
            settings=settings,
        )
        defensive_context_path = await _save_optional_context_upload(
            defensive_context_file,
            kind="defensive-context",
            settings=settings,
        )
        snapshot_path = _resolve_provider_snapshot_path(provider_snapshot_file, settings=settings)
        attack_mapping_path = _resolve_attack_artifact_path(attack_mapping_file, settings=settings)
        attack_metadata_path = _resolve_attack_artifact_path(
            attack_technique_metadata_file,
            settings=settings,
        )
        job, result = run_sync_workbench_job(
            session=session,
            kind="import_findings",
            project_id=project_id,
            target_type="project",
            target_id=project_id,
            payload_json={
                "input_format": selected_formats,
                "input_formats": selected_formats,
                "input_paths": [str(path) for path in upload_paths],
                "original_filenames": [
                    item.filename or path.name
                    for item, path in zip(selected_files, upload_paths, strict=True)
                ],
                "input_count": len(upload_paths),
                "locked_provider_data": locked_provider_data,
                "attack_source": attack_source,
                "provider_snapshot_file": str(snapshot_path) if snapshot_path is not None else None,
                "attack_mapping_file": (
                    str(attack_mapping_path) if attack_mapping_path is not None else None
                ),
                "attack_technique_metadata_file": (
                    str(attack_metadata_path) if attack_metadata_path is not None else None
                ),
                "asset_context_file": (
                    str(asset_context_path) if asset_context_path is not None else None
                ),
                "vex_file": str(vex_path) if vex_path is not None else None,
                "waiver_file": str(waiver_path) if waiver_path is not None else None,
                "defensive_context_file": (
                    str(defensive_context_path) if defensive_context_path is not None else None
                ),
            },
            operation=lambda _repo, active_job: run_workbench_import(
                session=session,
                settings=settings,
                project_id=project_id,
                input_path=upload_paths if len(upload_paths) > 1 else upload_paths[0],
                original_filename=[
                    item.filename or path.name
                    for item, path in zip(selected_files, upload_paths, strict=True)
                ]
                if len(upload_paths) > 1
                else (selected_files[0].filename or upload_paths[0].name),
                input_format=selected_formats if len(upload_paths) > 1 else selected_formats[0],
                provider_snapshot_file=snapshot_path,
                locked_provider_data=locked_provider_data,
                attack_source=attack_source,
                attack_mapping_file=attack_mapping_path,
                attack_technique_metadata_file=attack_metadata_path,
                asset_context_file=asset_context_path,
                vex_file=vex_path,
                waiver_file=waiver_path,
                defensive_context_file=defensive_context_path,
            ),
            result=lambda value: {
                "analysis_run_id": value.run.id,
                "findings_count": value.run.metadata_json.get("findings_count", 0),
            },
        )
        result.run.metadata_json = {**result.run.metadata_json, "job_id": job.id}
    except WorkbenchAnalysisError as exc:
        _cleanup_saved_uploads(
            *upload_paths,
            asset_context_path,
            vex_path,
            waiver_path,
            defensive_context_path,
        )
        session.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except HTTPException:
        _cleanup_saved_uploads(
            *upload_paths,
            asset_context_path,
            vex_path,
            waiver_path,
            defensive_context_path,
        )
        raise
    except Exception:
        _cleanup_saved_uploads(
            *upload_paths,
            asset_context_path,
            vex_path,
            waiver_path,
            defensive_context_path,
        )
        raise
    WorkbenchRepository(session).create_audit_event(
        project_id=project_id,
        event_type="analysis_run.imported",
        target_type="analysis_run",
        target_id=result.run.id,
        message="Workbench import completed.",
        metadata_json={
            "input_type": result.run.input_type,
            "input_count": len(upload_paths),
            "locked_provider_data": locked_provider_data,
        },
    )
    session.commit()
    return _analysis_run_payload(result.run)


@api_router.get("/analysis-runs/{run_id}", response_model=AnalysisRunResponse)
def get_analysis_run(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    run = WorkbenchRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found.")
    return _analysis_run_payload(run)


@api_router.get("/runs/{run_id}")
def get_run_alias(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    return get_analysis_run(run_id=run_id, session=session)


@api_router.get("/runs/{run_id}/summary")
def get_run_summary(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    run = WorkbenchRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found.")
    return _analysis_run_payload(run)["summary"]


@api_router.get("/analysis-runs/{run_id}/executive-report")
def get_run_executive_report(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    run = repo.get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found.")
    project = repo.get_project(run.project_id)
    try:
        return build_run_executive_report_model(repo=repo, run=run, project=project)
    except WorkbenchExecutiveReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@api_router.get("/projects/{project_id}/findings", response_model=FindingsListResponse)
def list_findings(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    priority: str | None = None,
    status: str | None = None,
    q: str | None = None,
    kev: bool | None = None,
    owner: str | None = None,
    service: str | None = None,
    min_epss: float | None = Query(default=None, ge=0, le=1),
    min_cvss: float | None = Query(default=None, ge=0, le=10),
    sort: str = Query(default="operational"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    try:
        paged, total = repo.list_project_findings_page(
            project_id,
            priority=priority,
            status=status,
            q=q,
            kev=kev,
            owner=owner,
            service=service,
            min_epss=min_epss,
            min_cvss=min_cvss,
            sort=sort,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "items": [_finding_payload(finding) for finding in paged],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@api_router.get("/findings/{finding_id}")
def get_finding(
    finding_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    finding = WorkbenchRepository(session).get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return _finding_payload(finding, include_detail=True)


@api_router.patch("/findings/{finding_id}", response_model=FindingResponse)
def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdateRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    finding = repo.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    actor = _strip_or_none(payload.actor) or "api"
    reason = _strip_or_none(payload.reason)
    history = repo.update_finding_status(
        finding,
        status=payload.status,
        actor=actor,
        reason=reason,
    )
    repo.create_audit_event(
        project_id=finding.project_id,
        event_type="finding.status_changed",
        target_type="finding",
        target_id=finding.id,
        actor=actor,
        message=f"Finding {finding.cve_id} status changed to {payload.status}.",
        metadata_json={
            "previous_status": history.previous_status,
            "new_status": history.new_status,
            "reason": history.reason,
        },
    )
    session.commit()
    updated = repo.get_finding(finding_id)
    if updated is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return _finding_payload(updated, include_detail=True)


@api_router.get("/findings/{finding_id}/explain")
def explain_finding(
    finding_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    finding = WorkbenchRepository(session).get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return {
        "finding_id": finding.id,
        "cve_id": finding.cve_id,
        "priority": finding.priority,
        "rationale": finding.rationale,
        "recommended_action": finding.recommended_action,
        "explanation": finding.explanation_json,
    }


@api_router.get(
    "/findings/{finding_id}/ttps",
    response_model=FindingAttackContextResponse,
)
def finding_ttps(
    finding_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    finding = repo.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    contexts = repo.list_finding_attack_contexts(finding.id)
    if not contexts:
        raise HTTPException(status_code=404, detail="ATT&CK context not found.")
    return _attack_context_payload(contexts[0], finding_id=finding.id)


@api_router.get(
    "/projects/{project_id}/attack/top-techniques",
    response_model=TopTechniquesResponse,
)
def project_top_techniques(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    limit: int = Query(default=10, ge=1, le=100),
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return {"items": top_technique_rows(repo.list_project_attack_contexts(project_id), limit=limit)}


@api_router.get(
    "/projects/{project_id}/attack/review-queue",
    response_model=AttackReviewQueueResponse,
)
def project_attack_review_queue(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    review_status: str | None = None,
    source: str | None = None,
    mapped: bool | None = None,
    priority: str | None = None,
    technique_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    if source is not None and source not in ATTACK_REVIEW_SOURCES:
        raise HTTPException(status_code=422, detail="Unsupported ATT&CK review source.")
    contexts = repo.list_project_attack_review_contexts(
        project_id,
        review_status=review_status,
        source=source,
        mapped=mapped,
        priority=priority,
        technique_id=technique_id,
        limit=limit,
    )
    return {"items": [_attack_review_queue_item_payload(context) for context in contexts]}


@api_router.patch(
    "/findings/{finding_id}/ttps/review",
    response_model=FindingAttackContextResponse,
)
def update_finding_attack_review(
    finding_id: str,
    payload: AttackReviewUpdateRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    finding = repo.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    contexts = repo.list_finding_attack_contexts(finding.id)
    if not contexts:
        raise HTTPException(status_code=404, detail="ATT&CK context not found.")
    sources = {context.source for context in contexts}
    if not sources <= ATTACK_REVIEW_SOURCES:
        raise HTTPException(status_code=422, detail="Unsupported ATT&CK review source.")
    updated_contexts = repo.update_finding_attack_review_status(
        finding.id,
        review_status=payload.review_status,
    )
    repo.create_audit_event(
        project_id=finding.project_id,
        event_type="attack_context.review_updated",
        target_type="finding",
        target_id=finding.id,
        actor=payload.actor,
        message=f"ATT&CK review status updated to {payload.review_status}.",
        metadata_json={"reason": payload.reason, "sources": sorted(sources)},
    )
    session.commit()
    return _attack_context_payload(updated_contexts[0], finding_id=finding.id)


@api_router.get("/projects/{project_id}/detection-controls")
def list_detection_controls(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return {
        "items": [
            _detection_control_payload(control)
            for control in repo.list_project_detection_controls(project_id)
        ]
    }


@api_router.post(
    "/projects/{project_id}/detection-controls",
    response_model=DetectionControlResponse,
)
def create_detection_control(
    project_id: str,
    payload: DetectionControlRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    control = repo.upsert_detection_control(
        project_id=project_id,
        **_detection_control_values(payload.model_dump(), index=1),
        history_actor=payload.owner,
    )
    repo.create_audit_event(
        project_id=project_id,
        event_type="detection_control.created",
        target_type="detection_control",
        target_id=control.id,
        actor=control.owner,
        message=f"Detection control {control.name!r} was created.",
    )
    session.commit()
    return _detection_control_payload(control)


@api_router.patch(
    "/detection-controls/{control_id}",
    response_model=DetectionControlResponse,
)
def update_detection_control(
    control_id: str,
    payload: DetectionControlPatchRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    control = repo.get_detection_control(control_id)
    if control is None:
        raise HTTPException(status_code=404, detail="Detection control not found.")
    values = _patched_detection_control_values(control, payload)
    try:
        updated = repo.update_detection_control(
            control,
            **values,
            history_actor=values.get("owner"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    repo.create_audit_event(
        project_id=updated.project_id,
        event_type="detection_control.updated",
        target_type="detection_control",
        target_id=updated.id,
        actor=updated.owner,
        message=f"Detection control {updated.name!r} was updated.",
    )
    session.commit()
    return _detection_control_payload(updated)


@api_router.delete("/detection-controls/{control_id}")
def delete_detection_control(
    control_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    control = repo.get_detection_control(control_id)
    if control is None:
        raise HTTPException(status_code=404, detail="Detection control not found.")
    project_id = control.project_id
    name = control.name
    removed_attachments = 0
    for attachment in list(control.attachments):
        if _delete_upload_artifact(
            attachment.path,
            settings=settings,
            expected_sha256=attachment.sha256,
        ):
            removed_attachments += 1
    repo.delete_detection_control(control)
    repo.create_audit_event(
        project_id=project_id,
        event_type="detection_control.deleted",
        target_type="detection_control",
        target_id=control_id,
        message=f"Detection control {name!r} was deleted.",
        metadata_json={"removed_attachments": removed_attachments},
    )
    session.commit()
    return {"deleted": True, "removed_attachments": removed_attachments}


@api_router.get(
    "/detection-controls/{control_id}/history",
    response_model=dict[str, list[DetectionControlHistoryResponse]],
)
def list_detection_control_history(
    control_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_detection_control(control_id) is None:
        raise HTTPException(status_code=404, detail="Detection control not found.")
    return {
        "items": [
            _detection_control_history_payload(item)
            for item in repo.list_detection_control_history(control_id)
        ]
    }


@api_router.get(
    "/detection-controls/{control_id}/attachments",
    response_model=dict[str, list[DetectionControlAttachmentResponse]],
)
def list_detection_control_attachments(
    control_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_detection_control(control_id) is None:
        raise HTTPException(status_code=404, detail="Detection control not found.")
    return {
        "items": [
            _detection_control_attachment_payload(item)
            for item in repo.list_detection_control_attachments(control_id)
        ]
    }


@api_router.post(
    "/detection-controls/{control_id}/attachments",
    response_model=DetectionControlAttachmentResponse,
)
async def upload_detection_control_attachment(
    control_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    file: Annotated[UploadFile, File()],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    control = repo.get_detection_control(control_id)
    if control is None:
        raise HTTPException(status_code=404, detail="Detection control not found.")
    filename = Path(file.filename or "evidence.bin").name
    _validate_detection_attachment_filename(filename)
    content = await _read_bounded_upload(file, settings=settings)
    digest = hashlib.sha256(content).hexdigest()
    attachment_dir = settings.upload_dir / "detection-controls" / control.id
    attachment_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = attachment_dir / f"{digest[:16]}-{filename}"
    artifact_path.write_bytes(content)
    attachment = repo.add_detection_control_attachment(
        control_id=control.id,
        project_id=control.project_id,
        filename=filename,
        content_type=file.content_type,
        path=str(artifact_path),
        sha256=digest,
        size_bytes=len(content),
    )
    repo.add_detection_control_history(
        control=control,
        event_type="attachment_added",
        current_json={"attachment_id": attachment.id, "filename": filename, "sha256": digest},
    )
    repo.create_audit_event(
        project_id=control.project_id,
        event_type="detection_control.attachment_added",
        target_type="detection_control",
        target_id=control.id,
        message=f"Evidence attachment {filename!r} was uploaded.",
        metadata_json={"attachment_id": attachment.id, "size_bytes": len(content)},
    )
    session.commit()
    return _detection_control_attachment_payload(attachment)


@api_router.get("/detection-control-attachments/{attachment_id}/download")
def download_detection_control_attachment(
    attachment_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> StreamingResponse:
    attachment = WorkbenchRepository(session).get_detection_control_attachment(attachment_id)
    if attachment is None:
        raise HTTPException(status_code=404, detail="Detection attachment not found.")
    attachment_path = _resolve_upload_artifact(
        attachment.path,
        settings=settings,
        expected_sha256=attachment.sha256,
        missing_detail="Detection attachment not found.",
    )
    return _artifact_response(
        attachment_path,
        media_type=attachment.content_type or "application/octet-stream",
    )


@api_router.delete("/detection-control-attachments/{attachment_id}")
def delete_detection_control_attachment(
    attachment_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    attachment = repo.get_detection_control_attachment(attachment_id)
    if attachment is None:
        raise HTTPException(status_code=404, detail="Detection attachment not found.")
    control = repo.get_detection_control(attachment.control_id)
    artifact_removed = _delete_upload_artifact(
        attachment.path,
        settings=settings,
        expected_sha256=attachment.sha256,
    )
    project_id = attachment.project_id
    control_id = attachment.control_id
    repo.delete_detection_control_attachment(attachment)
    if control is not None:
        repo.add_detection_control_history(
            control=control,
            event_type="attachment_deleted",
            current_json={"attachment_id": attachment_id},
        )
    repo.create_audit_event(
        project_id=project_id,
        event_type="detection_control.attachment_deleted",
        target_type="detection_control",
        target_id=control_id,
        message="Evidence attachment was deleted.",
        metadata_json={"attachment_id": attachment_id, "artifact_removed": artifact_removed},
    )
    session.commit()
    return {"deleted": True, "artifact_removed": artifact_removed}


@api_router.post(
    "/projects/{project_id}/detection-controls/import",
    response_model=DetectionControlImportResponse,
)
async def import_detection_controls(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    file: Annotated[UploadFile, File()],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    content = await _read_bounded_upload(file, settings=settings)
    rows = _parse_detection_control_rows(file.filename or "controls", content)
    controls = [
        repo.upsert_detection_control(project_id=project_id, **row, history_actor="api-import")
        for row in rows
    ]
    repo.create_audit_event(
        project_id=project_id,
        event_type="detection_control.imported",
        target_type="project",
        target_id=project_id,
        message="Detection controls were imported.",
        metadata_json={"imported": len(controls)},
    )
    session.commit()
    return {
        "imported": len(controls),
        "items": [_detection_control_payload(control) for control in controls],
    }


@api_router.get(
    "/projects/{project_id}/attack/coverage-gaps",
    response_model=CoverageGapResponse,
)
def project_coverage_gaps(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return _coverage_gap_payload(
        repo.list_project_attack_contexts(project_id),
        repo.list_project_detection_controls(project_id),
        repo.list_project_findings(project_id),
    )


@api_router.get("/projects/{project_id}/attack/coverage-gap-navigator-layer")
def project_coverage_gap_navigator_layer(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    payload = _coverage_gap_payload(
        repo.list_project_attack_contexts(project_id),
        repo.list_project_detection_controls(project_id),
        repo.list_project_findings(project_id),
    )
    gap_items = [
        item
        for item in payload["items"]
        if item["coverage_level"] in WEAK_DETECTION_COVERAGE_LEVELS
    ]
    return {
        "version": "4.5",
        "name": "vuln-prioritizer detection coverage gaps",
        "domain": "enterprise-attack",
        "description": (
            "Defensive Navigator layer showing mapped techniques with partial, missing, "
            "or unknown detection coverage. It does not describe offensive procedures."
        ),
        "techniques": [
            {
                "techniqueID": item["technique_id"],
                "score": _coverage_gap_score(item["coverage_level"]),
                "comment": item["recommended_action"],
            }
            for item in gap_items
        ],
    }


@api_router.get(
    "/projects/{project_id}/attack/techniques/{technique_id}",
    response_model=TechniqueDetailResponse,
)
def project_attack_technique_detail(
    project_id: str,
    technique_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    contexts = repo.list_project_attack_contexts(project_id)
    controls = repo.list_detection_controls_for_technique(project_id, technique_id)
    findings = [
        finding
        for finding in repo.list_project_findings(project_id)
        if any(
            _technique_id_from_dict(technique) == technique_id
            for context in finding.attack_contexts
            for technique in (context.techniques_json or [])
            if isinstance(technique, dict)
        )
    ]
    coverage = [
        item
        for item in _coverage_gap_payload(contexts, controls, findings)["items"]
        if item["technique_id"] == technique_id
    ]
    metadata = _technique_metadata_from_contexts(contexts, technique_id)
    return {
        "technique_id": technique_id,
        "name": metadata.get("name"),
        "deprecated": bool(metadata.get("deprecated")),
        "revoked": bool(metadata.get("revoked")),
        "tactics": list(metadata.get("tactics", [])),
        "findings": [_finding_payload(finding) for finding in findings],
        "controls": [_detection_control_payload(control) for control in controls],
        "coverage": coverage[0] if coverage else None,
    }


@api_router.get(
    "/projects/{project_id}/governance/rollups",
    response_model=GovernanceRollupsResponse,
)
def project_governance_rollups(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    limit: int = Query(default=10, ge=1, le=100),
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    summary = build_governance_summary(repo.list_project_findings(project_id), limit=limit)
    return _governance_payload(summary)


@api_router.get("/analysis-runs/{run_id}/attack/navigator-layer")
def run_attack_navigator_layer(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    run = repo.get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found.")
    return navigator_layer_from_contexts(repo.list_run_attack_contexts(run.id))


@api_router.get("/providers/status", response_model=ProviderStatusResponse)
def provider_status(
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    snapshot = WorkbenchRepository(session).get_latest_provider_snapshot()
    return _provider_status_payload(snapshot, settings=settings)


@api_router.get("/providers/update-jobs")
def list_provider_update_jobs(
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    return {
        "items": [
            _provider_update_job_payload(job)
            for job in WorkbenchRepository(session).list_provider_update_jobs()
        ]
    }


@api_router.post("/providers/update-jobs", response_model=ProviderUpdateJobResponse)
def create_provider_update_job(
    payload: ProviderUpdateJobRequest,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    durable_job, job = run_sync_workbench_job(
        session=session,
        kind="provider_update",
        payload_json=payload.model_dump(),
        operation=lambda active_repo, _active_job: _create_provider_update_job_record(
            repo=active_repo,
            settings=settings,
            payload=payload,
        ),
        result=lambda value: {
            "provider_update_job_id": value.id,
            "status": value.status,
            "new_snapshot_id": (value.metadata_json or {}).get("new_snapshot_id"),
        },
    )
    job.metadata_json = {**(job.metadata_json or {}), "job_id": durable_job.id}
    repo.create_audit_event(
        event_type="provider_update_job.created",
        target_type="provider_update_job",
        target_id=job.id,
        message="Provider update job was created.",
        metadata_json={"status": job.status, "sources": list(payload.sources)},
    )
    session.commit()
    return _provider_update_job_payload(job)


@api_router.get("/jobs", response_model=WorkbenchJobListResponse)
def list_workbench_jobs(
    session: Annotated[Session, Depends(get_db_session)],
    project_id: str | None = None,
    status: str | None = None,
    kind: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    return {
        "items": [
            _workbench_job_payload(job)
            for job in repo.list_workbench_jobs(
                project_id=project_id,
                status=status,
                kind=kind,
                limit=limit,
            )
        ]
    }


@api_router.get("/jobs/{job_id}", response_model=WorkbenchJobResponse)
def get_workbench_job(
    job_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    job = WorkbenchRepository(session).get_workbench_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Workbench job not found.")
    return _workbench_job_payload(job)


@api_router.post("/jobs", response_model=WorkbenchJobResponse)
def enqueue_workbench_job(
    payload: WorkbenchJobCreateRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if payload.project_id is not None and repo.get_project(payload.project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    job = repo.enqueue_workbench_job(
        kind=payload.kind,
        project_id=payload.project_id,
        target_type=payload.target_type,
        target_id=payload.target_id,
        payload_json=payload.payload,
        idempotency_key=payload.idempotency_key,
        priority=payload.priority,
        max_attempts=payload.max_attempts,
    )
    repo.create_audit_event(
        project_id=job.project_id,
        event_type="workbench_job.queued",
        target_type="workbench_job",
        target_id=job.id,
        message=f"Workbench job {job.kind!r} was queued.",
    )
    session.commit()
    return _workbench_job_payload(job)


@api_router.post("/jobs/{job_id}/retry", response_model=WorkbenchJobResponse)
def retry_workbench_job(
    job_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    job = repo.get_workbench_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Workbench job not found.")
    job = repo.retry_workbench_job(job)
    repo.create_audit_event(
        project_id=job.project_id,
        event_type="workbench_job.retry_queued",
        target_type="workbench_job",
        target_id=job.id,
        message=f"Workbench job {job.kind!r} was queued for retry.",
    )
    session.commit()
    return _workbench_job_payload(job)


@api_router.post("/jobs/{job_id}/run", response_model=WorkbenchJobResponse)
def run_queued_workbench_job(
    job_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    job = repo.get_workbench_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Workbench job not found.")
    if job.status == "completed":
        return _workbench_job_payload(job)
    if job.status != "queued":
        raise HTTPException(status_code=409, detail="Only queued Workbench jobs can be run.")

    repo.start_workbench_job(job, worker_id="api-local-runner")
    repo.update_workbench_job_progress(job, progress=25, message=f"{job.kind} started")
    nested = session.begin_nested()
    try:
        result_json = _execute_queued_workbench_job(
            repo=repo,
            session=session,
            settings=settings,
            job=job,
        )
    except Exception as exc:
        nested.rollback()
        session.refresh(job)
        error_message = _workbench_job_error_message(exc)
        repo.fail_workbench_job(job, error_message=error_message, retryable=False)
        repo.create_audit_event(
            project_id=job.project_id,
            event_type="workbench_job.failed",
            target_type="workbench_job",
            target_id=job.id,
            message=f"Workbench job {job.kind!r} failed.",
            metadata_json={"error": error_message},
        )
        session.commit()
        return _workbench_job_payload(job)
    nested.commit()
    repo.complete_workbench_job(job, result_json=result_json)
    repo.create_audit_event(
        project_id=job.project_id,
        event_type="workbench_job.completed",
        target_type="workbench_job",
        target_id=job.id,
        message=f"Workbench job {job.kind!r} completed.",
    )
    session.commit()
    return _workbench_job_payload(job)


def _execute_queued_workbench_job(
    *,
    repo: WorkbenchRepository,
    session: Session,
    settings: WorkbenchSettings,
    job: Any,
) -> dict[str, Any]:
    payload = job.payload_json if isinstance(job.payload_json, dict) else {}
    if job.kind == "create_report":
        analysis_run_id = _queued_job_analysis_run_id(job, payload)
        report_format_value = str(payload.get("format") or "html")
        if report_format_value not in {"json", "markdown", "html", "csv", "sarif"}:
            raise WorkbenchReportError(f"Unsupported report format: {report_format_value}.")
        report_format = cast(ReportFormat, report_format_value)
        report = create_run_report(
            session=session,
            settings=settings,
            analysis_run_id=analysis_run_id,
            report_format=report_format,
        )
        job.project_id = report.project_id
        repo.create_audit_event(
            project_id=report.project_id,
            event_type="report.created",
            target_type="report",
            target_id=report.id,
            message=f"{report_format} report was created.",
            metadata_json={"job_id": job.id, "runner": "api-local-runner"},
        )
        return {
            "report_id": report.id,
            "analysis_run_id": report.analysis_run_id,
            "format": report.format,
        }
    if job.kind == "create_evidence_bundle":
        analysis_run_id = _queued_job_analysis_run_id(job, payload)
        bundle = create_run_evidence_bundle(
            session=session,
            settings=settings,
            analysis_run_id=analysis_run_id,
        )
        job.project_id = bundle.project_id
        repo.create_audit_event(
            project_id=bundle.project_id,
            event_type="evidence_bundle.created",
            target_type="evidence_bundle",
            target_id=bundle.id,
            message="Evidence bundle was created.",
            metadata_json={"job_id": job.id, "runner": "api-local-runner"},
        )
        return {
            "evidence_bundle_id": bundle.id,
            "analysis_run_id": bundle.analysis_run_id,
        }
    if job.kind == "provider_update":
        provider_payload = ProviderUpdateJobRequest.model_validate(payload)
        provider_job = _create_provider_update_job_record(
            repo=repo,
            settings=settings,
            payload=provider_payload,
        )
        provider_job.metadata_json = {
            **(provider_job.metadata_json or {}),
            "job_id": job.id,
        }
        repo.create_audit_event(
            project_id=job.project_id,
            event_type="provider_update_job.created",
            target_type="provider_update_job",
            target_id=provider_job.id,
            message="Provider update job was created.",
            metadata_json={
                "status": provider_job.status,
                "sources": list(provider_payload.sources),
            },
        )
        return {
            "provider_update_job_id": provider_job.id,
            "status": provider_job.status,
            "new_snapshot_id": (provider_job.metadata_json or {}).get("new_snapshot_id"),
        }
    if job.kind == "import_findings":
        if not job.project_id:
            raise WorkbenchAnalysisError("Queued import job is missing project_id.")
        input_paths = [
            _queued_job_artifact_path(value, settings=settings)
            for value in _job_payload_list(payload.get("input_paths") or payload.get("input_path"))
        ]
        input_formats = _job_payload_list(
            payload.get("input_formats") or payload.get("input_format")
        )
        original_filenames = _job_payload_list(
            payload.get("original_filenames") or payload.get("original_filename")
        )
        if not input_paths:
            raise WorkbenchAnalysisError("Queued import job is missing input_paths.")
        if len(input_formats) != len(input_paths):
            raise WorkbenchAnalysisError(
                "Queued import job input format count does not match files."
            )
        if not original_filenames:
            original_filenames = [path.name for path in input_paths]
        if len(original_filenames) != len(input_paths):
            raise WorkbenchAnalysisError(
                "Queued import job original filename count does not match files."
            )
        result = run_workbench_import(
            session=session,
            settings=settings,
            project_id=job.project_id,
            input_path=input_paths,
            original_filename=original_filenames,
            input_format=input_formats,
            provider_snapshot_file=_queued_job_optional_artifact_path(
                payload.get("provider_snapshot_file"),
                settings=settings,
            ),
            locked_provider_data=bool(payload.get("locked_provider_data", False)),
            attack_source=str(payload.get("attack_source") or "none"),
            attack_mapping_file=_queued_job_optional_artifact_path(
                payload.get("attack_mapping_file"),
                settings=settings,
            ),
            attack_technique_metadata_file=_queued_job_optional_artifact_path(
                payload.get("attack_technique_metadata_file"),
                settings=settings,
            ),
            asset_context_file=_queued_job_optional_artifact_path(
                payload.get("asset_context_file"),
                settings=settings,
            ),
            vex_file=_queued_job_optional_artifact_path(payload.get("vex_file"), settings=settings),
            waiver_file=_queued_job_optional_artifact_path(
                payload.get("waiver_file"),
                settings=settings,
            ),
            defensive_context_file=_queued_job_optional_artifact_path(
                payload.get("defensive_context_file"),
                settings=settings,
            ),
        )
        result.run.metadata_json = {**result.run.metadata_json, "job_id": job.id}
        return {
            "analysis_run_id": result.run.id,
            "findings_count": result.run.metadata_json.get("findings_count", 0),
        }
    raise WorkbenchAnalysisError(f"Unsupported Workbench job kind: {job.kind}.")


def _queued_job_analysis_run_id(job: Any, payload: dict[str, Any]) -> str:
    raw_value = payload.get("analysis_run_id") or job.target_id
    if not raw_value:
        raise WorkbenchReportError("Queued job is missing analysis_run_id.")
    return str(raw_value)


def _job_payload_list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None and str(item)]
    return [str(value)]


def _queued_job_optional_artifact_path(
    value: Any,
    *,
    settings: WorkbenchSettings,
) -> Path | None:
    if value is None or value == "":
        return None
    return _queued_job_artifact_path(str(value), settings=settings)


def _queued_job_artifact_path(value: str, *, settings: WorkbenchSettings) -> Path:
    candidate = Path(value).expanduser().resolve(strict=False)
    allowed_roots = (
        settings.upload_dir.resolve(strict=False),
        settings.provider_snapshot_dir.resolve(strict=False),
        settings.provider_cache_dir.resolve(strict=False),
        settings.attack_artifact_dir.resolve(strict=False),
    )
    if not any(candidate.is_relative_to(root) for root in allowed_roots):
        raise WorkbenchAnalysisError("Queued job artifact path is outside Workbench data roots.")
    if not candidate.is_file():
        raise WorkbenchAnalysisError("Queued job artifact no longer exists.")
    return candidate


def _workbench_job_error_message(exc: Exception) -> str:
    if isinstance(exc, HTTPException):
        return str(exc.detail)
    return str(exc) or exc.__class__.__name__


@api_router.post("/projects/{project_id}/settings/config", response_model=ProjectConfigResponse)
def save_project_config(
    project_id: str,
    payload: ProjectConfigRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    try:
        document = RuntimeConfigDocument.model_validate(payload.config)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid project config: {exc}") from exc
    snapshot = repo.save_project_config_snapshot(
        project_id=project_id,
        source="api",
        config_json=document.model_dump(),
    )
    repo.create_audit_event(
        project_id=project_id,
        event_type="project_config.saved",
        target_type="project_config_snapshot",
        target_id=snapshot.id,
        message="Project config snapshot was saved.",
    )
    session.commit()
    return _project_config_payload(snapshot)


@api_router.get("/projects/{project_id}/settings/config")
def get_project_config(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    snapshot = repo.get_latest_project_config_snapshot(project_id)
    return {"item": _project_config_payload(snapshot) if snapshot is not None else None}


@api_router.get("/projects/{project_id}/settings/config/history")
def list_project_config_history(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return {
        "items": [
            _project_config_payload(snapshot)
            for snapshot in repo.list_project_config_snapshots(project_id, limit=limit)
        ]
    }


@api_router.get("/projects/{project_id}/settings/config/defaults")
def get_project_config_defaults(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return {"config": RuntimeConfigDocument().model_dump()}


@api_router.get("/projects/{project_id}/settings/config/{snapshot_id}/export")
def export_project_config_snapshot(
    project_id: str,
    snapshot_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> JSONResponse:
    repo = WorkbenchRepository(session)
    snapshot = repo.get_project_config_snapshot(snapshot_id)
    if snapshot is None or snapshot.project_id != project_id:
        raise HTTPException(status_code=404, detail="Project config snapshot not found.")
    response = JSONResponse(snapshot.config_json or {})
    response.headers["Content-Disposition"] = (
        f'attachment; filename="vuln-prioritizer-config-{snapshot.id}.json"'
    )
    return response


@api_router.get(
    "/projects/{project_id}/settings/config/{snapshot_id}/diff",
    response_model=ProjectConfigDiffResponse,
)
def diff_project_config_snapshot(
    project_id: str,
    snapshot_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    base_id: str | None = None,
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    target = repo.get_project_config_snapshot(snapshot_id)
    if target is None or target.project_id != project_id:
        raise HTTPException(status_code=404, detail="Project config snapshot not found.")
    if base_id is not None:
        base = repo.get_project_config_snapshot(base_id)
        if base is None or base.project_id != project_id:
            raise HTTPException(status_code=404, detail="Base config snapshot not found.")
    else:
        history = repo.list_project_config_snapshots(project_id, limit=200)
        older = [
            snapshot
            for snapshot in history
            if snapshot.id != target.id and snapshot.created_at <= target.created_at
        ]
        base = older[0] if older else None
    return _config_diff_payload(base=base, target=target)


@api_router.post(
    "/projects/{project_id}/settings/config/{snapshot_id}/rollback",
    response_model=ProjectConfigResponse,
)
def rollback_project_config_snapshot(
    project_id: str,
    snapshot_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    target = repo.get_project_config_snapshot(snapshot_id)
    if target is None or target.project_id != project_id:
        raise HTTPException(status_code=404, detail="Project config snapshot not found.")
    snapshot = repo.save_project_config_snapshot(
        project_id=project_id,
        source=f"rollback:{target.id}",
        config_json=target.config_json or {},
    )
    repo.create_audit_event(
        project_id=project_id,
        event_type="project_config.rolled_back",
        target_type="project_config_snapshot",
        target_id=snapshot.id,
        message="Project config snapshot was rolled back.",
        metadata_json={"rolled_back_to": target.id},
    )
    session.commit()
    return _project_config_payload(snapshot)


@api_router.post(
    "/projects/{project_id}/github/issues/preview",
    response_model=GitHubIssuePreviewResponse,
)
def preview_github_issues(
    project_id: str,
    payload: GitHubIssuePreviewRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    findings = _sort_findings(
        _filter_findings(
            repo.list_project_findings(project_id),
            priority=payload.priority,
            status=None,
            q=None,
            kev=None,
            owner=None,
            service=None,
            min_epss=None,
            min_cvss=None,
        ),
        sort="operational",
    )
    preview_items = []
    duplicate_keys: set[str] = set()
    for finding in findings:
        item = _github_issue_preview_payload(finding, payload=payload)
        if item["duplicate_key"] in duplicate_keys:
            continue
        duplicate_keys.add(item["duplicate_key"])
        preview_items.append(item)
        if len(preview_items) >= payload.limit:
            break
    return {
        "dry_run": True,
        "items": preview_items,
    }


@api_router.post(
    "/projects/{project_id}/github/issues/export",
    response_model=GitHubIssueExportResponse,
)
def export_github_issues(
    project_id: str,
    payload: GitHubIssueExportRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    repository_path = _github_repository_path(payload.repository)
    token = None if payload.dry_run else _github_export_token(payload.token_env)
    findings = _sort_findings(
        _filter_findings(
            repo.list_project_findings(project_id),
            priority=payload.priority,
            status=None,
            q=None,
            kev=None,
            owner=None,
            service=None,
            min_epss=None,
            min_cvss=None,
        ),
        sort="operational",
    )
    exported_items = []
    batch_keys: set[str] = set()
    created_count = 0
    skipped_count = 0
    for finding in findings:
        item = _github_issue_preview_payload(finding, payload=payload)
        duplicate_key = item["duplicate_key"]
        already_exported = repo.github_issue_export_exists(project_id, duplicate_key)
        if duplicate_key in batch_keys or already_exported:
            skipped_count += 1
            exported_items.append(
                {
                    **item,
                    "status": "skipped_duplicate",
                    "issue_url": None,
                    "issue_number": None,
                }
            )
        elif payload.dry_run:
            exported_items.append(
                {
                    **item,
                    "status": "preview",
                    "issue_url": None,
                    "issue_number": None,
                }
            )
        else:
            if token is None:
                raise HTTPException(status_code=422, detail="GitHub token is not configured.")
            issue = _create_github_issue(
                repository_path=repository_path,
                token=token,
                item=item,
            )
            repo.create_github_issue_export(
                project_id=project_id,
                finding_id=finding.id,
                duplicate_key=duplicate_key,
                title=item["title"],
                html_url=issue["html_url"],
                issue_number=issue["number"],
            )
            created_count += 1
            exported_items.append(
                {
                    **item,
                    "status": "created",
                    "issue_url": issue["html_url"],
                    "issue_number": issue["number"],
                }
            )
        batch_keys.add(duplicate_key)
        if len(exported_items) >= payload.limit:
            break
    repo.create_audit_event(
        project_id=project_id,
        event_type="github_issues.exported",
        target_type="project",
        target_id=project_id,
        message="GitHub issue export was processed.",
        metadata_json={
            "dry_run": payload.dry_run,
            "created_count": created_count,
            "skipped_count": skipped_count,
            "item_count": len(exported_items),
        },
    )
    session.commit()
    return {
        "dry_run": payload.dry_run,
        "created_count": created_count,
        "skipped_count": skipped_count,
        "items": exported_items,
    }


@api_router.post(
    "/projects/{project_id}/tickets/preview",
    response_model=TicketSyncResponse,
)
def preview_ticket_sync(
    project_id: str,
    payload: TicketSyncPreviewRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return {
        "dry_run": True,
        "created_count": 0,
        "skipped_count": 0,
        "items": [
            {**item, "status": "preview", "ticket_url": None, "external_id": None}
            for item in _ticket_sync_preview_items(repo, project_id, payload)
        ],
    }


@api_router.post(
    "/projects/{project_id}/tickets/export",
    response_model=TicketSyncResponse,
)
def export_ticket_sync(
    project_id: str,
    payload: TicketSyncExportRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    base_url = None if payload.dry_run else _ticket_base_url(payload.base_url)
    token = None if payload.dry_run else _ticket_sync_token(payload.token_env)
    jira_project_key = (
        _jira_project_key(payload.jira_project_key)
        if payload.provider == "jira" and not payload.dry_run
        else None
    )
    servicenow_table = (
        _servicenow_table(payload.servicenow_table)
        if payload.provider == "servicenow"
        else payload.servicenow_table
    )
    exported_items: list[dict[str, Any]] = []
    batch_keys: set[str] = set()
    created_count = 0
    skipped_count = 0
    for item in _ticket_sync_preview_items(repo, project_id, payload):
        duplicate_key = item["duplicate_key"]
        stored_duplicate_key = f"{payload.provider}:{duplicate_key}"
        already_exported = repo.github_issue_export_exists(project_id, stored_duplicate_key)
        if duplicate_key in batch_keys or already_exported:
            skipped_count += 1
            exported_items.append(
                {**item, "status": "skipped_duplicate", "ticket_url": None, "external_id": None}
            )
        elif payload.dry_run:
            exported_items.append(
                {**item, "status": "preview", "ticket_url": None, "external_id": None}
            )
        else:
            if base_url is None or token is None:
                raise HTTPException(status_code=422, detail="Ticket sync is not configured.")
            if payload.provider == "jira":
                if jira_project_key is None:
                    raise HTTPException(status_code=422, detail="jira_project_key is required.")
                ticket = _create_jira_issue(
                    base_url=base_url,
                    token=token,
                    project_key=jira_project_key,
                    item=item,
                )
            else:
                ticket = _create_servicenow_ticket(
                    base_url=base_url,
                    token=token,
                    table=servicenow_table,
                    item=item,
                )
            repo.create_github_issue_export(
                project_id=project_id,
                finding_id=str(item.get("finding_id")) if item.get("finding_id") else None,
                duplicate_key=stored_duplicate_key,
                title=str(item.get("title") or item.get("cve_id") or "Ticket sync item"),
                html_url=ticket.get("ticket_url"),
                issue_number=None,
            )
            created_count += 1
            exported_items.append({**item, "status": "created", **ticket})
        batch_keys.add(duplicate_key)
        if len(exported_items) >= payload.limit:
            break
    repo.create_audit_event(
        project_id=project_id,
        event_type="ticket_sync.exported",
        target_type="project",
        target_id=project_id,
        message=f"{payload.provider} ticket sync was processed.",
        metadata_json={
            "provider": payload.provider,
            "dry_run": payload.dry_run,
            "created_count": created_count,
            "skipped_count": skipped_count,
            "item_count": len(exported_items),
        },
    )
    session.commit()
    return {
        "dry_run": payload.dry_run,
        "created_count": created_count,
        "skipped_count": skipped_count,
        "items": exported_items,
    }


@api_router.post("/analysis-runs/{run_id}/reports", response_model=ReportResponse)
def create_report(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    payload: ReportCreateRequest,
) -> dict[str, Any]:
    try:
        durable_job, report = run_sync_workbench_job(
            session=session,
            kind="create_report",
            target_type="analysis_run",
            target_id=run_id,
            payload_json={"analysis_run_id": run_id, "format": payload.format},
            operation=lambda _repo, _job: create_run_report(
                session=session,
                settings=settings,
                analysis_run_id=run_id,
                report_format=payload.format,
            ),
            result=lambda value: {
                "report_id": value.id,
                "analysis_run_id": value.analysis_run_id,
                "format": value.format,
            },
        )
    except WorkbenchReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    durable_job.project_id = report.project_id
    WorkbenchRepository(session).create_audit_event(
        project_id=report.project_id,
        event_type="report.created",
        target_type="report",
        target_id=report.id,
        message=f"{payload.format} report was created.",
        metadata_json={"job_id": durable_job.id},
    )
    session.commit()
    return _report_payload(report)


@api_router.post(
    "/analysis-runs/{run_id}/evidence-bundle",
    response_model=EvidenceBundleResponse,
)
def create_evidence_bundle(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    try:
        durable_job, bundle = run_sync_workbench_job(
            session=session,
            kind="create_evidence_bundle",
            target_type="analysis_run",
            target_id=run_id,
            payload_json={"analysis_run_id": run_id},
            operation=lambda _repo, _job: create_run_evidence_bundle(
                session=session,
                settings=settings,
                analysis_run_id=run_id,
            ),
            result=lambda value: {
                "evidence_bundle_id": value.id,
                "analysis_run_id": value.analysis_run_id,
            },
        )
    except WorkbenchReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    durable_job.project_id = bundle.project_id
    WorkbenchRepository(session).create_audit_event(
        project_id=bundle.project_id,
        event_type="evidence_bundle.created",
        target_type="evidence_bundle",
        target_id=bundle.id,
        message="Evidence bundle was created.",
        metadata_json={"job_id": durable_job.id},
    )
    session.commit()
    return _evidence_bundle_payload(bundle)


@api_router.get("/projects/{project_id}/artifacts")
def list_project_artifacts(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    reports = repo.list_project_reports(project_id)
    bundles = repo.list_project_evidence_bundles(project_id)
    return {
        "reports": [_report_payload(report) for report in reports],
        "evidence_bundles": [_evidence_bundle_payload(bundle) for bundle in bundles],
        "disk_usage_bytes": _artifact_disk_usage(
            [report.path for report in reports] + [bundle.path for bundle in bundles]
        ),
    }


@api_router.get(
    "/projects/{project_id}/artifacts/retention",
    response_model=ArtifactRetentionResponse,
)
def get_project_artifact_retention(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return _artifact_retention_payload(
        repo.get_project_artifact_retention(project_id),
        project_id=project_id,
    )


@api_router.patch(
    "/projects/{project_id}/artifacts/retention",
    response_model=ArtifactRetentionResponse,
)
def update_project_artifact_retention(
    project_id: str,
    payload: ArtifactRetentionRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    retention = repo.upsert_project_artifact_retention(
        project_id=project_id,
        report_retention_days=payload.report_retention_days,
        evidence_retention_days=payload.evidence_retention_days,
        max_disk_usage_mb=payload.max_disk_usage_mb,
    )
    repo.create_audit_event(
        project_id=project_id,
        event_type="artifact_retention.updated",
        target_type="project",
        target_id=project_id,
        message="Artifact retention settings were updated.",
        metadata_json=payload.model_dump(),
    )
    session.commit()
    return _artifact_retention_payload(retention, project_id=project_id)


@api_router.post(
    "/projects/{project_id}/artifacts/cleanup",
    response_model=ArtifactCleanupResponse,
)
def cleanup_project_artifact_retention(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    dry_run: bool = Query(default=True),
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    result = cleanup_project_artifacts(
        session=session,
        settings=settings,
        project_id=project_id,
        dry_run=dry_run,
    )
    repo.create_audit_event(
        project_id=project_id,
        event_type="artifact_cleanup.completed",
        target_type="project",
        target_id=project_id,
        message="Artifact cleanup completed.",
        metadata_json=result.to_dict(),
    )
    session.commit()
    return result.to_dict()


@api_router.get("/reports/{report_id}/download")
def download_report(
    report_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> StreamingResponse:
    report = WorkbenchRepository(session).get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    report_path = _resolve_download_artifact(
        report.path,
        settings=settings,
        expected_sha256=report.sha256,
        missing_detail="Report not found.",
    )
    return _artifact_response(report_path, media_type="application/octet-stream")


@api_router.delete("/reports/{report_id}")
def delete_report(
    report_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    report = repo.get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    artifact_removed = _delete_download_artifact(
        report.path,
        settings=settings,
        expected_sha256=report.sha256,
    )
    project_id = report.project_id
    repo.delete_report(report)
    repo.create_audit_event(
        project_id=project_id,
        event_type="report.deleted",
        target_type="report",
        target_id=report_id,
        message="Report artifact was deleted.",
        metadata_json={"artifact_removed": artifact_removed},
    )
    session.commit()
    return {"deleted": True, "artifact_removed": artifact_removed}


@api_router.get("/evidence-bundles/{bundle_id}/download")
def download_evidence_bundle(
    bundle_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> StreamingResponse:
    bundle = WorkbenchRepository(session).get_evidence_bundle(bundle_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Evidence bundle not found.")
    bundle_path = _resolve_download_artifact(
        bundle.path,
        settings=settings,
        expected_sha256=bundle.sha256,
        missing_detail="Evidence bundle not found.",
    )
    return _artifact_response(bundle_path, media_type="application/zip")


@api_router.delete("/evidence-bundles/{bundle_id}")
def delete_evidence_bundle(
    bundle_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    bundle = repo.get_evidence_bundle(bundle_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Evidence bundle not found.")
    artifact_removed = _delete_download_artifact(
        bundle.path,
        settings=settings,
        expected_sha256=bundle.sha256,
    )
    project_id = bundle.project_id
    repo.delete_evidence_bundle(bundle)
    repo.create_audit_event(
        project_id=project_id,
        event_type="evidence_bundle.deleted",
        target_type="evidence_bundle",
        target_id=bundle_id,
        message="Evidence bundle artifact was deleted.",
        metadata_json={"artifact_removed": artifact_removed},
    )
    session.commit()
    return {"deleted": True, "artifact_removed": artifact_removed}


@api_router.get(
    "/evidence-bundles/{bundle_id}/verify",
    response_model=EvidenceBundleVerificationResponse,
)
def verify_evidence_bundle_api(
    bundle_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    try:
        return verify_run_evidence_bundle(
            session=session,
            settings=settings,
            bundle_id=bundle_id,
        )
    except WorkbenchReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _api_token_hash(token_value: str) -> str:
    return api_token_digest(token_value)


def _selected_import_files(
    *,
    file: UploadFile | None,
    files: list[UploadFile] | None,
) -> list[UploadFile]:
    selected = [item for item in (files or []) if item.filename]
    if file is not None and file.filename:
        selected.insert(0, file)
    if not selected:
        raise HTTPException(status_code=422, detail="At least one import file is required.")
    return selected


def _selected_import_formats(
    *,
    input_format: str,
    input_formats: list[str] | None,
    file_count: int,
) -> list[str]:
    selected = [item for item in (input_formats or []) if item]
    if not selected:
        selected = [input_format]
    if len(selected) == 1 and file_count > 1:
        return selected * file_count
    if len(selected) != file_count:
        raise HTTPException(
            status_code=422,
            detail="input_formats must contain one format per uploaded file.",
        )
    return selected


def _patched_detection_control_values(
    control: Any,
    payload: DetectionControlPatchRequest,
) -> dict[str, Any]:
    values = {
        "control_id": control.control_id,
        "name": control.name,
        "technique_id": control.technique_id,
        "technique_name": control.technique_name,
        "source_type": control.source_type,
        "coverage_level": control.coverage_level,
        "environment": control.environment,
        "owner": control.owner,
        "evidence_ref": control.evidence_ref,
        "evidence_refs": list(control.evidence_refs_json or []),
        "review_status": control.review_status,
        "notes": control.notes,
        "last_verified_at": control.last_verified_at,
    }
    for field_name in payload.model_fields_set:
        values[field_name] = getattr(payload, field_name)
    return _detection_control_values(values, index=1)


def _config_diff_payload(*, base: Any | None, target: Any) -> dict[str, Any]:
    before = base.config_json if base is not None and isinstance(base.config_json, dict) else {}
    after = target.config_json if isinstance(target.config_json, dict) else {}
    added: dict[str, Any] = {}
    removed: dict[str, Any] = {}
    changed: dict[str, dict[str, Any]] = {}
    _collect_config_diff(
        before=before,
        after=after,
        prefix="",
        added=added,
        removed=removed,
        changed=changed,
    )
    return {
        "base_id": base.id if base is not None else None,
        "target_id": target.id,
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def _collect_config_diff(
    *,
    before: dict[str, Any],
    after: dict[str, Any],
    prefix: str,
    added: dict[str, Any],
    removed: dict[str, Any],
    changed: dict[str, dict[str, Any]],
) -> None:
    for key in sorted(set(before) | set(after)):
        path = f"{prefix}.{key}" if prefix else key
        if key not in before:
            added[path] = after[key]
        elif key not in after:
            removed[path] = before[key]
        elif isinstance(before[key], dict) and isinstance(after[key], dict):
            _collect_config_diff(
                before=before[key],
                after=after[key],
                prefix=path,
                added=added,
                removed=removed,
                changed=changed,
            )
        elif before[key] != after[key]:
            changed[path] = {"before": before[key], "after": after[key]}


def _ticket_sync_preview_items(
    repo: WorkbenchRepository,
    project_id: str,
    payload: TicketSyncPreviewRequest,
) -> list[dict[str, Any]]:
    findings = _sort_findings(
        _filter_findings(
            repo.list_project_findings(project_id),
            priority=payload.priority,
            status=None,
            q=None,
            kev=None,
            owner=None,
            service=None,
            min_epss=None,
            min_cvss=None,
        ),
        sort="operational",
    )
    preview_items: list[dict[str, Any]] = []
    duplicate_keys: set[str] = set()
    for finding in findings:
        item = _ticket_preview_payload(finding, payload=payload)
        if item["duplicate_key"] in duplicate_keys:
            continue
        duplicate_keys.add(item["duplicate_key"])
        preview_items.append(item)
        if len(preview_items) >= payload.limit:
            break
    return preview_items


def _artifact_disk_usage(paths: list[str]) -> int:
    total = 0
    for raw_path in paths:
        path = Path(raw_path)
        try:
            total += path.stat().st_size
        except OSError:
            continue
    return total


def _directory_diagnostics(path: Path) -> dict[str, Any]:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".vuln-prioritizer-write-check"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        writable = True
    except OSError:
        writable = False
    return {
        "path": str(path),
        "exists": path.exists(),
        "writable": writable,
    }


def _asset_audit_snapshot(asset: Any) -> dict[str, Any]:
    return {
        "asset_id": asset.asset_id,
        "target_ref": asset.target_ref,
        "owner": asset.owner,
        "business_service": asset.business_service,
        "environment": asset.environment,
        "exposure": asset.exposure,
        "criticality": asset.criticality,
    }


def _validate_detection_attachment_filename(filename: str) -> None:
    if Path(filename).name != filename or filename in {"", ".", ".."}:
        raise HTTPException(status_code=422, detail="Invalid attachment filename.")
    if Path(filename).suffix.lower() not in {
        ".txt",
        ".md",
        ".json",
        ".csv",
        ".pdf",
        ".png",
        ".jpg",
        ".jpeg",
    }:
        raise HTTPException(status_code=422, detail="Unsupported attachment file type.")


def _resolve_upload_artifact(
    value: str,
    *,
    settings: WorkbenchSettings,
    expected_sha256: str,
    missing_detail: str,
) -> Path:
    resolved = Path(value).resolve(strict=False)
    upload_root = settings.upload_dir.resolve(strict=False)
    if not resolved.is_relative_to(upload_root) or not resolved.is_file():
        raise HTTPException(status_code=404, detail=missing_detail)
    actual_sha256 = hashlib.sha256(resolved.read_bytes()).hexdigest()
    if actual_sha256 != expected_sha256:
        raise HTTPException(status_code=409, detail="Attachment checksum mismatch.")
    return resolved


def _delete_upload_artifact(
    value: str,
    *,
    settings: WorkbenchSettings,
    expected_sha256: str,
) -> bool:
    resolved = Path(value).resolve(strict=False)
    upload_root = settings.upload_dir.resolve(strict=False)
    if not resolved.is_relative_to(upload_root):
        raise HTTPException(status_code=422, detail="Attachment path is outside the upload root.")
    if not resolved.is_file():
        return False
    actual_sha256 = hashlib.sha256(resolved.read_bytes()).hexdigest()
    if actual_sha256 != expected_sha256:
        raise HTTPException(status_code=409, detail="Attachment checksum mismatch.")
    resolved.unlink()
    return True
