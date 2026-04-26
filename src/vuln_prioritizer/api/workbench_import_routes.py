"""Workbench import, run, and finding API routes."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session

from vuln_prioritizer.api.deps import get_db_session, get_workbench_settings
from vuln_prioritizer.api.schemas import (
    AnalysisRunResponse,
    FindingResponse,
    FindingsListResponse,
    FindingStatusUpdateRequest,
)
from vuln_prioritizer.api.workbench_payloads import (
    _analysis_run_payload,
    _finding_payload,
)
from vuln_prioritizer.api.workbench_route_support import (
    _selected_import_files,
    _selected_import_formats,
)
from vuln_prioritizer.api.workbench_uploads import (
    _cleanup_saved_uploads,
    _resolve_attack_artifact_path,
    _resolve_provider_snapshot_path,
    _save_optional_context_upload,
    _save_upload,
)
from vuln_prioritizer.api.workbench_waivers import (
    _strip_or_none,
)
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.services.workbench_analysis import (
    WorkbenchAnalysisError,
    run_workbench_import,
)
from vuln_prioritizer.services.workbench_executive_report import (
    WorkbenchExecutiveReportError,
    build_run_executive_report_model,
)
from vuln_prioritizer.services.workbench_jobs import run_sync_workbench_job
from vuln_prioritizer.workbench_config import WorkbenchSettings

router = APIRouter()


@router.get("/projects/{project_id}/runs")
def list_project_runs(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return {"items": [_analysis_run_payload(run) for run in repo.list_analysis_runs(project_id)]}


@router.post("/projects/{project_id}/imports", response_model=AnalysisRunResponse)
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


@router.get("/analysis-runs/{run_id}", response_model=AnalysisRunResponse)
def get_analysis_run(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    run = WorkbenchRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found.")
    return _analysis_run_payload(run)


@router.get("/runs/{run_id}")
def get_run_alias(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    return get_analysis_run(run_id=run_id, session=session)


@router.get("/runs/{run_id}/summary")
def get_run_summary(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    run = WorkbenchRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found.")
    return _analysis_run_payload(run)["summary"]


@router.get("/analysis-runs/{run_id}/executive-report")
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


@router.get("/projects/{project_id}/findings", response_model=FindingsListResponse)
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


@router.get("/findings/{finding_id}")
def get_finding(
    finding_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    finding = WorkbenchRepository(session).get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return _finding_payload(finding, include_detail=True)


@router.patch("/findings/{finding_id}", response_model=FindingResponse)
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


@router.get("/findings/{finding_id}/explain")
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
