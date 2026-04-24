"""JSON API routes for the Workbench MVP."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from vuln_prioritizer.api.deps import get_db_session, get_workbench_settings
from vuln_prioritizer.api.schemas import ProjectCreateRequest, ReportCreateRequest
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.services.workbench_analysis import (
    SUPPORTED_WORKBENCH_INPUT_FORMATS,
    WorkbenchAnalysisError,
    run_workbench_import,
)
from vuln_prioritizer.services.workbench_reports import (
    WorkbenchReportError,
    create_run_evidence_bundle,
    create_run_report,
)
from vuln_prioritizer.workbench_config import WorkbenchSettings

api_router = APIRouter(prefix="/api")

ALLOWED_UPLOAD_SUFFIXES = {
    "cve-list": {".txt", ".csv"},
    "generic-occurrence-csv": {".csv"},
    "trivy-json": {".json"},
    "grype-json": {".json"},
}


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


@api_router.get("/projects")
def list_projects(session: Annotated[Session, Depends(get_db_session)]) -> dict[str, Any]:
    projects = WorkbenchRepository(session).list_projects()
    return {"items": [_project_payload(project) for project in projects]}


@api_router.post("/projects")
def create_project(
    payload: ProjectCreateRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Project name is required.")
    repo = WorkbenchRepository(session)
    project = repo.create_project(name=name, description=payload.description)
    session.commit()
    return _project_payload(project)


@api_router.get("/projects/{project_id}")
def get_project(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    project = WorkbenchRepository(session).get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return _project_payload(project)


@api_router.post("/projects/{project_id}/imports")
async def import_findings(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    input_format: Annotated[str, Form()],
    file: Annotated[UploadFile, File()],
    provider_snapshot_file: Annotated[str | None, Form()] = None,
    locked_provider_data: Annotated[bool, Form()] = False,
) -> dict[str, Any]:
    upload_path = await _save_upload(file, input_format=input_format, settings=settings)
    try:
        result = run_workbench_import(
            session=session,
            settings=settings,
            project_id=project_id,
            input_path=upload_path,
            original_filename=file.filename or upload_path.name,
            input_format=input_format,
            provider_snapshot_file=Path(provider_snapshot_file) if provider_snapshot_file else None,
            locked_provider_data=locked_provider_data,
        )
    except WorkbenchAnalysisError as exc:
        session.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    session.commit()
    return _analysis_run_payload(result.run)


@api_router.get("/analysis-runs/{run_id}")
def get_analysis_run(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    run = WorkbenchRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found.")
    return _analysis_run_payload(run)


@api_router.get("/projects/{project_id}/findings")
def list_findings(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    priority: str | None = None,
    status: str | None = None,
    q: str | None = None,
) -> dict[str, Any]:
    findings = WorkbenchRepository(session).list_project_findings(project_id)
    filtered = [
        finding
        for finding in findings
        if (priority is None or finding.priority == priority)
        and (status is None or finding.status == status)
        and (q is None or q.lower() in finding.cve_id.lower())
    ]
    return {"items": [_finding_payload(finding) for finding in filtered]}


@api_router.get("/findings/{finding_id}")
def get_finding(
    finding_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    finding = WorkbenchRepository(session).get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return _finding_payload(finding, include_detail=True)


@api_router.post("/analysis-runs/{run_id}/reports")
def create_report(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    payload: ReportCreateRequest,
) -> dict[str, Any]:
    try:
        report = create_run_report(
            session=session,
            settings=settings,
            analysis_run_id=run_id,
            report_format=payload.format,
        )
    except WorkbenchReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    session.commit()
    return _report_payload(report)


@api_router.post("/analysis-runs/{run_id}/evidence-bundle")
def create_evidence_bundle(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    try:
        bundle = create_run_evidence_bundle(
            session=session,
            settings=settings,
            analysis_run_id=run_id,
        )
    except WorkbenchReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    session.commit()
    return _evidence_bundle_payload(bundle)


@api_router.get("/reports/{report_id}/download")
def download_report(
    report_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> FileResponse:
    report = WorkbenchRepository(session).get_report(report_id)
    if report is None or not Path(report.path).is_file():
        raise HTTPException(status_code=404, detail="Report not found.")
    return FileResponse(report.path, filename=Path(report.path).name)


@api_router.get("/evidence-bundles/{bundle_id}/download")
def download_evidence_bundle(
    bundle_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> FileResponse:
    bundle = WorkbenchRepository(session).get_evidence_bundle(bundle_id)
    if bundle is None or not Path(bundle.path).is_file():
        raise HTTPException(status_code=404, detail="Evidence bundle not found.")
    return FileResponse(bundle.path, filename=Path(bundle.path).name)


async def _save_upload(
    file: UploadFile,
    *,
    input_format: str,
    settings: WorkbenchSettings,
) -> Path:
    if input_format not in SUPPORTED_WORKBENCH_INPUT_FORMATS:
        raise HTTPException(status_code=422, detail="Unsupported Workbench input format.")
    original_filename = file.filename or "upload"
    sanitized = _sanitize_filename(original_filename)
    suffix = Path(sanitized).suffix.lower()
    if suffix not in ALLOWED_UPLOAD_SUFFIXES[input_format]:
        raise HTTPException(status_code=422, detail="File extension does not match input format.")

    target_dir = settings.upload_dir / uuid4().hex
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / sanitized
    total = 0
    with target_path.open("wb") as output:
        while chunk := await file.read(1024 * 1024):
            total += len(chunk)
            if total > settings.max_upload_bytes:
                target_path.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="Upload exceeds configured limit.")
            output.write(chunk)
    return target_path


def _sanitize_filename(filename: str) -> str:
    name = Path(filename).name.strip() or "upload"
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def _project_payload(project: Any) -> dict[str, Any]:
    return {
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "created_at": project.created_at.isoformat(),
    }


def _analysis_run_payload(run: Any) -> dict[str, Any]:
    return {
        "id": run.id,
        "project_id": run.project_id,
        "input_type": run.input_type,
        "input_filename": run.input_filename,
        "status": run.status,
        "started_at": run.started_at.isoformat(),
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "error_message": run.error_message,
        "summary": {
            "findings_count": run.metadata_json.get("findings_count", 0),
            "kev_hits": run.metadata_json.get("kev_hits", 0),
            "counts_by_priority": run.metadata_json.get("counts_by_priority", {}),
        },
    }


def _finding_payload(finding: Any, *, include_detail: bool = False) -> dict[str, Any]:
    payload = {
        "id": finding.id,
        "project_id": finding.project_id,
        "analysis_run_id": finding.analysis_run_id,
        "cve_id": finding.cve_id,
        "priority": finding.priority,
        "priority_rank": finding.priority_rank,
        "operational_rank": finding.operational_rank,
        "status": finding.status,
        "in_kev": finding.in_kev,
        "epss": finding.epss,
        "cvss_base_score": finding.cvss_base_score,
        "component": finding.component.name if finding.component else None,
        "component_version": finding.component.version if finding.component else None,
        "asset": finding.asset.asset_id if finding.asset else None,
        "owner": finding.asset.owner if finding.asset else None,
        "service": finding.asset.business_service if finding.asset else None,
        "rationale": finding.rationale,
        "recommended_action": finding.recommended_action,
    }
    if include_detail:
        payload["finding"] = finding.finding_json
        payload["occurrences"] = [item.evidence_json for item in finding.occurrences]
    return payload


def _report_payload(report: Any) -> dict[str, Any]:
    return {
        "id": report.id,
        "analysis_run_id": report.analysis_run_id,
        "format": report.format,
        "kind": report.kind,
        "sha256": report.sha256,
        "download_url": f"/api/reports/{report.id}/download",
    }


def _evidence_bundle_payload(bundle: Any) -> dict[str, Any]:
    return {
        "id": bundle.id,
        "analysis_run_id": bundle.analysis_run_id,
        "sha256": bundle.sha256,
        "download_url": f"/api/evidence-bundles/{bundle.id}/download",
    }
