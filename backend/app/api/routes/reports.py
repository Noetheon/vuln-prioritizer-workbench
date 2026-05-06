"""Report API routes for template Workbench analysis runs."""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from starlette.responses import FileResponse

from app.api.deps import ScopedReportUser, SessionDep
from app.api.routes.workbench_access import require_visible_project
from app.core.config import Settings
from app.models import (
    Report,
    ReportCreate,
    ReportPublic,
    ReportsPublic,
    ReportVerificationPublic,
)
from app.repositories import ReportRepository, RunRepository
from app.services import (
    ReportGenerationError,
    ReportService,
    ReportVerificationError,
    verify_evidence_bundle_zip,
)
from app.services.audit import record_audit_event

router = APIRouter(tags=["reports"])


@router.post("/runs/{run_id}/reports", response_model=ReportPublic)
def create_run_report(
    run_id: uuid.UUID,
    payload: ReportCreate,
    request: Request,
    session: SessionDep,
    current_user: ScopedReportUser,
) -> ReportPublic:
    """Create a report artifact for a completed visible analysis run."""
    run = RunRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    project = require_visible_project(session, current_user, run.project_id)
    try:
        report_service = ReportService(session, _template_settings(request))
        if payload.format == "html":
            report = report_service.create_html_report(run=run, project=project)
        elif payload.format == "json":
            report = report_service.create_analysis_json_export(run=run, project=project)
        elif payload.format == "csv":
            report = report_service.create_findings_csv_export(run=run, project=project)
        elif payload.format == "attack-navigator":
            report = report_service.create_attack_navigator_layer(
                run=run,
                project=project,
                filter_value=payload.attack_filter,
            )
        elif payload.format == "sarif":
            report = report_service.create_sarif_report(run=run, project=project)
        elif payload.format == "zip":
            report = report_service.create_evidence_bundle(run=run, project=project)
        else:
            report = report_service.create_markdown_report(run=run, project=project)
    except ReportGenerationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    record_audit_event(
        session,
        action="report.create",
        resource_type="report",
        resource_id=report.id,
        actor=current_user,
        project_id=report.project_id,
        detail={"format": report.format, "kind": report.kind, "run_id": str(run.id)},
    )
    session.commit()
    session.refresh(report)
    return _report_public(report, request)


@router.get("/runs/{run_id}/reports", response_model=ReportsPublic)
def read_run_reports(
    run_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    current_user: ScopedReportUser,
) -> ReportsPublic:
    """List report metadata for a visible analysis run."""
    run = RunRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    require_visible_project(session, current_user, run.project_id)
    reports = ReportRepository(session).list_run_reports(run.id)
    return ReportsPublic(
        data=[_report_public(report, request) for report in reports],
        count=len(reports),
    )


@router.get("/reports/{report_id}/download")
def download_report(
    report_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    current_user: ScopedReportUser,
) -> FileResponse:
    """Download a visible report after root and checksum validation."""
    report = ReportRepository(session).get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    require_visible_project(session, current_user, report.project_id)
    report_path = _validated_report_path(report, _template_settings(request))
    record_audit_event(
        session,
        action="report.download",
        resource_type="report",
        resource_id=report.id,
        actor=current_user,
        project_id=report.project_id,
        detail={"format": report.format, "kind": report.kind},
    )
    session.commit()
    response = FileResponse(
        report_path,
        filename=report.filename,
        media_type=report.content_type,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@router.post("/reports/{report_id}/verify", response_model=ReportVerificationPublic)
def verify_report(
    report_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    current_user: ScopedReportUser,
) -> ReportVerificationPublic:
    """Verify a visible evidence bundle report against its embedded manifest."""
    report = ReportRepository(session).get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    require_visible_project(session, current_user, report.project_id)
    if report.kind != "evidence-bundle" or report.format != "zip":
        raise HTTPException(status_code=422, detail="Report is not an evidence bundle")

    report_path = _validated_report_path(report, _template_settings(request))
    try:
        result = verify_evidence_bundle_zip(report_path, display_path=report.filename)
    except ReportVerificationError as exc:
        record_audit_event(
            session,
            action="report.verify",
            resource_type="report",
            resource_id=report.id,
            status="failure",
            actor=current_user,
            project_id=report.project_id,
            detail={"error": str(exc)},
        )
        session.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    record_audit_event(
        session,
        action="report.verify",
        resource_type="report",
        resource_id=report.id,
        actor=current_user,
        project_id=report.project_id,
        detail={"format": report.format, "kind": report.kind},
    )
    session.commit()
    return ReportVerificationPublic(**result)


def _report_public(report: Report, request: Request) -> ReportPublic:
    settings = _template_settings(request)
    return ReportPublic(
        id=report.id,
        project_id=report.project_id,
        analysis_run_id=report.analysis_run_id,
        kind=report.kind,
        format=report.format,
        filename=report.filename,
        content_type=report.content_type,
        sha256=report.sha256,
        size_bytes=report.size_bytes,
        metadata_json=report.metadata_json,
        created_at=report.created_at,
        download_url=f"{settings.API_V1_STR}/reports/{report.id}/download",
    )


def _validated_report_path(report: Report, settings: Settings) -> Path:
    root = settings.report_dir_path.resolve(strict=False)
    try:
        resolved = Path(report.path).resolve(strict=True)
        resolved.relative_to(root)
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=404, detail="Report artifact not found") from exc

    if not resolved.is_file():
        raise HTTPException(status_code=404, detail="Report artifact not found")
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    if digest != report.sha256:
        raise HTTPException(status_code=409, detail="Report artifact checksum mismatch")
    return resolved


def _template_settings(request: Request) -> Settings:
    candidate = getattr(request.app.state, "template_settings", None)
    if isinstance(candidate, Settings):
        return candidate
    raise HTTPException(status_code=500, detail="Template settings are not configured.")
