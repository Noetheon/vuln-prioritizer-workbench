"""Report API routes for Workbench analysis runs."""

from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from starlette.responses import FileResponse

from app.api.deps import LocalActor, SessionDep
from app.api.routes.workbench_access import require_project
from app.core.app_state import workbench_settings
from app.models import (
    Report,
    ReportCreate,
    ReportPublic,
    ReportsPublic,
    ReportVerificationPublic,
    WorkflowRunPublic,
)
from app.repositories import ReportRepository, RunRepository, WorkflowRepository
from app.services import (
    ReportGenerationError,
    ReportService,
    ReportVerificationError,
    verify_evidence_bundle_zip,
)
from app.services.audit import record_audit_event
from app.services.report_artifacts import (
    ReportArtifactChecksumError,
    ReportArtifactNotFoundError,
    build_report_public,
    validated_report_path,
)
from app.services.workflows import latest_report_workflow_public, workflow_run_public

router = APIRouter(tags=["reports"])


@router.post("/runs/{run_id}/report-jobs", response_model=WorkflowRunPublic)
def queue_run_report(
    run_id: uuid.UUID,
    payload: ReportCreate,
    request: Request,
    session: SessionDep,
    local_actor: LocalActor,
) -> WorkflowRunPublic:
    """Queue a report artifact generation workflow for a completed visible run."""
    run = RunRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    project = require_project(session, run.project_id)
    try:
        workflow = ReportService(session, workbench_settings(request)).enqueue_report_generation(
            run=run,
            project=project,
            report_format=payload.format,
            attack_filter=payload.attack_filter,
        )
    except ReportGenerationError as exc:
        record_audit_event(
            session,
            action="report.job.create",
            resource_type="analysis_run",
            resource_id=run.id,
            status="failure",
            actor=local_actor,
            project_id=run.project_id,
            detail={"format": payload.format, "run_id": str(run.id), "error": str(exc)},
        )
        session.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    record_audit_event(
        session,
        action="report.job.create",
        resource_type="analysis_run",
        resource_id=run.id,
        actor=local_actor,
        project_id=run.project_id,
        detail={"format": payload.format, "run_id": str(run.id)},
    )
    session.commit()
    session.refresh(workflow)
    repository = WorkflowRepository(session)
    return workflow_run_public(workflow, latest_event=repository.latest_event(workflow.id))


@router.get("/runs/{run_id}/reports", response_model=ReportsPublic)
def read_run_reports(
    run_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    local_actor: LocalActor,
) -> ReportsPublic:
    """List report metadata for a visible analysis run."""
    run = RunRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    require_project(session, run.project_id)
    reports = ReportRepository(session).list_run_reports(run.id)
    return ReportsPublic(
        data=[
            _report_public(
                report,
                request,
                workflow=latest_report_workflow_public(session, report_id=report.id),
            )
            for report in reports
        ],
        count=len(reports),
    )


@router.get(
    "/reports/{report_id}/download",
    response_class=FileResponse,
    responses={
        200: {
            "content": {
                "application/octet-stream": {"schema": {"format": "binary", "type": "string"}}
            },
            "description": "Report artifact download.",
        }
    },
)
def download_report(
    report_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    local_actor: LocalActor,
) -> FileResponse:
    """Download a visible report after root and checksum validation."""
    report = ReportRepository(session).get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    require_project(session, report.project_id)
    report_path = _report_artifact_path(report, request)
    record_audit_event(
        session,
        action="report.download",
        resource_type="report",
        resource_id=report.id,
        actor=local_actor,
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
    local_actor: LocalActor,
) -> ReportVerificationPublic:
    """Verify a visible evidence bundle report against its embedded manifest."""
    report = ReportRepository(session).get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    require_project(session, report.project_id)
    if report.kind != "evidence-bundle" or report.format != "zip":
        raise HTTPException(status_code=422, detail="Report is not an evidence bundle")

    report_path = _report_artifact_path(report, request)
    try:
        result = verify_evidence_bundle_zip(report_path, display_path=report.filename)
    except ReportVerificationError as exc:
        record_audit_event(
            session,
            action="report.verify",
            resource_type="report",
            resource_id=report.id,
            status="failure",
            actor=local_actor,
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
        actor=local_actor,
        project_id=report.project_id,
        detail={"format": report.format, "kind": report.kind},
    )
    session.commit()
    return ReportVerificationPublic(**result)


def _report_public(
    report: Report,
    request: Request,
    *,
    workflow: WorkflowRunPublic | None = None,
) -> ReportPublic:
    return build_report_public(report, workbench_settings(request), workflow=workflow)


def _report_artifact_path(report: Report, request: Request) -> Path:
    try:
        return validated_report_path(report, workbench_settings(request))
    except ReportArtifactNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Report artifact not found") from exc
    except ReportArtifactChecksumError as exc:
        raise HTTPException(status_code=409, detail="Report artifact checksum mismatch") from exc
