"""Workbench web routes split by domain."""

from __future__ import annotations

# ruff: noqa: F403, F405
from fastapi import APIRouter

from vuln_prioritizer.web.workbench_common import *

router = APIRouter()


@router.get("/analysis-runs/{run_id}/reports", response_class=HTMLResponse)
def run_reports(
    request: Request,
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> HTMLResponse:
    repo = WorkbenchRepository(session)
    run = repo.get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found.")
    project = repo.get_project(run.project_id)
    return templates.TemplateResponse(
        request,
        "reports/index.html",
        reports_model(
            run,
            repo.list_run_reports(run.id),
            repo.list_run_evidence_bundles(run.id),
            project=project,
        )
        | {"csrf_token": settings.csrf_token},
    )


@router.get("/analysis-runs/{run_id}/executive-report", response_class=HTMLResponse)
def run_executive_report(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> HTMLResponse:
    repo = WorkbenchRepository(session)
    run = repo.get_analysis_run(_safe_uuid_path_value(run_id))
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found.")
    project = repo.get_project(run.project_id)
    try:
        model = build_run_executive_report_model(repo=repo, run=run, project=project)
    except WorkbenchExecutiveReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return HTMLResponse(
        render_executive_report_html(
            model,
            stylesheet_href="/static/executive-report.css?v=executive-interactive-5",
            script_href="/static/workbench.js?v=executive-interactive-5",
            include_inline_styles=False,
            back_href=f"/analysis-runs/{run.id}/reports",
        )
    )


@router.post("/web/analysis-runs/{run_id}/reports", response_class=HTMLResponse)
def create_report_form(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    report_format: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    safe_run_id = _safe_uuid_path_value(run_id)
    if report_format not in {"json", "markdown", "html", "csv", "sarif"}:
        raise HTTPException(status_code=422, detail="Unsupported report format.")
    try:
        durable_job, report = run_sync_workbench_job(
            session=session,
            kind="create_report",
            target_type="analysis_run",
            target_id=safe_run_id,
            payload_json={"analysis_run_id": safe_run_id, "format": report_format},
            operation=lambda _repo, _job: create_run_report(
                session=session,
                settings=settings,
                analysis_run_id=safe_run_id,
                report_format=cast(ReportFormat, report_format),
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
        message=f"{report_format} report was created from web form.",
        metadata_json={"job_id": durable_job.id},
    )
    session.commit()
    return RedirectResponse(f"/analysis-runs/{safe_run_id}/reports", status_code=303)


@router.get("/evidence-bundles/{bundle_id}/verify", response_class=HTMLResponse)
def verify_evidence_page(
    request: Request,
    bundle_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> HTMLResponse:
    safe_bundle_id = _safe_uuid_path_value(bundle_id)
    repo = WorkbenchRepository(session)
    bundle = repo.get_evidence_bundle(safe_bundle_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Evidence bundle not found.")
    run = repo.get_analysis_run(bundle.analysis_run_id)
    project = repo.get_project(bundle.project_id)
    try:
        result = verify_run_evidence_bundle(
            session=session,
            settings=settings,
            bundle_id=safe_bundle_id,
        )
    except WorkbenchReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return templates.TemplateResponse(
        request,
        "evidence/verify.html",
        result | {"project": project, "run": run, "bundle": bundle},
    )


@router.post("/web/analysis-runs/{run_id}/evidence-bundle", response_class=HTMLResponse)
def create_evidence_form(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    safe_run_id = _safe_uuid_path_value(run_id)
    try:
        durable_job, bundle = run_sync_workbench_job(
            session=session,
            kind="create_evidence_bundle",
            target_type="analysis_run",
            target_id=safe_run_id,
            payload_json={"analysis_run_id": safe_run_id},
            operation=lambda _repo, _job: create_run_evidence_bundle(
                session=session,
                settings=settings,
                analysis_run_id=safe_run_id,
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
        message="Evidence bundle was created from web form.",
        metadata_json={"job_id": durable_job.id},
    )
    session.commit()
    return RedirectResponse(f"/analysis-runs/{safe_run_id}/reports", status_code=303)
