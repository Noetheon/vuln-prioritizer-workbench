"""Server-rendered Workbench routes."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, cast

from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from vuln_prioritizer.api.deps import get_db_session, get_workbench_settings
from vuln_prioritizer.api.routes import _save_upload
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.services.workbench_analysis import (
    WorkbenchAnalysisError,
    run_workbench_import,
)
from vuln_prioritizer.services.workbench_reports import (
    ReportFormat,
    WorkbenchReportError,
    create_run_evidence_bundle,
    create_run_report,
)
from vuln_prioritizer.web.view_models import dashboard_model, findings_model, reports_model
from vuln_prioritizer.workbench_config import WorkbenchSettings

TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
web_router = APIRouter()


@web_router.get("/", response_class=HTMLResponse)
def index(session: Annotated[Session, Depends(get_db_session)]) -> RedirectResponse:
    projects = WorkbenchRepository(session).list_projects()
    if not projects:
        return RedirectResponse("/projects/new", status_code=303)
    return RedirectResponse(f"/projects/{projects[-1].id}/dashboard", status_code=303)


@web_router.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    return Response(status_code=204)


@web_router.get("/projects/new", response_class=HTMLResponse)
def new_project(
    request: Request,
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "projects/new.html",
        {"csrf_token": settings.csrf_token},
    )


@web_router.post("/projects", response_class=HTMLResponse)
def create_project_form(
    request: Request,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    name: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    repo = WorkbenchRepository(session)
    project = repo.create_project(name=name.strip(), description=description.strip() or None)
    session.commit()
    return RedirectResponse(f"/projects/{project.id}/dashboard", status_code=303)


@web_router.get("/projects/{project_id}/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> HTMLResponse:
    repo = WorkbenchRepository(session)
    project = repo.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    model = dashboard_model(
        project,
        repo.list_project_findings(project.id),
        repo.list_analysis_runs(project.id),
    )
    return templates.TemplateResponse(request, "dashboard.html", model)


@web_router.get("/projects/{project_id}/imports/new", response_class=HTMLResponse)
def new_import(
    request: Request,
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> HTMLResponse:
    project = WorkbenchRepository(session).get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return templates.TemplateResponse(
        request,
        "imports/new.html",
        {"project": project, "csrf_token": settings.csrf_token},
    )


@web_router.post("/web/projects/{project_id}/imports", response_class=HTMLResponse)
async def create_import_form(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    file: UploadFile,
    input_format: Annotated[str, Form()],
    provider_snapshot_file: Annotated[str, Form()] = "",
    locked_provider_data: Annotated[bool, Form()] = False,
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
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
    return RedirectResponse(f"/analysis-runs/{result.run.id}/reports", status_code=303)


@web_router.get("/projects/{project_id}/findings", response_class=HTMLResponse)
def findings(
    request: Request,
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> HTMLResponse:
    repo = WorkbenchRepository(session)
    project = repo.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return templates.TemplateResponse(
        request,
        "findings/index.html",
        findings_model(project, repo.list_project_findings(project.id)),
    )


@web_router.get("/findings/{finding_id}", response_class=HTMLResponse)
def finding_detail(
    request: Request,
    finding_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> HTMLResponse:
    finding = WorkbenchRepository(session).get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return templates.TemplateResponse(request, "findings/detail.html", {"finding": finding})


@web_router.get("/analysis-runs/{run_id}/reports", response_class=HTMLResponse)
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
    return templates.TemplateResponse(
        request,
        "reports/index.html",
        reports_model(run, repo.list_run_reports(run.id), repo.list_run_evidence_bundles(run.id))
        | {"csrf_token": settings.csrf_token},
    )


@web_router.post("/web/analysis-runs/{run_id}/reports", response_class=HTMLResponse)
def create_report_form(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    report_format: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    if report_format not in {"json", "markdown", "html"}:
        raise HTTPException(status_code=422, detail="Unsupported report format.")
    try:
        create_run_report(
            session=session,
            settings=settings,
            analysis_run_id=run_id,
            report_format=cast(ReportFormat, report_format),
        )
    except WorkbenchReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    session.commit()
    return RedirectResponse(f"/analysis-runs/{run_id}/reports", status_code=303)


@web_router.post("/web/analysis-runs/{run_id}/evidence-bundle", response_class=HTMLResponse)
def create_evidence_form(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    try:
        create_run_evidence_bundle(session=session, settings=settings, analysis_run_id=run_id)
    except WorkbenchReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    session.commit()
    return RedirectResponse(f"/analysis-runs/{run_id}/reports", status_code=303)


def _check_csrf(submitted: str, settings: WorkbenchSettings) -> None:
    if submitted != settings.csrf_token:
        raise HTTPException(status_code=403, detail="Invalid CSRF token.")
