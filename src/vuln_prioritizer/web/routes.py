"""Server-rendered Workbench routes."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from vuln_prioritizer.api.deps import get_db_session, get_workbench_settings
from vuln_prioritizer.api.routes import (
    _cleanup_saved_uploads,
    _filter_findings,
    _provider_status_payload,
    _resolve_attack_artifact_path,
    _resolve_provider_snapshot_path,
    _save_optional_context_upload,
    _save_upload,
    _sort_findings,
)
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.services.workbench_analysis import (
    WorkbenchAnalysisError,
    run_workbench_import,
)
from vuln_prioritizer.services.workbench_governance import build_governance_summary
from vuln_prioritizer.services.workbench_reports import (
    ReportFormat,
    WorkbenchReportError,
    create_run_evidence_bundle,
    create_run_report,
    verify_run_evidence_bundle,
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
    project_name = name.strip()
    if not project_name:
        raise HTTPException(status_code=422, detail="Project name is required.")
    repo = WorkbenchRepository(session)
    if repo.get_project_by_name(project_name) is not None:
        raise HTTPException(status_code=409, detail="Project already exists.")
    project = repo.create_project(name=project_name, description=description.strip() or None)
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
    provider_status = _provider_status_payload(
        repo.get_latest_provider_snapshot(),
        settings=get_workbench_settings(request),
    )
    model = dashboard_model(
        project,
        repo.list_project_findings(project.id),
        repo.list_analysis_runs(project.id),
        provider_status=provider_status,
        attack_contexts=repo.list_project_attack_contexts(project.id),
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
    attack_source: Annotated[str, Form()] = "none",
    attack_mapping_file: Annotated[str, Form()] = "",
    attack_technique_metadata_file: Annotated[str, Form()] = "",
    asset_context_file: Annotated[UploadFile | None, File()] = None,
    vex_file: Annotated[UploadFile | None, File()] = None,
    waiver_file: Annotated[UploadFile | None, File()] = None,
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    upload_path: Path | None = None
    asset_context_path: Path | None = None
    vex_path: Path | None = None
    waiver_path: Path | None = None
    try:
        upload_path = await _save_upload(file, input_format=input_format, settings=settings)
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
        snapshot_path = _resolve_provider_snapshot_path(
            provider_snapshot_file,
            settings=settings,
        )
        attack_mapping_path = _resolve_attack_artifact_path(attack_mapping_file, settings=settings)
        attack_metadata_path = _resolve_attack_artifact_path(
            attack_technique_metadata_file,
            settings=settings,
        )
        result = run_workbench_import(
            session=session,
            settings=settings,
            project_id=project_id,
            input_path=upload_path,
            original_filename=file.filename or upload_path.name,
            input_format=input_format,
            provider_snapshot_file=snapshot_path,
            locked_provider_data=locked_provider_data,
            attack_source=attack_source,
            attack_mapping_file=attack_mapping_path,
            attack_technique_metadata_file=attack_metadata_path,
            asset_context_file=asset_context_path,
            vex_file=vex_path,
            waiver_file=waiver_path,
        )
    except WorkbenchAnalysisError as exc:
        _cleanup_saved_uploads(upload_path, asset_context_path, vex_path, waiver_path)
        session.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except HTTPException:
        _cleanup_saved_uploads(upload_path, asset_context_path, vex_path, waiver_path)
        raise
    except Exception:
        _cleanup_saved_uploads(upload_path, asset_context_path, vex_path, waiver_path)
        raise
    session.commit()
    return RedirectResponse(f"/analysis-runs/{result.run.id}/reports", status_code=303)


@web_router.get("/projects/{project_id}/findings", response_class=HTMLResponse)
def findings(
    request: Request,
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    priority: str | None = None,
    status: str | None = None,
    q: str | None = None,
    kev: str | None = None,
    owner: str | None = None,
    service: str | None = None,
    min_epss: float | None = Query(default=None, ge=0, le=1),
    min_cvss: float | None = Query(default=None, ge=0, le=10),
    sort: str = "operational",
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> HTMLResponse:
    repo = WorkbenchRepository(session)
    project = repo.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    kev_filter = _optional_bool_filter(kev)
    filtered = _filter_findings(
        repo.list_project_findings(project.id),
        priority=priority or None,
        status=status or None,
        q=q or None,
        kev=kev_filter,
        owner=owner or None,
        service=service or None,
        min_epss=min_epss,
        min_cvss=min_cvss,
    )
    sorted_findings = _sort_findings(filtered, sort=sort)
    paged = sorted_findings[offset : offset + limit]
    return templates.TemplateResponse(
        request,
        "findings/index.html",
        findings_model(
            project,
            paged,
            filters={
                "priority": priority or "",
                "status": status or "",
                "q": q or "",
                "kev": kev_filter,
                "owner": owner or "",
                "service": service or "",
                "min_epss": min_epss,
                "min_cvss": min_cvss,
                "sort": sort,
                "limit": limit,
                "offset": offset,
            },
            total=len(sorted_findings),
        ),
    )


@web_router.get("/projects/{project_id}/governance", response_class=HTMLResponse)
def governance(
    request: Request,
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> HTMLResponse:
    repo = WorkbenchRepository(session)
    project = repo.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    summary = build_governance_summary(repo.list_project_findings(project.id), limit=12)
    return templates.TemplateResponse(
        request,
        "governance/index.html",
        {"project": project, "summary": summary},
    )


@web_router.get("/findings/{finding_id}", response_class=HTMLResponse)
def finding_detail(
    request: Request,
    finding_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> HTMLResponse:
    repo = WorkbenchRepository(session)
    finding = repo.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    attack_contexts = repo.list_finding_attack_contexts(finding.id)
    return templates.TemplateResponse(
        request,
        "findings/detail.html",
        {"finding": finding, "attack_context": attack_contexts[0] if attack_contexts else None},
    )


@web_router.get("/projects/{project_id}/settings", response_class=HTMLResponse)
def project_settings(
    request: Request,
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> HTMLResponse:
    repo = WorkbenchRepository(session)
    project = repo.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    provider_status = _provider_status_payload(
        repo.get_latest_provider_snapshot(), settings=settings
    )
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "project": project,
            "settings": settings,
            "database_url_display": _redacted_database_url(settings.database_url),
            "provider_status": provider_status,
            "nvd_api_key_display": _redacted_env_value(settings.nvd_api_key_env),
        },
    )


@web_router.get("/projects/{project_id}/vulnerabilities", response_class=HTMLResponse)
def vulnerability_lookup(
    request: Request,
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    q: str = "",
) -> HTMLResponse:
    repo = WorkbenchRepository(session)
    project = repo.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    normalized_q = q.strip().upper()
    vulnerability = repo.get_vulnerability_by_cve(normalized_q) if normalized_q else None
    findings = repo.list_findings_for_cve(project.id, normalized_q) if vulnerability else []
    return templates.TemplateResponse(
        request,
        "vulnerabilities/index.html",
        {
            "project": project,
            "query": q,
            "vulnerability": vulnerability,
            "findings": findings,
            "looked_up": bool(normalized_q),
        },
    )


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


@web_router.post("/web/analysis-runs/{run_id}/reports", response_class=HTMLResponse)
def create_report_form(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    report_format: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    safe_run_id = _safe_uuid_path_value(run_id)
    if report_format not in {"json", "markdown", "html", "csv"}:
        raise HTTPException(status_code=422, detail="Unsupported report format.")
    try:
        create_run_report(
            session=session,
            settings=settings,
            analysis_run_id=safe_run_id,
            report_format=cast(ReportFormat, report_format),
        )
    except WorkbenchReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    session.commit()
    return RedirectResponse(f"/analysis-runs/{safe_run_id}/reports", status_code=303)


@web_router.get("/evidence-bundles/{bundle_id}/verify", response_class=HTMLResponse)
def verify_evidence_page(
    request: Request,
    bundle_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> HTMLResponse:
    try:
        result = verify_run_evidence_bundle(
            session=session,
            settings=settings,
            bundle_id=_safe_uuid_path_value(bundle_id),
        )
    except WorkbenchReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return templates.TemplateResponse(request, "evidence/verify.html", result)


@web_router.post("/web/analysis-runs/{run_id}/evidence-bundle", response_class=HTMLResponse)
def create_evidence_form(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    safe_run_id = _safe_uuid_path_value(run_id)
    try:
        create_run_evidence_bundle(session=session, settings=settings, analysis_run_id=safe_run_id)
    except WorkbenchReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    session.commit()
    return RedirectResponse(f"/analysis-runs/{safe_run_id}/reports", status_code=303)


def _check_csrf(submitted: str, settings: WorkbenchSettings) -> None:
    if not secrets.compare_digest(submitted, settings.csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token.")


def _optional_bool_filter(value: str | None) -> bool | None:
    if value is None or value == "":
        return None
    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise HTTPException(status_code=422, detail="Invalid boolean filter.")


def _redacted_database_url(database_url: str) -> str:
    try:
        return make_url(database_url).render_as_string(hide_password=True)
    except Exception:
        return "<set>"


def _safe_uuid_path_value(value: str) -> str:
    try:
        return UUID(value).hex
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Analysis run not found.") from exc


def _redacted_env_value(name: str) -> str:
    import os

    if os.getenv(name):
        return "<set>"
    return "<not set>"
