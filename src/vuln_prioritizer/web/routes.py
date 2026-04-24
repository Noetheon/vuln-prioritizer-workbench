"""Server-rendered Workbench routes."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Annotated, cast
from urllib.parse import quote
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from vuln_prioritizer.api.deps import get_db_session, get_workbench_settings
from vuln_prioritizer.api.routes import (
    _cleanup_saved_uploads,
    _count_matching_waiver_findings,
    _coverage_gap_payload,
    _create_provider_update_job_record,
    _detection_control_payload,
    _filter_findings,
    _parse_detection_control_rows,
    _provider_status_payload,
    _provider_update_job_payload,
    _read_bounded_upload,
    _resolve_attack_artifact_path,
    _resolve_provider_snapshot_path,
    _save_optional_context_upload,
    _save_upload,
    _sort_findings,
    _sync_project_waivers,
    _technique_metadata_from_contexts,
    _validated_waiver_values,
    _waiver_payload,
)
from vuln_prioritizer.api.schemas import ProviderSourceName, ProviderUpdateJobRequest, WaiverRequest
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


@web_router.get("/projects/{project_id}/assets", response_class=HTMLResponse)
def assets_page(
    request: Request,
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> HTMLResponse:
    repo = WorkbenchRepository(session)
    project = repo.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    findings = repo.list_project_findings(project.id)
    finding_counts: dict[str, int] = {}
    for finding in findings:
        if finding.asset_id:
            finding_counts[finding.asset_id] = finding_counts.get(finding.asset_id, 0) + 1
    return templates.TemplateResponse(
        request,
        "assets/index.html",
        {
            "project": project,
            "assets": repo.list_project_assets(project.id),
            "finding_counts": finding_counts,
            "csrf_token": settings.csrf_token,
        },
    )


@web_router.post("/web/assets/{asset_row_id}", response_class=HTMLResponse)
def update_asset_form(
    asset_row_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    asset_id: Annotated[str, Form()],
    target_ref: Annotated[str, Form()] = "",
    owner: Annotated[str, Form()] = "",
    business_service: Annotated[str, Form()] = "",
    environment: Annotated[str, Form()] = "",
    exposure: Annotated[str, Form()] = "",
    criticality: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    repo = WorkbenchRepository(session)
    asset = repo.get_asset(asset_row_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    repo.update_asset(
        asset,
        asset_id=asset_id.strip() or asset.asset_id,
        target_ref=target_ref.strip() or None,
        owner=owner.strip() or None,
        business_service=business_service.strip() or None,
        environment=environment.strip() or None,
        exposure=exposure.strip() or None,
        criticality=criticality.strip() or None,
    )
    session.commit()
    return RedirectResponse(f"/projects/{asset.project_id}/assets", status_code=303)


@web_router.get("/projects/{project_id}/waivers", response_class=HTMLResponse)
def waivers_page(
    request: Request,
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> HTMLResponse:
    repo = WorkbenchRepository(session)
    project = repo.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    findings = repo.list_project_findings(project.id)
    waivers = [
        _waiver_payload(
            waiver,
            matched_findings=_count_matching_waiver_findings(waiver, findings),
        )
        for waiver in repo.list_project_waivers(project.id)
    ]
    return templates.TemplateResponse(
        request,
        "waivers/index.html",
        {
            "project": project,
            "waivers": waivers,
            "findings": findings,
            "csrf_token": settings.csrf_token,
        },
    )


@web_router.post("/web/projects/{project_id}/waivers", response_class=HTMLResponse)
def create_waiver_form(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    owner: Annotated[str, Form()],
    reason: Annotated[str, Form()],
    expires_on: Annotated[str, Form()],
    cve_id: Annotated[str, Form()] = "",
    finding_id: Annotated[str, Form()] = "",
    asset_id: Annotated[str, Form()] = "",
    component_name: Annotated[str, Form()] = "",
    component_version: Annotated[str, Form()] = "",
    service: Annotated[str, Form()] = "",
    review_on: Annotated[str, Form()] = "",
    approval_ref: Annotated[str, Form()] = "",
    ticket_url: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    payload = WaiverRequest(
        owner=owner,
        reason=reason,
        expires_on=expires_on,
        cve_id=cve_id or None,
        finding_id=finding_id or None,
        asset_id=asset_id or None,
        component_name=component_name or None,
        component_version=component_version or None,
        service=service or None,
        review_on=review_on or None,
        approval_ref=approval_ref or None,
        ticket_url=ticket_url or None,
    )
    repo.create_waiver(
        project_id=project_id,
        **_validated_waiver_values(payload, project_id=project_id, repo=repo),
    )
    _sync_project_waivers(repo, project_id)
    session.commit()
    return RedirectResponse(_project_path(project_id, "waivers"), status_code=303)


@web_router.post("/web/waivers/{waiver_id}", response_class=HTMLResponse)
def update_waiver_form(
    waiver_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    owner: Annotated[str, Form()],
    reason: Annotated[str, Form()],
    expires_on: Annotated[str, Form()],
    cve_id: Annotated[str, Form()] = "",
    finding_id: Annotated[str, Form()] = "",
    asset_id: Annotated[str, Form()] = "",
    component_name: Annotated[str, Form()] = "",
    component_version: Annotated[str, Form()] = "",
    service: Annotated[str, Form()] = "",
    review_on: Annotated[str, Form()] = "",
    approval_ref: Annotated[str, Form()] = "",
    ticket_url: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    repo = WorkbenchRepository(session)
    waiver = repo.get_waiver(waiver_id)
    if waiver is None:
        raise HTTPException(status_code=404, detail="Waiver not found.")
    payload = WaiverRequest(
        owner=owner,
        reason=reason,
        expires_on=expires_on,
        cve_id=cve_id or None,
        finding_id=finding_id or None,
        asset_id=asset_id or None,
        component_name=component_name or None,
        component_version=component_version or None,
        service=service or None,
        review_on=review_on or None,
        approval_ref=approval_ref or None,
        ticket_url=ticket_url or None,
    )
    repo.update_waiver(
        waiver,
        **_validated_waiver_values(payload, project_id=waiver.project_id, repo=repo),
    )
    _sync_project_waivers(repo, waiver.project_id)
    session.commit()
    return RedirectResponse(_project_path(waiver.project_id, "waivers"), status_code=303)


@web_router.post("/web/waivers/{waiver_id}/delete", response_class=HTMLResponse)
def delete_waiver_form(
    waiver_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    repo = WorkbenchRepository(session)
    waiver = repo.get_waiver(waiver_id)
    if waiver is None:
        raise HTTPException(status_code=404, detail="Waiver not found.")
    project_id = waiver.project_id
    repo.delete_waiver(waiver)
    _sync_project_waivers(repo, project_id)
    session.commit()
    return RedirectResponse(_project_path(project_id, "waivers"), status_code=303)


@web_router.get("/projects/{project_id}/coverage", response_class=HTMLResponse)
def coverage_page(
    request: Request,
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> HTMLResponse:
    repo = WorkbenchRepository(session)
    project = repo.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    gaps = _coverage_gap_payload(
        repo.list_project_attack_contexts(project.id),
        repo.list_project_detection_controls(project.id),
        repo.list_project_findings(project.id),
    )
    return templates.TemplateResponse(
        request,
        "coverage/index.html",
        {
            "project": project,
            "controls": [
                _detection_control_payload(control)
                for control in repo.list_project_detection_controls(project.id)
            ],
            "gaps": gaps,
            "csrf_token": settings.csrf_token,
        },
    )


@web_router.post("/web/projects/{project_id}/coverage/import", response_class=HTMLResponse)
async def import_detection_controls_form(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    file: UploadFile,
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    rows = _parse_detection_control_rows(
        file.filename or "controls",
        await _read_bounded_upload(file, settings=settings),
    )
    for row in rows:
        repo.upsert_detection_control(project_id=project_id, **row)
    session.commit()
    return RedirectResponse(_project_path(project_id, "coverage"), status_code=303)


@web_router.get("/findings/{finding_id}", response_class=HTMLResponse)
def finding_detail(
    request: Request,
    finding_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> HTMLResponse:
    repo = WorkbenchRepository(session)
    finding = repo.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    project = repo.get_project(finding.project_id)
    attack_contexts = repo.list_finding_attack_contexts(finding.id)
    return templates.TemplateResponse(
        request,
        "findings/detail.html",
        {
            "project": project,
            "finding": finding,
            "attack_context": attack_contexts[0] if attack_contexts else None,
            "csrf_token": settings.csrf_token,
        },
    )


@web_router.get(
    "/projects/{project_id}/attack/techniques/{technique_id}", response_class=HTMLResponse
)
def technique_detail_page(
    request: Request,
    project_id: str,
    technique_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> HTMLResponse:
    repo = WorkbenchRepository(session)
    project = repo.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    contexts = repo.list_project_attack_contexts(project.id)
    controls = repo.list_detection_controls_for_technique(project.id, technique_id)
    findings = [
        finding
        for finding in repo.list_project_findings(project.id)
        if any(
            str(technique.get("attack_object_id") or technique.get("technique_id") or "")
            == technique_id
            for context in finding.attack_contexts
            for technique in (context.techniques_json or [])
            if isinstance(technique, dict)
        )
    ]
    coverage_items = [
        item
        for item in _coverage_gap_payload(contexts, controls, findings)["items"]
        if item["technique_id"] == technique_id
    ]
    metadata = _technique_metadata_from_contexts(contexts, technique_id)
    technique_name = metadata.get("name") or (coverage_items[0]["name"] if coverage_items else None)
    return templates.TemplateResponse(
        request,
        "coverage/technique.html",
        {
            "project": project,
            "technique_id": technique_id,
            "technique_name": technique_name,
            "metadata": metadata,
            "findings": findings,
            "controls": [_detection_control_payload(control) for control in controls],
            "coverage": coverage_items[0] if coverage_items else None,
        },
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
            "provider_jobs": [
                _provider_update_job_payload(job) for job in repo.list_provider_update_jobs()
            ],
            "nvd_api_key_display": _redacted_env_value(settings.nvd_api_key_env),
            "csrf_token": settings.csrf_token,
        },
    )


@web_router.post("/web/projects/{project_id}/providers/update-jobs", response_class=HTMLResponse)
def create_provider_update_job_form(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    sources: Annotated[list[str] | None, Form()] = None,
    max_cves: Annotated[str, Form()] = "",
    cache_only: Annotated[bool, Form()] = True,
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    selected_sources: list[ProviderSourceName] = [
        cast(ProviderSourceName, source)
        for source in (sources or [])
        if source in {"nvd", "epss", "kev"}
    ]
    try:
        max_cves_value = int(max_cves) if max_cves.strip() else None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="max_cves must be a number.") from exc
    payload = ProviderUpdateJobRequest(
        sources=selected_sources or ["nvd", "epss", "kev"],
        max_cves=max_cves_value,
        cache_only=cache_only,
    )
    _create_provider_update_job_record(repo=repo, settings=settings, payload=payload)
    session.commit()
    return RedirectResponse(_project_path(project_id, "settings"), status_code=303)


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
    if report_format not in {"json", "markdown", "html", "csv", "sarif"}:
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


def _project_path(project_id: str, child: str) -> str:
    return f"/projects/{quote(project_id, safe='')}/{child}"


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
