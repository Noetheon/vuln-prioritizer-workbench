"""Server-rendered Workbench routes."""

from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path
from typing import Annotated, Any, cast
from uuid import UUID

import yaml
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from vuln_prioritizer.api.deps import get_db_session, get_workbench_settings
from vuln_prioritizer.api.schemas import ProviderSourceName, ProviderUpdateJobRequest, WaiverRequest
from vuln_prioritizer.api.security import api_token_digest
from vuln_prioritizer.api.workbench_payloads import (
    _attack_review_queue_item_payload,
    _detection_control_attachment_payload,
)
from vuln_prioritizer.api.workbench_support import (
    _cleanup_saved_uploads,
    _count_matching_waiver_findings,
    _coverage_gap_payload,
    _create_provider_update_job_record,
    _detection_control_payload,
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
from vuln_prioritizer.attack_sources import ATTACK_SOURCE_NONE, WORKBENCH_ALLOWED_MAPPING_SOURCES
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.reporting_executive import render_executive_report_html
from vuln_prioritizer.runtime_config import RuntimeConfigDocument
from vuln_prioritizer.services.workbench_analysis import (
    WorkbenchAnalysisError,
    run_workbench_import,
)
from vuln_prioritizer.services.workbench_artifacts import cleanup_project_artifacts
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
from vuln_prioritizer.web.view_models import dashboard_model, findings_model, reports_model
from vuln_prioritizer.workbench_config import WorkbenchSettings

TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
web_router = APIRouter()
WEB_API_TOKEN_PREFIX = "vpr_"
ATTACK_REVIEW_SOURCES = set(WORKBENCH_ALLOWED_MAPPING_SOURCES) | {ATTACK_SOURCE_NONE}
ATTACK_REVIEW_STATUSES = {
    "unreviewed",
    "needs_review",
    "source_reviewed",
    "reviewed",
    "rejected",
    "not_applicable",
}

_PROJECT_CHILD_ROUTES = frozenset(
    {
        "assets",
        "coverage",
        "dashboard",
        "findings",
        "governance",
        "imports/new",
        "settings",
        "vulnerabilities",
        "waivers",
    }
)


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
    repo.create_audit_event(
        project_id=project.id,
        event_type="project.created",
        target_type="project",
        target_id=project.id,
        message=f"Project {project_name!r} was created from web form.",
    )
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
    repo = WorkbenchRepository(session)
    project = repo.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return templates.TemplateResponse(
        request,
        "imports/new.html",
        _project_nav_context(
            repo, project, {"project": project, "csrf_token": settings.csrf_token}
        ),
    )


@web_router.post("/web/projects/{project_id}/imports", response_class=HTMLResponse)
async def create_import_form(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    input_format: Annotated[str, Form()],
    file: Annotated[UploadFile | None, File()] = None,
    files: Annotated[list[UploadFile] | None, File()] = None,
    provider_snapshot_file: Annotated[str, Form()] = "",
    locked_provider_data: Annotated[bool, Form()] = False,
    attack_source: Annotated[str, Form()] = "none",
    attack_mapping_file: Annotated[str, Form()] = "",
    attack_technique_metadata_file: Annotated[str, Form()] = "",
    asset_context_file: Annotated[UploadFile | None, File()] = None,
    vex_file: Annotated[UploadFile | None, File()] = None,
    waiver_file: Annotated[UploadFile | None, File()] = None,
    defensive_context_file: Annotated[UploadFile | None, File()] = None,
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    upload_paths: list[Path] = []
    asset_context_path: Path | None = None
    vex_path: Path | None = None
    waiver_path: Path | None = None
    defensive_context_path: Path | None = None
    try:
        selected_files = _selected_import_files(file=file, files=files)
        upload_paths = [
            await _save_upload(item, input_format=input_format, settings=settings)
            for item in selected_files
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
        snapshot_path = _resolve_provider_snapshot_path(
            provider_snapshot_file,
            settings=settings,
        )
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
                "input_format": input_format,
                "input_formats": [input_format] * len(upload_paths),
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
            operation=lambda _repo, _job: run_workbench_import(
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
                input_format=[input_format] * len(upload_paths)
                if len(upload_paths) > 1
                else input_format,
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
        message="Workbench import completed from web form.",
        metadata_json={
            "input_type": result.run.input_type,
            "input_count": len(upload_paths),
            "job_id": job.id,
        },
    )
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
    min_epss: str | None = None,
    min_cvss: str | None = None,
    sort: str = "operational",
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> HTMLResponse:
    repo = WorkbenchRepository(session)
    project = repo.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    kev_filter = _optional_bool_filter(kev)
    min_epss_filter = _optional_float_filter(min_epss, lower=0, upper=1, label="EPSS")
    min_cvss_filter = _optional_float_filter(min_cvss, lower=0, upper=10, label="CVSS")
    try:
        paged, total_count = repo.list_project_findings_page(
            project.id,
            priority=priority or None,
            status=status or None,
            q=q or None,
            kev=kev_filter,
            owner=owner or None,
            service=service or None,
            min_epss=min_epss_filter,
            min_cvss=min_cvss_filter,
            sort=sort,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return templates.TemplateResponse(
        request,
        "findings/index.html",
        _project_nav_context(
            repo,
            project,
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
                    "min_epss": min_epss_filter,
                    "min_cvss": min_cvss_filter,
                    "sort": sort,
                    "limit": limit,
                    "offset": offset,
                },
                total=total_count,
            ),
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
        _project_nav_context(repo, project, {"project": project, "summary": summary}),
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
    assets = repo.list_project_assets(project.id)
    finding_counts: dict[str, int] = {}
    for finding in findings:
        if finding.asset_id:
            finding_counts[finding.asset_id] = finding_counts.get(finding.asset_id, 0) + 1
    asset_summary = {
        "total": len(assets),
        "owned": sum(1 for asset in assets if asset.owner),
        "services": len({asset.business_service for asset in assets if asset.business_service}),
        "internet_facing": sum(
            1
            for asset in assets
            if str(asset.exposure or "").strip().lower()
            in {"internet-facing", "public", "external"}
        ),
        "critical": sum(
            1 for asset in assets if str(asset.criticality or "").strip().lower() == "critical"
        ),
    }
    return templates.TemplateResponse(
        request,
        "assets/index.html",
        _project_nav_context(
            repo,
            project,
            {
                "project": project,
                "assets": assets,
                "asset_summary": asset_summary,
                "finding_counts": finding_counts,
                "csrf_token": settings.csrf_token,
            },
        ),
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
    previous = _asset_audit_snapshot(asset)
    updated = repo.update_asset(
        asset,
        asset_id=asset_id.strip() or asset.asset_id,
        target_ref=target_ref.strip() or None,
        owner=owner.strip() or None,
        business_service=business_service.strip() or None,
        environment=environment.strip() or None,
        exposure=exposure.strip() or None,
        criticality=criticality.strip() or None,
    )
    repo.create_audit_event(
        project_id=updated.project_id,
        event_type="asset.updated",
        target_type="asset",
        target_id=updated.id,
        actor=updated.owner,
        message=f"Asset {updated.asset_id!r} was updated from assets UI.",
        metadata_json={"previous": previous, "current": _asset_audit_snapshot(updated)},
    )
    session.commit()
    return RedirectResponse(_project_path(asset.project_id, "assets"), status_code=303)


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
    waiver_summary = {
        "total": len(waivers),
        "active": sum(1 for waiver in waivers if waiver["status"] == "active"),
        "review_due": sum(1 for waiver in waivers if waiver["status"] == "review_due"),
        "expired": sum(1 for waiver in waivers if waiver["status"] == "expired"),
        "matched_findings": sum(int(waiver["matched_findings"]) for waiver in waivers),
    }
    return templates.TemplateResponse(
        request,
        "waivers/index.html",
        _project_nav_context(
            repo,
            project,
            {
                "project": project,
                "waivers": waivers,
                "waiver_summary": waiver_summary,
                "findings": findings,
                "csrf_token": settings.csrf_token,
            },
        ),
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
    waiver = repo.create_waiver(
        project_id=project_id,
        **_validated_waiver_values(payload, project_id=project_id, repo=repo),
    )
    matched = _sync_project_waivers(repo, project_id)
    repo.create_audit_event(
        project_id=project_id,
        event_type="waiver.created",
        target_type="waiver",
        target_id=waiver.id,
        actor=waiver.owner,
        message="Waiver was created from web form.",
        metadata_json={"matched_findings": matched.get(waiver.id, 0)},
    )
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
    matched = _sync_project_waivers(repo, waiver.project_id)
    repo.create_audit_event(
        project_id=waiver.project_id,
        event_type="waiver.updated",
        target_type="waiver",
        target_id=waiver.id,
        actor=waiver.owner,
        message="Waiver was updated from web form.",
        metadata_json={"matched_findings": matched.get(waiver.id, 0)},
    )
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
    repo.create_audit_event(
        project_id=project_id,
        event_type="waiver.deleted",
        target_type="waiver",
        target_id=waiver_id,
        message="Waiver was deleted from web form.",
    )
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
    controls = repo.list_project_detection_controls(project.id)
    gaps = _coverage_gap_payload(
        repo.list_project_attack_contexts(project.id),
        controls,
        repo.list_project_findings(project.id),
    )
    coverage_summary = {
        "techniques": len(gaps["items"]),
        "controls": len(controls),
        "covered": gaps["summary"].get("covered", 0),
        "partial": gaps["summary"].get("partial", 0),
        "not_covered": gaps["summary"].get("not_covered", 0),
        "unknown": gaps["summary"].get("unknown", 0),
    }
    return templates.TemplateResponse(
        request,
        "coverage/index.html",
        _project_nav_context(
            repo,
            project,
            {
                "project": project,
                "controls": [_detection_control_payload(control) for control in controls],
                "coverage_summary": coverage_summary,
                "gaps": gaps,
                "review_queue": [
                    _attack_review_queue_item_payload(context)
                    for context in repo.list_project_attack_review_contexts(project.id, limit=25)
                ],
                "csrf_token": settings.csrf_token,
            },
        ),
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
        repo.upsert_detection_control(project_id=project_id, **row, history_actor="web-import")
    repo.create_audit_event(
        project_id=project_id,
        event_type="detection_control.imported",
        target_type="project",
        target_id=project_id,
        message="Detection controls were imported from web form.",
        metadata_json={"imported": len(rows)},
    )
    session.commit()
    return RedirectResponse(_project_path(project_id, "coverage"), status_code=303)


@web_router.post("/web/findings/{finding_id}/attack-review", response_class=HTMLResponse)
def update_attack_review_form(
    finding_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    review_status: Annotated[str, Form()],
    actor: Annotated[str, Form()] = "",
    reason: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    if review_status not in ATTACK_REVIEW_STATUSES:
        raise HTTPException(status_code=422, detail="Unsupported ATT&CK review status.")
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
    repo.update_finding_attack_review_status(finding.id, review_status=review_status)
    repo.create_audit_event(
        project_id=finding.project_id,
        event_type="attack_context.review_updated",
        target_type="finding",
        target_id=finding.id,
        actor=actor.strip() or None,
        message=f"ATT&CK review status updated to {review_status} from coverage UI.",
        metadata_json={"reason": reason.strip() or None, "sources": sorted(sources)},
    )
    session.commit()
    return RedirectResponse(_project_path(finding.project_id, "coverage"), status_code=303)


@web_router.post("/web/detection-controls/{control_id}", response_class=HTMLResponse)
def update_detection_control_form(
    control_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    coverage_level: Annotated[str, Form()],
    review_status: Annotated[str, Form()],
    owner: Annotated[str, Form()] = "",
    evidence_ref: Annotated[str, Form()] = "",
    evidence_refs: Annotated[str, Form()] = "",
    notes: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    repo = WorkbenchRepository(session)
    control = repo.get_detection_control(control_id)
    if control is None:
        raise HTTPException(status_code=404, detail="Detection control not found.")
    actor = owner.strip() or "web"
    repo.upsert_detection_control(
        project_id=control.project_id,
        control_id=control.control_id,
        name=control.name,
        technique_id=control.technique_id,
        technique_name=control.technique_name,
        source_type=control.source_type,
        coverage_level=coverage_level,
        environment=control.environment,
        owner=owner.strip() or None,
        evidence_ref=evidence_ref.strip() or None,
        evidence_refs_json=_csv_form_values(evidence_refs),
        review_status=review_status,
        notes=notes.strip() or None,
        last_verified_at=control.last_verified_at,
        history_actor=actor,
        history_reason="coverage review update",
    )
    repo.create_audit_event(
        project_id=control.project_id,
        event_type="detection_control.updated",
        target_type="detection_control",
        target_id=control.id,
        actor=actor,
        message=f"Detection control {control.name!r} was updated from coverage UI.",
    )
    session.commit()
    return RedirectResponse(
        f"/projects/{control.project_id}/attack/techniques/{control.technique_id}",
        status_code=303,
    )


@web_router.post("/web/detection-controls/{control_id}/attachments", response_class=HTMLResponse)
async def upload_detection_control_attachment_form(
    control_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    file: UploadFile,
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
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
        message=f"Evidence attachment {filename!r} was uploaded from coverage UI.",
    )
    session.commit()
    return RedirectResponse(
        f"/projects/{control.project_id}/attack/techniques/{control.technique_id}",
        status_code=303,
    )


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
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    attack_contexts = repo.list_finding_attack_contexts(finding.id)
    return templates.TemplateResponse(
        request,
        "findings/detail.html",
        _project_nav_context(
            repo,
            project,
            {
                "project": project,
                "finding": finding,
                "attack_context": attack_contexts[0] if attack_contexts else None,
                "csrf_token": settings.csrf_token,
            },
        ),
    )


@web_router.post("/web/findings/{finding_id}/status", response_class=HTMLResponse)
def update_finding_status_form(
    finding_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    status: Annotated[str, Form()],
    reason: Annotated[str, Form()] = "",
    actor: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    if status not in {"open", "in_review", "remediating", "fixed", "accepted", "suppressed"}:
        raise HTTPException(status_code=422, detail="Unsupported finding status.")
    repo = WorkbenchRepository(session)
    finding = repo.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    active_actor = actor.strip() or "web"
    history = repo.update_finding_status(
        finding,
        status=status,
        actor=active_actor,
        reason=reason.strip() or None,
    )
    repo.create_audit_event(
        project_id=finding.project_id,
        event_type="finding.status_changed",
        target_type="finding",
        target_id=finding.id,
        actor=active_actor,
        message=f"Finding {finding.cve_id} status changed to {status}.",
        metadata_json={
            "previous_status": history.previous_status,
            "new_status": history.new_status,
            "reason": history.reason,
        },
    )
    session.commit()
    return RedirectResponse(f"/findings/{finding.id}", status_code=303)


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
        _project_nav_context(
            repo,
            project,
            {
                "project": project,
                "technique_id": technique_id,
                "technique_name": technique_name,
                "metadata": metadata,
                "findings": findings,
                "controls": [
                    _detection_control_payload(control)
                    | {
                        "attachments": [
                            _detection_control_attachment_payload(item)
                            for item in control.attachments
                        ],
                        "history": control.history,
                    }
                    for control in controls
                ],
                "coverage": coverage_items[0] if coverage_items else None,
                "csrf_token": get_workbench_settings(request).csrf_token,
            },
        ),
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
    config_history = repo.list_project_config_snapshots(project.id, limit=20)
    latest_config = config_history[0] if config_history else None
    default_config_text = json.dumps(
        RuntimeConfigDocument().model_dump(),
        indent=2,
        sort_keys=True,
    )
    diff_target_id = request.query_params.get("diff_config")
    config_diff = None
    if diff_target_id:
        target = repo.get_project_config_snapshot(diff_target_id)
        if target is not None and target.project_id == project.id:
            base_id = request.query_params.get("base_config")
            base = repo.get_project_config_snapshot(base_id) if base_id else None
            if base is None or base.project_id != project.id:
                older = [
                    item
                    for item in config_history
                    if item.id != target.id and item.created_at <= target.created_at
                ]
                base = older[0] if older else None
            config_diff = _web_config_diff(base=base, target=target)
    return templates.TemplateResponse(
        request,
        "settings.html",
        _project_nav_context(
            repo,
            project,
            {
                "project": project,
                "settings": settings,
                "database_url_display": _redacted_database_url(settings.database_url),
                "provider_status": provider_status,
                "provider_jobs": [
                    _provider_update_job_payload(job) for job in repo.list_provider_update_jobs()
                ],
                "workbench_jobs": repo.list_workbench_jobs(project_id=project.id, limit=20),
                "api_tokens": repo.list_api_tokens(),
                "artifact_retention": repo.get_project_artifact_retention(project.id),
                "config_history": config_history,
                "latest_config": latest_config,
                "config_editor_text": json.dumps(
                    latest_config.config_json
                    if latest_config
                    else RuntimeConfigDocument().model_dump(),
                    indent=2,
                    sort_keys=True,
                ),
                "config_defaults_json": default_config_text,
                "config_diff": config_diff,
                "created_api_token": None,
                "nvd_api_key_display": _redacted_env_value(settings.nvd_api_key_env),
                "csrf_token": settings.csrf_token,
            },
        ),
    )


@web_router.post("/web/projects/{project_id}/api-tokens", response_class=HTMLResponse)
def create_api_token_form(
    request: Request,
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    name: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()] = "",
) -> HTMLResponse:
    _check_csrf(csrf_token, settings)
    repo = WorkbenchRepository(session)
    project = repo.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    token_name = name.strip()
    if not token_name:
        raise HTTPException(status_code=422, detail="Token name is required.")
    token_value = WEB_API_TOKEN_PREFIX + secrets.token_urlsafe(32)
    token = repo.create_api_token(name=token_name, token_hash=api_token_digest(token_value))
    repo.create_audit_event(
        event_type="api_token.created",
        target_type="api_token",
        target_id=token.id,
        actor=token.name,
        message=f"API token {token.name!r} was created from settings.",
    )
    session.commit()
    provider_status = _provider_status_payload(
        repo.get_latest_provider_snapshot(), settings=settings
    )
    config_history = repo.list_project_config_snapshots(project.id, limit=20)
    latest_config = config_history[0] if config_history else None
    return templates.TemplateResponse(
        request,
        "settings.html",
        _project_nav_context(
            repo,
            project,
            {
                "project": project,
                "settings": settings,
                "database_url_display": _redacted_database_url(settings.database_url),
                "provider_status": provider_status,
                "provider_jobs": [
                    _provider_update_job_payload(job) for job in repo.list_provider_update_jobs()
                ],
                "workbench_jobs": repo.list_workbench_jobs(project_id=project.id, limit=20),
                "api_tokens": repo.list_api_tokens(),
                "artifact_retention": repo.get_project_artifact_retention(project.id),
                "config_history": config_history,
                "latest_config": latest_config,
                "config_editor_text": json.dumps(
                    latest_config.config_json
                    if latest_config
                    else RuntimeConfigDocument().model_dump(),
                    indent=2,
                    sort_keys=True,
                ),
                "config_defaults_json": json.dumps(
                    RuntimeConfigDocument().model_dump(),
                    indent=2,
                    sort_keys=True,
                ),
                "config_diff": None,
                "created_api_token": token_value,
                "nvd_api_key_display": _redacted_env_value(settings.nvd_api_key_env),
                "csrf_token": settings.csrf_token,
            },
        ),
    )


@web_router.post(
    "/web/projects/{project_id}/api-tokens/{token_id}/revoke", response_class=HTMLResponse
)
def revoke_api_token_form(
    project_id: str,
    token_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    token = repo.get_api_token(token_id)
    if token is None:
        raise HTTPException(status_code=404, detail="API token not found.")
    repo.revoke_api_token(token)
    repo.create_audit_event(
        event_type="api_token.revoked",
        target_type="api_token",
        target_id=token.id,
        actor=token.name,
        message=f"API token {token.name!r} was revoked from settings.",
    )
    session.commit()
    return RedirectResponse(_project_path(project_id, "settings"), status_code=303)


@web_router.post("/web/projects/{project_id}/settings/config", response_class=HTMLResponse)
def save_project_config_form(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    config_text: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    document = _runtime_config_from_text(config_text)
    snapshot = repo.save_project_config_snapshot(
        project_id=project_id,
        source="web",
        config_json=document.model_dump(),
    )
    repo.create_audit_event(
        project_id=project_id,
        event_type="project_config.saved",
        target_type="project_config_snapshot",
        target_id=snapshot.id,
        message="Project config snapshot was saved from settings.",
    )
    session.commit()
    return RedirectResponse(_project_path(project_id, "settings"), status_code=303)


@web_router.post(
    "/web/projects/{project_id}/settings/config/{snapshot_id}/rollback",
    response_class=HTMLResponse,
)
def rollback_project_config_form(
    project_id: str,
    snapshot_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    repo = WorkbenchRepository(session)
    snapshot = repo.get_project_config_snapshot(snapshot_id)
    if snapshot is None or snapshot.project_id != project_id:
        raise HTTPException(status_code=404, detail="Project config snapshot not found.")
    rollback = repo.save_project_config_snapshot(
        project_id=project_id,
        source=f"rollback:{snapshot.id}",
        config_json=snapshot.config_json or {},
    )
    repo.create_audit_event(
        project_id=project_id,
        event_type="project_config.rolled_back",
        target_type="project_config_snapshot",
        target_id=rollback.id,
        message="Project config snapshot was rolled back from settings.",
        metadata_json={"rolled_back_to": snapshot.id},
    )
    session.commit()
    return RedirectResponse(_project_path(project_id, "settings"), status_code=303)


@web_router.get("/projects/{project_id}/settings/config/{snapshot_id}/export")
def export_project_config_form(
    project_id: str,
    snapshot_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> Response:
    repo = WorkbenchRepository(session)
    snapshot = repo.get_project_config_snapshot(snapshot_id)
    if snapshot is None or snapshot.project_id != project_id:
        raise HTTPException(status_code=404, detail="Project config snapshot not found.")
    return Response(
        json.dumps(snapshot.config_json or {}, indent=2, sort_keys=True),
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="vuln-prioritizer-config-{snapshot.id}.json"'
            )
        },
    )


@web_router.post("/web/projects/{project_id}/artifacts/retention", response_class=HTMLResponse)
def update_artifact_retention_form(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    report_retention_days: Annotated[str, Form()] = "",
    evidence_retention_days: Annotated[str, Form()] = "",
    max_disk_usage_mb: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    retention = repo.upsert_project_artifact_retention(
        project_id=project_id,
        report_retention_days=_optional_positive_int(
            report_retention_days,
            "report_retention_days",
        ),
        evidence_retention_days=_optional_positive_int(
            evidence_retention_days,
            "evidence_retention_days",
        ),
        max_disk_usage_mb=_optional_positive_int(max_disk_usage_mb, "max_disk_usage_mb"),
    )
    repo.create_audit_event(
        project_id=project_id,
        event_type="artifact_retention.updated",
        target_type="project",
        target_id=project_id,
        message="Artifact retention settings were updated from settings.",
        metadata_json={
            "report_retention_days": retention.report_retention_days,
            "evidence_retention_days": retention.evidence_retention_days,
            "max_disk_usage_mb": retention.max_disk_usage_mb,
        },
    )
    session.commit()
    return RedirectResponse(_project_path(project_id, "settings"), status_code=303)


@web_router.post("/web/projects/{project_id}/artifacts/cleanup", response_class=HTMLResponse)
def cleanup_artifacts_form(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    delete: Annotated[bool, Form()] = False,
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    result = cleanup_project_artifacts(
        session=session,
        settings=settings,
        project_id=project_id,
        dry_run=not delete,
    )
    repo.create_audit_event(
        project_id=project_id,
        event_type="artifact_cleanup.completed",
        target_type="project",
        target_id=project_id,
        message="Artifact cleanup completed from settings.",
        metadata_json=result.to_dict(),
    )
    session.commit()
    return RedirectResponse(_project_path(project_id, "settings"), status_code=303)


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
    durable_job, job = run_sync_workbench_job(
        session=session,
        kind="provider_update",
        project_id=project_id,
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
        message="Provider update job was created from settings.",
        metadata_json={"status": job.status, "sources": list(payload.sources)},
    )
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
    suggested_findings = _sort_findings(repo.list_project_findings(project.id), sort="operational")[
        :8
    ]
    return templates.TemplateResponse(
        request,
        "vulnerabilities/index.html",
        _project_nav_context(
            repo,
            project,
            {
                "project": project,
                "query": q,
                "vulnerability": vulnerability,
                "findings": findings,
                "suggested_findings": suggested_findings,
                "looked_up": bool(normalized_q),
            },
        ),
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


@web_router.get("/analysis-runs/{run_id}/executive-report", response_class=HTMLResponse)
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


@web_router.get("/evidence-bundles/{bundle_id}/verify", response_class=HTMLResponse)
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


def _check_csrf(submitted: str, settings: WorkbenchSettings) -> None:
    if not secrets.compare_digest(submitted, settings.csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token.")


def _project_path(project_id: str, child: str) -> str:
    if child not in _PROJECT_CHILD_ROUTES:
        raise HTTPException(status_code=404, detail="Project route not found.")
    return f"/projects/{_safe_project_path_value(project_id)}/{child}"


def _project_nav_context(
    repo: WorkbenchRepository,
    project: Any,
    context: dict[str, Any],
) -> dict[str, Any]:
    if "latest_run" not in context:
        runs = repo.list_analysis_runs(project.id)
        context["latest_run"] = runs[0] if runs else None
    return context


def _safe_project_path_value(value: str) -> str:
    try:
        return UUID(value).hex
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Project not found.") from exc


def _optional_bool_filter(value: str | None) -> bool | None:
    if value is None or value == "":
        return None
    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise HTTPException(status_code=422, detail="Invalid boolean filter.")


def _optional_float_filter(
    value: str | None,
    *,
    lower: float,
    upper: float,
    label: str,
) -> float | None:
    if value is None or value == "":
        return None
    try:
        parsed = float(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid {label} filter.") from exc
    if parsed < lower or parsed > upper:
        raise HTTPException(status_code=422, detail=f"Invalid {label} filter.")
    return parsed


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


def _runtime_config_from_text(config_text: str) -> RuntimeConfigDocument:
    try:
        raw = yaml.safe_load(config_text) if config_text.strip() else {}
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid config YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise HTTPException(status_code=422, detail="Project config must be a JSON/YAML object.")
    try:
        return RuntimeConfigDocument.model_validate(raw)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid project config: {exc}") from exc


def _optional_positive_int(value: str, label: str) -> int | None:
    if not value.strip():
        return None
    try:
        parsed = int(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"{label} must be a number.") from exc
    if parsed <= 0:
        raise HTTPException(status_code=422, detail=f"{label} must be positive.")
    return parsed


def _csv_form_values(value: str) -> list[str]:
    return list(dict.fromkeys(item.strip() for item in value.split(",") if item.strip()))


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


def _web_config_diff(*, base: Any | None, target: Any) -> dict[str, Any]:
    before = base.config_json if base is not None and isinstance(base.config_json, dict) else {}
    after = target.config_json if isinstance(target.config_json, dict) else {}
    changed: dict[str, dict[str, Any]] = {}
    _web_collect_config_diff(before=before, after=after, prefix="", changed=changed)
    return {
        "base": base,
        "target": target,
        "changed": changed,
    }


def _web_collect_config_diff(
    *,
    before: dict[str, Any],
    after: dict[str, Any],
    prefix: str,
    changed: dict[str, dict[str, Any]],
) -> None:
    for key in sorted(set(before) | set(after)):
        path = f"{prefix}.{key}" if prefix else key
        if key not in before:
            changed[path] = {"before": None, "after": after[key]}
        elif key not in after:
            changed[path] = {"before": before[key], "after": None}
        elif isinstance(before[key], dict) and isinstance(after[key], dict):
            _web_collect_config_diff(
                before=before[key],
                after=after[key],
                prefix=path,
                changed=changed,
            )
        elif before[key] != after[key]:
            changed[path] = {"before": before[key], "after": after[key]}


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
