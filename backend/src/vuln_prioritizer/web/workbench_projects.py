"""Workbench web routes split by domain."""

from __future__ import annotations

# ruff: noqa: F403, F405
from fastapi import APIRouter

from vuln_prioritizer.web.workbench_common import *

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def index(session: Annotated[Session, Depends(get_db_session)]) -> RedirectResponse:
    projects = WorkbenchRepository(session).list_projects()
    if not projects:
        return RedirectResponse("/projects/new", status_code=303)
    return RedirectResponse(f"/projects/{projects[-1].id}/dashboard", status_code=303)


@router.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    return Response(status_code=204)


@router.get("/projects/new", response_class=HTMLResponse)
def new_project(
    request: Request,
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "projects/new.html",
        {"csrf_token": settings.csrf_token},
    )


@router.post("/projects", response_class=HTMLResponse)
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


@router.get("/projects/{project_id}/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> HTMLResponse:
    repo = WorkbenchRepository(session)
    project = repo.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    provider_jobs = repo.list_provider_update_jobs()
    provider_status = _provider_status_payload(
        repo.get_latest_provider_snapshot(),
        settings=get_workbench_settings(request),
        latest_update_job=provider_jobs[0] if provider_jobs else None,
    )
    model = dashboard_model(
        project,
        repo.list_project_findings(project.id),
        repo.list_analysis_runs(project.id),
        provider_status=provider_status,
        attack_contexts=repo.list_project_attack_contexts(project.id),
    )
    return templates.TemplateResponse(request, "dashboard.html", model)


@router.get("/projects/{project_id}/imports/new", response_class=HTMLResponse)
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


@router.post("/web/projects/{project_id}/imports", response_class=HTMLResponse)
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


@router.get("/projects/{project_id}/findings", response_class=HTMLResponse)
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


@router.get("/projects/{project_id}/vulnerabilities", response_class=HTMLResponse)
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
