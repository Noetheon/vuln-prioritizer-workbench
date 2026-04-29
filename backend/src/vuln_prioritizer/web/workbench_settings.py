"""Workbench web routes split by domain."""

from __future__ import annotations

# ruff: noqa: F403, F405
from fastapi import APIRouter

from vuln_prioritizer.web.workbench_common import *

router = APIRouter()


@router.get("/projects/{project_id}/settings", response_class=HTMLResponse)
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
    provider_jobs = repo.list_provider_update_jobs()
    provider_status = _provider_status_payload(
        repo.get_latest_provider_snapshot(),
        settings=settings,
        latest_update_job=provider_jobs[0] if provider_jobs else None,
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
                "provider_jobs": [_provider_update_job_payload(job) for job in provider_jobs],
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


@router.post("/web/projects/{project_id}/api-tokens", response_class=HTMLResponse)
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
    provider_jobs = repo.list_provider_update_jobs()
    provider_status = _provider_status_payload(
        repo.get_latest_provider_snapshot(),
        settings=settings,
        latest_update_job=provider_jobs[0] if provider_jobs else None,
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
                "provider_jobs": [_provider_update_job_payload(job) for job in provider_jobs],
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


@router.post("/web/projects/{project_id}/api-tokens/{token_id}/revoke", response_class=HTMLResponse)
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


@router.post("/web/projects/{project_id}/settings/config", response_class=HTMLResponse)
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


@router.post(
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


@router.get("/projects/{project_id}/settings/config/{snapshot_id}/export")
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


@router.post("/web/projects/{project_id}/artifacts/retention", response_class=HTMLResponse)
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


@router.post("/web/projects/{project_id}/artifacts/cleanup", response_class=HTMLResponse)
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


@router.post("/web/projects/{project_id}/providers/update-jobs", response_class=HTMLResponse)
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
