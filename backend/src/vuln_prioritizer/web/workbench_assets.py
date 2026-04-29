"""Asset context Workbench web routes."""

from __future__ import annotations

# ruff: noqa: F403, F405, I001

from fastapi import APIRouter

from vuln_prioritizer.services.workbench_assets import (
    asset_rescore_needed,
    asset_snapshot,
    changed_asset_fields,
    filter_assets_by_context,
    import_asset_context_csv,
    mark_asset_findings_rescore_needed,
    recalculate_asset_findings,
)
from vuln_prioritizer.web.workbench_common import *

router = APIRouter()


@router.get("/projects/{project_id}/assets", response_class=HTMLResponse)
def assets_page(
    request: Request,
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    owner: str = "",
    service: str = "",
) -> HTMLResponse:
    repo = WorkbenchRepository(session)
    project = repo.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    findings = repo.list_project_findings(project.id)
    all_assets = repo.list_project_assets(project.id)
    assets = filter_assets_by_context(all_assets, owner=owner, service=service)
    finding_counts: dict[str, int] = {}
    for finding in findings:
        if finding.asset_id:
            finding_counts[finding.asset_id] = finding_counts.get(finding.asset_id, 0) + 1
    asset_summary = {
        "total": len(all_assets),
        "filtered": len(assets),
        "owned": sum(1 for asset in all_assets if asset.owner),
        "services": len({asset.business_service for asset in all_assets if asset.business_service}),
        "internet_facing": sum(
            1
            for asset in all_assets
            if str(asset.exposure or "").strip().lower()
            in {"internet-facing", "public", "external"}
        ),
        "critical": sum(
            1 for asset in all_assets if str(asset.criticality or "").strip().lower() == "critical"
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
                "asset_rescore_status": {asset.id: asset_rescore_needed(asset) for asset in assets},
                "asset_filters": {"owner": owner, "service": service},
                "csrf_token": settings.csrf_token,
            },
        ),
    )


@router.post("/web/assets/{asset_row_id}", response_class=HTMLResponse)
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
    previous = asset_snapshot(asset)
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
    changed_fields = changed_asset_fields(previous, asset_snapshot(updated))
    marked_findings = mark_asset_findings_rescore_needed(
        updated,
        changed_fields=changed_fields,
    )
    repo.create_audit_event(
        project_id=updated.project_id,
        event_type="asset.updated",
        target_type="asset",
        target_id=updated.id,
        actor=updated.owner,
        message=f"Asset {updated.asset_id!r} was updated from assets UI.",
        metadata_json={
            "previous": previous,
            "current": asset_snapshot(updated),
            "changed_fields": changed_fields,
            "rescore_needed_findings": marked_findings,
        },
    )
    session.commit()
    return RedirectResponse(_project_path(asset.project_id, "assets"), status_code=303)


@router.post("/web/projects/{project_id}/assets/import", response_class=HTMLResponse)
async def import_asset_context_form(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    asset_context_file: Annotated[UploadFile | None, File()] = None,
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    repo = WorkbenchRepository(session)
    project = repo.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    asset_context_path = await _save_optional_context_upload(
        asset_context_file,
        kind="asset-context",
        settings=settings,
    )
    if asset_context_path is None:
        raise HTTPException(status_code=422, detail="Asset context CSV file is required.")
    try:
        result = import_asset_context_csv(
            repo,
            project_id=project.id,
            asset_context_path=asset_context_path,
        )
    except ValueError as exc:
        _cleanup_saved_uploads(asset_context_path)
        raise HTTPException(
            status_code=422,
            detail=f"Asset context CSV import failed: {exc}",
        ) from exc
    repo.create_audit_event(
        project_id=project.id,
        event_type="asset_context.imported",
        target_type="project",
        target_id=project.id,
        message="Asset context CSV was imported from the assets UI.",
        metadata_json=result.as_payload(project_id=project.id),
    )
    session.commit()
    return RedirectResponse(_project_path(project.id, "assets"), status_code=303)


@router.post("/web/assets/{asset_row_id}/rescore", response_class=HTMLResponse)
def recalculate_asset_form(
    asset_row_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _check_csrf(csrf_token, settings)
    repo = WorkbenchRepository(session)
    asset = repo.get_asset(asset_row_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    result = recalculate_asset_findings(asset)
    repo.create_audit_event(
        project_id=asset.project_id,
        event_type="asset.recalculated",
        target_type="asset",
        target_id=asset.id,
        actor=asset.owner,
        message=f"Asset {asset.asset_id!r} linked findings were recalculated from assets UI.",
        metadata_json=result.as_payload(asset=asset),
    )
    session.commit()
    return RedirectResponse(_project_path(asset.project_id, "assets"), status_code=303)
