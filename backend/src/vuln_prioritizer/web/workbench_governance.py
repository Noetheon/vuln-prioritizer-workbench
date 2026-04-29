"""Workbench web routes split by domain."""

from __future__ import annotations

# ruff: noqa: F403, F405
from fastapi import APIRouter

from vuln_prioritizer.web.workbench_common import *

router = APIRouter()


@router.get("/projects/{project_id}/governance", response_class=HTMLResponse)
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


@router.get("/projects/{project_id}/assets", response_class=HTMLResponse)
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


@router.get("/projects/{project_id}/waivers", response_class=HTMLResponse)
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


@router.post("/web/projects/{project_id}/waivers", response_class=HTMLResponse)
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


@router.post("/web/waivers/{waiver_id}", response_class=HTMLResponse)
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


@router.post("/web/waivers/{waiver_id}/delete", response_class=HTMLResponse)
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


@router.get("/projects/{project_id}/coverage", response_class=HTMLResponse)
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


@router.post("/web/projects/{project_id}/coverage/import", response_class=HTMLResponse)
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


@router.post("/web/findings/{finding_id}/attack-review", response_class=HTMLResponse)
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


@router.post("/web/detection-controls/{control_id}", response_class=HTMLResponse)
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


@router.post("/web/detection-controls/{control_id}/attachments", response_class=HTMLResponse)
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


@router.get("/findings/{finding_id}", response_class=HTMLResponse)
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


@router.post("/web/findings/{finding_id}/status", response_class=HTMLResponse)
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


@router.get("/projects/{project_id}/attack/techniques/{technique_id}", response_class=HTMLResponse)
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
