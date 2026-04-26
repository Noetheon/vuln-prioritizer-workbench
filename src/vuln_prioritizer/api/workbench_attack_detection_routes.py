"""ATT&CK, detection, and governance API routes."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from vuln_prioritizer.api.deps import get_db_session, get_workbench_settings
from vuln_prioritizer.api.schemas import (
    AttackReviewQueueResponse,
    AttackReviewUpdateRequest,
    CoverageGapResponse,
    DetectionControlAttachmentResponse,
    DetectionControlHistoryResponse,
    DetectionControlImportResponse,
    DetectionControlPatchRequest,
    DetectionControlRequest,
    DetectionControlResponse,
    FindingAttackContextResponse,
    GovernanceRollupsResponse,
    TechniqueDetailResponse,
    TopTechniquesResponse,
)
from vuln_prioritizer.api.workbench_detection import (
    WEAK_DETECTION_COVERAGE_LEVELS,
    _coverage_gap_payload,
    _coverage_gap_score,
    _detection_control_payload,
    _detection_control_values,
    _parse_detection_control_rows,
    _technique_id_from_dict,
    _technique_metadata_from_contexts,
)
from vuln_prioritizer.api.workbench_payloads import (
    _attack_context_payload,
    _attack_review_queue_item_payload,
    _detection_control_attachment_payload,
    _detection_control_history_payload,
    _finding_payload,
    _governance_payload,
)
from vuln_prioritizer.api.workbench_route_support import (
    _delete_upload_artifact,
    _patched_detection_control_values,
    _resolve_upload_artifact,
    _validate_detection_attachment_filename,
)
from vuln_prioritizer.api.workbench_uploads import (
    _artifact_response,
    _read_bounded_upload,
)
from vuln_prioritizer.attack_sources import ATTACK_SOURCE_NONE, WORKBENCH_ALLOWED_MAPPING_SOURCES
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.services.workbench_attack import (
    navigator_layer_from_contexts,
    top_technique_rows,
)
from vuln_prioritizer.services.workbench_governance import build_governance_summary
from vuln_prioritizer.workbench_config import WorkbenchSettings

router = APIRouter()

ATTACK_REVIEW_SOURCES = set(WORKBENCH_ALLOWED_MAPPING_SOURCES) | {ATTACK_SOURCE_NONE}


@router.get(
    "/findings/{finding_id}/ttps",
    response_model=FindingAttackContextResponse,
)
def finding_ttps(
    finding_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    finding = repo.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    contexts = repo.list_finding_attack_contexts(finding.id)
    if not contexts:
        raise HTTPException(status_code=404, detail="ATT&CK context not found.")
    return _attack_context_payload(contexts[0], finding_id=finding.id)


@router.get(
    "/projects/{project_id}/attack/top-techniques",
    response_model=TopTechniquesResponse,
)
def project_top_techniques(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    limit: int = Query(default=10, ge=1, le=100),
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return {"items": top_technique_rows(repo.list_project_attack_contexts(project_id), limit=limit)}


@router.get(
    "/projects/{project_id}/attack/review-queue",
    response_model=AttackReviewQueueResponse,
)
def project_attack_review_queue(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    review_status: str | None = None,
    source: str | None = None,
    mapped: bool | None = None,
    priority: str | None = None,
    technique_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    if source is not None and source not in ATTACK_REVIEW_SOURCES:
        raise HTTPException(status_code=422, detail="Unsupported ATT&CK review source.")
    contexts = repo.list_project_attack_review_contexts(
        project_id,
        review_status=review_status,
        source=source,
        mapped=mapped,
        priority=priority,
        technique_id=technique_id,
        limit=limit,
    )
    return {"items": [_attack_review_queue_item_payload(context) for context in contexts]}


@router.patch(
    "/findings/{finding_id}/ttps/review",
    response_model=FindingAttackContextResponse,
)
def update_finding_attack_review(
    finding_id: str,
    payload: AttackReviewUpdateRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
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
    updated_contexts = repo.update_finding_attack_review_status(
        finding.id,
        review_status=payload.review_status,
    )
    repo.create_audit_event(
        project_id=finding.project_id,
        event_type="attack_context.review_updated",
        target_type="finding",
        target_id=finding.id,
        actor=payload.actor,
        message=f"ATT&CK review status updated to {payload.review_status}.",
        metadata_json={"reason": payload.reason, "sources": sorted(sources)},
    )
    session.commit()
    return _attack_context_payload(updated_contexts[0], finding_id=finding.id)


@router.get("/projects/{project_id}/detection-controls")
def list_detection_controls(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return {
        "items": [
            _detection_control_payload(control)
            for control in repo.list_project_detection_controls(project_id)
        ]
    }


@router.post(
    "/projects/{project_id}/detection-controls",
    response_model=DetectionControlResponse,
)
def create_detection_control(
    project_id: str,
    payload: DetectionControlRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    control = repo.upsert_detection_control(
        project_id=project_id,
        **_detection_control_values(payload.model_dump(), index=1),
        history_actor=payload.owner,
    )
    repo.create_audit_event(
        project_id=project_id,
        event_type="detection_control.created",
        target_type="detection_control",
        target_id=control.id,
        actor=control.owner,
        message=f"Detection control {control.name!r} was created.",
    )
    session.commit()
    return _detection_control_payload(control)


@router.patch(
    "/detection-controls/{control_id}",
    response_model=DetectionControlResponse,
)
def update_detection_control(
    control_id: str,
    payload: DetectionControlPatchRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    control = repo.get_detection_control(control_id)
    if control is None:
        raise HTTPException(status_code=404, detail="Detection control not found.")
    values = _patched_detection_control_values(control, payload)
    try:
        updated = repo.update_detection_control(
            control,
            **values,
            history_actor=values.get("owner"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    repo.create_audit_event(
        project_id=updated.project_id,
        event_type="detection_control.updated",
        target_type="detection_control",
        target_id=updated.id,
        actor=updated.owner,
        message=f"Detection control {updated.name!r} was updated.",
    )
    session.commit()
    return _detection_control_payload(updated)


@router.delete("/detection-controls/{control_id}")
def delete_detection_control(
    control_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    control = repo.get_detection_control(control_id)
    if control is None:
        raise HTTPException(status_code=404, detail="Detection control not found.")
    project_id = control.project_id
    name = control.name
    removed_attachments = 0
    for attachment in list(control.attachments):
        if _delete_upload_artifact(
            attachment.path,
            settings=settings,
            expected_sha256=attachment.sha256,
        ):
            removed_attachments += 1
    repo.delete_detection_control(control)
    repo.create_audit_event(
        project_id=project_id,
        event_type="detection_control.deleted",
        target_type="detection_control",
        target_id=control_id,
        message=f"Detection control {name!r} was deleted.",
        metadata_json={"removed_attachments": removed_attachments},
    )
    session.commit()
    return {"deleted": True, "removed_attachments": removed_attachments}


@router.get(
    "/detection-controls/{control_id}/history",
    response_model=dict[str, list[DetectionControlHistoryResponse]],
)
def list_detection_control_history(
    control_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_detection_control(control_id) is None:
        raise HTTPException(status_code=404, detail="Detection control not found.")
    return {
        "items": [
            _detection_control_history_payload(item)
            for item in repo.list_detection_control_history(control_id)
        ]
    }


@router.get(
    "/detection-controls/{control_id}/attachments",
    response_model=dict[str, list[DetectionControlAttachmentResponse]],
)
def list_detection_control_attachments(
    control_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_detection_control(control_id) is None:
        raise HTTPException(status_code=404, detail="Detection control not found.")
    return {
        "items": [
            _detection_control_attachment_payload(item)
            for item in repo.list_detection_control_attachments(control_id)
        ]
    }


@router.post(
    "/detection-controls/{control_id}/attachments",
    response_model=DetectionControlAttachmentResponse,
)
async def upload_detection_control_attachment(
    control_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    file: Annotated[UploadFile, File()],
) -> dict[str, Any]:
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
        message=f"Evidence attachment {filename!r} was uploaded.",
        metadata_json={"attachment_id": attachment.id, "size_bytes": len(content)},
    )
    session.commit()
    return _detection_control_attachment_payload(attachment)


@router.get("/detection-control-attachments/{attachment_id}/download")
def download_detection_control_attachment(
    attachment_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> StreamingResponse:
    attachment = WorkbenchRepository(session).get_detection_control_attachment(attachment_id)
    if attachment is None:
        raise HTTPException(status_code=404, detail="Detection attachment not found.")
    attachment_path = _resolve_upload_artifact(
        attachment.path,
        settings=settings,
        expected_sha256=attachment.sha256,
        missing_detail="Detection attachment not found.",
    )
    return _artifact_response(
        attachment_path,
        media_type=attachment.content_type or "application/octet-stream",
    )


@router.delete("/detection-control-attachments/{attachment_id}")
def delete_detection_control_attachment(
    attachment_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    attachment = repo.get_detection_control_attachment(attachment_id)
    if attachment is None:
        raise HTTPException(status_code=404, detail="Detection attachment not found.")
    control = repo.get_detection_control(attachment.control_id)
    artifact_removed = _delete_upload_artifact(
        attachment.path,
        settings=settings,
        expected_sha256=attachment.sha256,
    )
    project_id = attachment.project_id
    control_id = attachment.control_id
    repo.delete_detection_control_attachment(attachment)
    if control is not None:
        repo.add_detection_control_history(
            control=control,
            event_type="attachment_deleted",
            current_json={"attachment_id": attachment_id},
        )
    repo.create_audit_event(
        project_id=project_id,
        event_type="detection_control.attachment_deleted",
        target_type="detection_control",
        target_id=control_id,
        message="Evidence attachment was deleted.",
        metadata_json={"attachment_id": attachment_id, "artifact_removed": artifact_removed},
    )
    session.commit()
    return {"deleted": True, "artifact_removed": artifact_removed}


@router.post(
    "/projects/{project_id}/detection-controls/import",
    response_model=DetectionControlImportResponse,
)
async def import_detection_controls(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    file: Annotated[UploadFile, File()],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    content = await _read_bounded_upload(file, settings=settings)
    rows = _parse_detection_control_rows(file.filename or "controls", content)
    controls = [
        repo.upsert_detection_control(project_id=project_id, **row, history_actor="api-import")
        for row in rows
    ]
    repo.create_audit_event(
        project_id=project_id,
        event_type="detection_control.imported",
        target_type="project",
        target_id=project_id,
        message="Detection controls were imported.",
        metadata_json={"imported": len(controls)},
    )
    session.commit()
    return {
        "imported": len(controls),
        "items": [_detection_control_payload(control) for control in controls],
    }


@router.get(
    "/projects/{project_id}/attack/coverage-gaps",
    response_model=CoverageGapResponse,
)
def project_coverage_gaps(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return _coverage_gap_payload(
        repo.list_project_attack_contexts(project_id),
        repo.list_project_detection_controls(project_id),
        repo.list_project_findings(project_id),
    )


@router.get("/projects/{project_id}/attack/coverage-gap-navigator-layer")
def project_coverage_gap_navigator_layer(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    payload = _coverage_gap_payload(
        repo.list_project_attack_contexts(project_id),
        repo.list_project_detection_controls(project_id),
        repo.list_project_findings(project_id),
    )
    gap_items = [
        item
        for item in payload["items"]
        if item["coverage_level"] in WEAK_DETECTION_COVERAGE_LEVELS
    ]
    return {
        "version": "4.5",
        "name": "vuln-prioritizer detection coverage gaps",
        "domain": "enterprise-attack",
        "description": (
            "Defensive Navigator layer showing mapped techniques with partial, missing, "
            "or unknown detection coverage. It does not describe offensive procedures."
        ),
        "techniques": [
            {
                "techniqueID": item["technique_id"],
                "score": _coverage_gap_score(item["coverage_level"]),
                "comment": item["recommended_action"],
            }
            for item in gap_items
        ],
    }


@router.get(
    "/projects/{project_id}/attack/techniques/{technique_id}",
    response_model=TechniqueDetailResponse,
)
def project_attack_technique_detail(
    project_id: str,
    technique_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    contexts = repo.list_project_attack_contexts(project_id)
    controls = repo.list_detection_controls_for_technique(project_id, technique_id)
    findings = [
        finding
        for finding in repo.list_project_findings(project_id)
        if any(
            _technique_id_from_dict(technique) == technique_id
            for context in finding.attack_contexts
            for technique in (context.techniques_json or [])
            if isinstance(technique, dict)
        )
    ]
    coverage = [
        item
        for item in _coverage_gap_payload(contexts, controls, findings)["items"]
        if item["technique_id"] == technique_id
    ]
    metadata = _technique_metadata_from_contexts(contexts, technique_id)
    return {
        "technique_id": technique_id,
        "name": metadata.get("name"),
        "deprecated": bool(metadata.get("deprecated")),
        "revoked": bool(metadata.get("revoked")),
        "tactics": list(metadata.get("tactics", [])),
        "findings": [_finding_payload(finding) for finding in findings],
        "controls": [_detection_control_payload(control) for control in controls],
        "coverage": coverage[0] if coverage else None,
    }


@router.get(
    "/projects/{project_id}/governance/rollups",
    response_model=GovernanceRollupsResponse,
)
def project_governance_rollups(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    limit: int = Query(default=10, ge=1, le=100),
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    summary = build_governance_summary(repo.list_project_findings(project_id), limit=limit)
    return _governance_payload(summary)


@router.get("/analysis-runs/{run_id}/attack/navigator-layer")
def run_attack_navigator_layer(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    run = repo.get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found.")
    return navigator_layer_from_contexts(repo.list_run_attack_contexts(run.id))
