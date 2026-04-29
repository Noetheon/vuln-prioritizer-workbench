"""Report, evidence bundle, and artifact API routes."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from vuln_prioritizer.api.deps import get_db_session, get_workbench_settings
from vuln_prioritizer.api.schemas import (
    ArtifactCleanupResponse,
    ArtifactRetentionRequest,
    ArtifactRetentionResponse,
    EvidenceBundleResponse,
    EvidenceBundleVerificationResponse,
    ReportCreateRequest,
    ReportResponse,
)
from vuln_prioritizer.api.workbench_payloads import (
    _artifact_retention_payload,
    _evidence_bundle_payload,
    _report_payload,
)
from vuln_prioritizer.api.workbench_route_support import (
    _artifact_disk_usage,
)
from vuln_prioritizer.api.workbench_uploads import (
    _artifact_response,
    _delete_download_artifact,
    _resolve_download_artifact,
)
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.services.workbench_artifacts import cleanup_project_artifacts
from vuln_prioritizer.services.workbench_jobs import run_sync_workbench_job
from vuln_prioritizer.services.workbench_reports import (
    WorkbenchReportError,
    create_run_evidence_bundle,
    create_run_report,
    verify_run_evidence_bundle,
)
from vuln_prioritizer.workbench_config import WorkbenchSettings

router = APIRouter()


@router.post("/analysis-runs/{run_id}/reports", response_model=ReportResponse)
def create_report(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    payload: ReportCreateRequest,
) -> dict[str, Any]:
    try:
        durable_job, report = run_sync_workbench_job(
            session=session,
            kind="create_report",
            target_type="analysis_run",
            target_id=run_id,
            payload_json={"analysis_run_id": run_id, "format": payload.format},
            operation=lambda _repo, _job: create_run_report(
                session=session,
                settings=settings,
                analysis_run_id=run_id,
                report_format=payload.format,
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
        message=f"{payload.format} report was created.",
        metadata_json={"job_id": durable_job.id},
    )
    session.commit()
    return _report_payload(report)


@router.post(
    "/analysis-runs/{run_id}/evidence-bundle",
    response_model=EvidenceBundleResponse,
)
def create_evidence_bundle(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    try:
        durable_job, bundle = run_sync_workbench_job(
            session=session,
            kind="create_evidence_bundle",
            target_type="analysis_run",
            target_id=run_id,
            payload_json={"analysis_run_id": run_id},
            operation=lambda _repo, _job: create_run_evidence_bundle(
                session=session,
                settings=settings,
                analysis_run_id=run_id,
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
        message="Evidence bundle was created.",
        metadata_json={"job_id": durable_job.id},
    )
    session.commit()
    return _evidence_bundle_payload(bundle)


@router.get("/projects/{project_id}/artifacts")
def list_project_artifacts(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    reports = repo.list_project_reports(project_id)
    bundles = repo.list_project_evidence_bundles(project_id)
    return {
        "reports": [_report_payload(report) for report in reports],
        "evidence_bundles": [_evidence_bundle_payload(bundle) for bundle in bundles],
        "disk_usage_bytes": _artifact_disk_usage(
            [report.path for report in reports] + [bundle.path for bundle in bundles]
        ),
    }


@router.get(
    "/projects/{project_id}/artifacts/retention",
    response_model=ArtifactRetentionResponse,
)
def get_project_artifact_retention(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return _artifact_retention_payload(
        repo.get_project_artifact_retention(project_id),
        project_id=project_id,
    )


@router.patch(
    "/projects/{project_id}/artifacts/retention",
    response_model=ArtifactRetentionResponse,
)
def update_project_artifact_retention(
    project_id: str,
    payload: ArtifactRetentionRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    retention = repo.upsert_project_artifact_retention(
        project_id=project_id,
        report_retention_days=payload.report_retention_days,
        evidence_retention_days=payload.evidence_retention_days,
        max_disk_usage_mb=payload.max_disk_usage_mb,
    )
    repo.create_audit_event(
        project_id=project_id,
        event_type="artifact_retention.updated",
        target_type="project",
        target_id=project_id,
        message="Artifact retention settings were updated.",
        metadata_json=payload.model_dump(),
    )
    session.commit()
    return _artifact_retention_payload(retention, project_id=project_id)


@router.post(
    "/projects/{project_id}/artifacts/cleanup",
    response_model=ArtifactCleanupResponse,
)
def cleanup_project_artifact_retention(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    dry_run: bool = Query(default=True),
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    result = cleanup_project_artifacts(
        session=session,
        settings=settings,
        project_id=project_id,
        dry_run=dry_run,
    )
    repo.create_audit_event(
        project_id=project_id,
        event_type="artifact_cleanup.completed",
        target_type="project",
        target_id=project_id,
        message="Artifact cleanup completed.",
        metadata_json=result.to_dict(),
    )
    session.commit()
    return result.to_dict()


@router.get("/reports/{report_id}/download")
def download_report(
    report_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> StreamingResponse:
    report = WorkbenchRepository(session).get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    report_path = _resolve_download_artifact(
        report.path,
        settings=settings,
        expected_sha256=report.sha256,
        missing_detail="Report not found.",
    )
    return _artifact_response(report_path, media_type="application/octet-stream")


@router.delete("/reports/{report_id}")
def delete_report(
    report_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    report = repo.get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    artifact_removed = _delete_download_artifact(
        report.path,
        settings=settings,
        expected_sha256=report.sha256,
    )
    project_id = report.project_id
    repo.delete_report(report)
    repo.create_audit_event(
        project_id=project_id,
        event_type="report.deleted",
        target_type="report",
        target_id=report_id,
        message="Report artifact was deleted.",
        metadata_json={"artifact_removed": artifact_removed},
    )
    session.commit()
    return {"deleted": True, "artifact_removed": artifact_removed}


@router.get("/evidence-bundles/{bundle_id}/download")
def download_evidence_bundle(
    bundle_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> StreamingResponse:
    bundle = WorkbenchRepository(session).get_evidence_bundle(bundle_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Evidence bundle not found.")
    bundle_path = _resolve_download_artifact(
        bundle.path,
        settings=settings,
        expected_sha256=bundle.sha256,
        missing_detail="Evidence bundle not found.",
    )
    return _artifact_response(bundle_path, media_type="application/zip")


@router.delete("/evidence-bundles/{bundle_id}")
def delete_evidence_bundle(
    bundle_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    bundle = repo.get_evidence_bundle(bundle_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Evidence bundle not found.")
    artifact_removed = _delete_download_artifact(
        bundle.path,
        settings=settings,
        expected_sha256=bundle.sha256,
    )
    project_id = bundle.project_id
    repo.delete_evidence_bundle(bundle)
    repo.create_audit_event(
        project_id=project_id,
        event_type="evidence_bundle.deleted",
        target_type="evidence_bundle",
        target_id=bundle_id,
        message="Evidence bundle artifact was deleted.",
        metadata_json={"artifact_removed": artifact_removed},
    )
    session.commit()
    return {"deleted": True, "artifact_removed": artifact_removed}


@router.get(
    "/evidence-bundles/{bundle_id}/verify",
    response_model=EvidenceBundleVerificationResponse,
)
def verify_evidence_bundle_api(
    bundle_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    try:
        return verify_run_evidence_bundle(
            session=session,
            settings=settings,
            bundle_id=bundle_id,
        )
    except WorkbenchReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
