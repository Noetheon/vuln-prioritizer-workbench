"""JSON API routes for the Workbench MVP."""

from __future__ import annotations

import hashlib
import re
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import quote
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from vuln_prioritizer import __version__
from vuln_prioritizer.api.deps import get_db_session, get_workbench_settings
from vuln_prioritizer.api.schemas import (
    AnalysisRunResponse,
    EvidenceBundleResponse,
    EvidenceBundleVerificationResponse,
    FindingAttackContextResponse,
    FindingsListResponse,
    GovernanceRollupsResponse,
    ProjectCreateRequest,
    ProjectResponse,
    ProviderSnapshotStatus,
    ProviderSourceStatus,
    ProviderStatusResponse,
    ReportCreateRequest,
    ReportResponse,
    TopTechniquesResponse,
)
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.services.workbench_analysis import (
    SUPPORTED_WORKBENCH_INPUT_FORMATS,
    WorkbenchAnalysisError,
    run_workbench_import,
)
from vuln_prioritizer.services.workbench_attack import (
    navigator_layer_from_contexts,
    top_technique_rows,
)
from vuln_prioritizer.services.workbench_governance import build_governance_summary
from vuln_prioritizer.services.workbench_reports import (
    WorkbenchReportError,
    create_run_evidence_bundle,
    create_run_report,
    verify_run_evidence_bundle,
)
from vuln_prioritizer.workbench_config import WorkbenchSettings

api_router = APIRouter(prefix="/api")

ALLOWED_UPLOAD_SUFFIXES = {
    "cve-list": {".txt", ".csv"},
    "generic-occurrence-csv": {".csv"},
    "trivy-json": {".json"},
    "grype-json": {".json"},
}
ALLOWED_CONTEXT_UPLOAD_SUFFIXES = {
    "asset-context": {".csv"},
    "vex": {".json"},
    "waiver": {".yml", ".yaml"},
}
SAFE_SNAPSHOT_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*[.]json$")
SAFE_ATTACK_FILENAME_RE = SAFE_SNAPSHOT_FILENAME_RE


@api_router.get("/health")
def health(
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    return {
        "status": "ok",
        "database": "ok",
        "projects": len(repo.list_projects()),
        "upload_dir": str(settings.upload_dir),
        "report_dir": str(settings.report_dir),
    }


@api_router.get("/version")
def version() -> dict[str, Any]:
    return {"version": __version__, "app": "Vuln Prioritizer Workbench"}


@api_router.get("/projects")
def list_projects(session: Annotated[Session, Depends(get_db_session)]) -> dict[str, Any]:
    projects = WorkbenchRepository(session).list_projects()
    return {"items": [_project_payload(project) for project in projects]}


@api_router.post("/projects", response_model=ProjectResponse)
def create_project(
    payload: ProjectCreateRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Project name is required.")
    repo = WorkbenchRepository(session)
    if repo.get_project_by_name(name) is not None:
        raise HTTPException(status_code=409, detail="Project already exists.")
    project = repo.create_project(name=name, description=payload.description)
    session.commit()
    return _project_payload(project)


@api_router.get("/projects/{project_id}", response_model=ProjectResponse)
def get_project(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    project = WorkbenchRepository(session).get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return _project_payload(project)


@api_router.get("/projects/{project_id}/runs")
def list_project_runs(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return {"items": [_analysis_run_payload(run) for run in repo.list_analysis_runs(project_id)]}


@api_router.post("/projects/{project_id}/imports", response_model=AnalysisRunResponse)
async def import_findings(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    input_format: Annotated[str, Form()],
    file: Annotated[UploadFile, File()],
    provider_snapshot_file: Annotated[str | None, Form()] = None,
    locked_provider_data: Annotated[bool, Form()] = False,
    attack_source: Annotated[str, Form()] = "none",
    attack_mapping_file: Annotated[str | None, Form()] = None,
    attack_technique_metadata_file: Annotated[str | None, Form()] = None,
    asset_context_file: Annotated[UploadFile | None, File()] = None,
    vex_file: Annotated[UploadFile | None, File()] = None,
    waiver_file: Annotated[UploadFile | None, File()] = None,
) -> dict[str, Any]:
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
        snapshot_path = _resolve_provider_snapshot_path(provider_snapshot_file, settings=settings)
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
    return _analysis_run_payload(result.run)


@api_router.get("/analysis-runs/{run_id}", response_model=AnalysisRunResponse)
def get_analysis_run(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    run = WorkbenchRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found.")
    return _analysis_run_payload(run)


@api_router.get("/runs/{run_id}")
def get_run_alias(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    return get_analysis_run(run_id=run_id, session=session)


@api_router.get("/runs/{run_id}/summary")
def get_run_summary(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    run = WorkbenchRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found.")
    return _analysis_run_payload(run)["summary"]


@api_router.get("/projects/{project_id}/findings", response_model=FindingsListResponse)
def list_findings(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    priority: str | None = None,
    status: str | None = None,
    q: str | None = None,
    kev: bool | None = None,
    owner: str | None = None,
    service: str | None = None,
    min_epss: float | None = Query(default=None, ge=0, le=1),
    min_cvss: float | None = Query(default=None, ge=0, le=10),
    sort: str = Query(default="operational"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    findings = repo.list_project_findings(project_id)
    filtered = _filter_findings(
        findings,
        priority=priority,
        status=status,
        q=q,
        kev=kev,
        owner=owner,
        service=service,
        min_epss=min_epss,
        min_cvss=min_cvss,
    )
    sorted_findings = _sort_findings(filtered, sort=sort)
    paged = sorted_findings[offset : offset + limit]
    return {
        "items": [_finding_payload(finding) for finding in paged],
        "total": len(sorted_findings),
        "limit": limit,
        "offset": offset,
    }


@api_router.get("/findings/{finding_id}")
def get_finding(
    finding_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    finding = WorkbenchRepository(session).get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return _finding_payload(finding, include_detail=True)


@api_router.get("/findings/{finding_id}/explain")
def explain_finding(
    finding_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    finding = WorkbenchRepository(session).get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return {
        "finding_id": finding.id,
        "cve_id": finding.cve_id,
        "priority": finding.priority,
        "rationale": finding.rationale,
        "recommended_action": finding.recommended_action,
        "explanation": finding.explanation_json,
    }


@api_router.get(
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


@api_router.get(
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


@api_router.get(
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


@api_router.get("/analysis-runs/{run_id}/attack/navigator-layer")
def run_attack_navigator_layer(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    run = repo.get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found.")
    return navigator_layer_from_contexts(repo.list_run_attack_contexts(run.id))


@api_router.get("/providers/status", response_model=ProviderStatusResponse)
def provider_status(
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    snapshot = WorkbenchRepository(session).get_latest_provider_snapshot()
    return _provider_status_payload(snapshot, settings=settings)


@api_router.post("/analysis-runs/{run_id}/reports", response_model=ReportResponse)
def create_report(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
    payload: ReportCreateRequest,
) -> dict[str, Any]:
    try:
        report = create_run_report(
            session=session,
            settings=settings,
            analysis_run_id=run_id,
            report_format=payload.format,
        )
    except WorkbenchReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    session.commit()
    return _report_payload(report)


@api_router.post(
    "/analysis-runs/{run_id}/evidence-bundle",
    response_model=EvidenceBundleResponse,
)
def create_evidence_bundle(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    try:
        bundle = create_run_evidence_bundle(
            session=session,
            settings=settings,
            analysis_run_id=run_id,
        )
    except WorkbenchReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    session.commit()
    return _evidence_bundle_payload(bundle)


@api_router.get("/reports/{report_id}/download")
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


@api_router.get("/evidence-bundles/{bundle_id}/download")
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


@api_router.get(
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


async def _save_upload(
    file: UploadFile,
    *,
    input_format: str,
    settings: WorkbenchSettings,
) -> Path:
    if input_format not in SUPPORTED_WORKBENCH_INPUT_FORMATS:
        raise HTTPException(status_code=422, detail="Unsupported Workbench input format.")
    original_filename = file.filename or "upload"
    _reject_unsafe_upload_filename(original_filename)
    sanitized = _sanitize_filename(original_filename)
    suffix = Path(sanitized).suffix.lower()
    if suffix not in ALLOWED_UPLOAD_SUFFIXES[input_format]:
        raise HTTPException(status_code=422, detail="File extension does not match input format.")

    target_dir = settings.upload_dir / uuid4().hex
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / sanitized
    total = 0
    with target_path.open("wb") as output:
        while chunk := await file.read(1024 * 1024):
            total += len(chunk)
            if total > settings.max_upload_bytes:
                shutil.rmtree(target_dir, ignore_errors=True)
                raise HTTPException(status_code=413, detail="Upload exceeds configured limit.")
            output.write(chunk)
    return target_path


async def _save_optional_context_upload(
    file: UploadFile | None,
    *,
    kind: str,
    settings: WorkbenchSettings,
) -> Path | None:
    if file is None or not file.filename:
        return None
    try:
        allowed_suffixes = ALLOWED_CONTEXT_UPLOAD_SUFFIXES[kind]
    except KeyError as exc:
        raise HTTPException(status_code=422, detail="Unsupported context upload kind.") from exc

    _reject_unsafe_upload_filename(file.filename)
    sanitized = _sanitize_filename(file.filename)
    suffix = Path(sanitized).suffix.lower()
    if suffix not in allowed_suffixes:
        raise HTTPException(status_code=422, detail=f"{kind} file extension is not allowed.")

    target_dir = settings.upload_dir / uuid4().hex / "context"
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / sanitized
    total = 0
    with target_path.open("wb") as output:
        while chunk := await file.read(1024 * 1024):
            total += len(chunk)
            if total > settings.max_upload_bytes:
                shutil.rmtree(target_dir.parent, ignore_errors=True)
                raise HTTPException(status_code=413, detail="Upload exceeds configured limit.")
            output.write(chunk)
    return target_path


def _sanitize_filename(filename: str) -> str:
    name = Path(filename).name.strip() or "upload"
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def _reject_unsafe_upload_filename(filename: str) -> None:
    if "/" in filename or "\\" in filename or Path(filename).name != filename:
        raise HTTPException(status_code=422, detail="Upload filename is not allowed.")
    if any(ord(character) < 32 for character in filename):
        raise HTTPException(status_code=422, detail="Upload filename is not allowed.")


def _artifact_response(path: Path, *, media_type: str) -> StreamingResponse:
    filename = _sanitize_filename(path.name)
    return StreamingResponse(
        _iter_file(path),
        media_type=media_type,
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": (
                f"attachment; filename=\"{filename}\"; filename*=UTF-8''{quote(filename)}"
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )


def _iter_file(path: Path) -> Iterator[bytes]:
    with path.open("rb") as artifact:
        while chunk := artifact.read(1024 * 1024):
            yield chunk


def _resolve_download_artifact(
    value: str,
    *,
    settings: WorkbenchSettings,
    expected_sha256: str,
    missing_detail: str,
) -> Path:
    resolved = Path(value).resolve(strict=False)
    report_root = settings.report_dir.resolve(strict=False)
    if not resolved.is_relative_to(report_root) or not resolved.is_file():
        raise HTTPException(status_code=404, detail=missing_detail)
    actual_sha256 = _sha256_file(resolved)
    if actual_sha256 != expected_sha256:
        raise HTTPException(status_code=409, detail="Artifact checksum mismatch.")
    return resolved


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        while chunk := artifact.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _cleanup_saved_uploads(*paths: Path | None) -> None:
    for path in paths:
        if path is None:
            continue
        root = path.parent.parent if path.parent.name == "context" else path.parent
        shutil.rmtree(root, ignore_errors=True)


def _resolve_provider_snapshot_path(
    value: str | None,
    *,
    settings: WorkbenchSettings,
) -> Path | None:
    if value is None or not value.strip():
        return None

    filename = value.strip()
    if (
        not SAFE_SNAPSHOT_FILENAME_RE.fullmatch(filename)
        or "/" in filename
        or "\\" in filename
        or Path(filename).name != filename
    ):
        raise HTTPException(status_code=422, detail="Provider snapshot path is not allowed.")

    allowed_roots = (
        settings.provider_snapshot_dir.resolve(strict=False),
        settings.provider_cache_dir.resolve(strict=False),
    )
    for root in allowed_roots:
        resolved = _resolve_allowed_root_file(root, filename)
        if resolved is not None:
            return resolved

    raise HTTPException(status_code=422, detail="Provider snapshot file does not exist.")


def _resolve_attack_artifact_path(
    value: str | None,
    *,
    settings: WorkbenchSettings,
) -> Path | None:
    if value is None or not value.strip():
        return None

    filename = value.strip()
    if (
        not SAFE_ATTACK_FILENAME_RE.fullmatch(filename)
        or "/" in filename
        or "\\" in filename
        or Path(filename).name != filename
    ):
        raise HTTPException(status_code=422, detail="ATT&CK artifact path is not allowed.")

    root = settings.attack_artifact_dir.resolve(strict=False)
    resolved = _resolve_allowed_root_file(root, filename)
    if resolved is not None:
        return resolved

    raise HTTPException(status_code=422, detail="ATT&CK artifact file does not exist.")


def _resolve_allowed_root_file(root: Path, filename: str) -> Path | None:
    if not root.is_dir():
        return None
    candidate = root / filename
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError:
        return None
    if not resolved.is_file() or not resolved.is_relative_to(root.resolve(strict=True)):
        return None
    return resolved


def _filter_findings(
    findings: list[Any],
    *,
    priority: str | None,
    status: str | None,
    q: str | None,
    kev: bool | None,
    owner: str | None,
    service: str | None,
    min_epss: float | None,
    min_cvss: float | None,
) -> list[Any]:
    query = q.lower().strip() if q else None
    owner_query = owner.lower().strip() if owner else None
    service_query = service.lower().strip() if service else None
    return [
        finding
        for finding in findings
        if (priority is None or finding.priority == priority)
        and (status is None or finding.status == status)
        and (kev is None or finding.in_kev is kev)
        and (min_epss is None or (finding.epss is not None and finding.epss >= min_epss))
        and (
            min_cvss is None
            or (finding.cvss_base_score is not None and finding.cvss_base_score >= min_cvss)
        )
        and _finding_matches_query(finding, query)
        and _finding_matches_owner(finding, owner_query)
        and _finding_matches_service(finding, service_query)
    ]


def _sort_findings(findings: list[Any], *, sort: str) -> list[Any]:
    if sort == "operational":
        return sorted(findings, key=lambda item: (item.operational_rank, item.cve_id))
    if sort == "priority":
        return sorted(findings, key=lambda item: (item.priority_rank, item.operational_rank))
    if sort == "epss":
        return sorted(findings, key=lambda item: (-(item.epss or -1), item.operational_rank))
    if sort == "cvss":
        return sorted(
            findings,
            key=lambda item: (-(item.cvss_base_score or -1), item.operational_rank),
        )
    if sort == "cve":
        return sorted(findings, key=lambda item: item.cve_id)
    if sort == "last_seen":
        return sorted(findings, key=lambda item: item.last_seen_at, reverse=True)
    raise HTTPException(status_code=422, detail=f"Unsupported findings sort: {sort}.")


def _finding_matches_query(finding: Any, query: str | None) -> bool:
    if query is None:
        return True
    values = [
        finding.cve_id,
        finding.component.name if finding.component else None,
        finding.component.version if finding.component else None,
        finding.asset.asset_id if finding.asset else None,
        finding.asset.business_service if finding.asset else None,
        finding.asset.owner if finding.asset else None,
    ]
    return any(query in str(value).lower() for value in values if value)


def _finding_matches_owner(finding: Any, owner: str | None) -> bool:
    if owner is None:
        return True
    return finding.asset is not None and owner in (finding.asset.owner or "").lower()


def _finding_matches_service(finding: Any, service: str | None) -> bool:
    if service is None:
        return True
    return finding.asset is not None and service in (finding.asset.business_service or "").lower()


def _provider_status_payload(snapshot: Any, *, settings: WorkbenchSettings) -> dict[str, Any]:
    metadata = snapshot.metadata_json if snapshot is not None else {}
    selected_sources = metadata.get("selected_sources", []) if isinstance(metadata, dict) else []
    locked_provider_data = (
        bool(metadata.get("locked_provider_data")) if isinstance(metadata, dict) else False
    )
    warnings = list(metadata.get("warnings", [])) if isinstance(metadata, dict) else []
    snapshot_status = ProviderSnapshotStatus(
        id=snapshot.id if snapshot is not None else None,
        content_hash=snapshot.content_hash if snapshot is not None else None,
        generated_at=metadata.get("generated_at") if isinstance(metadata, dict) else None,
        selected_sources=list(selected_sources),
        requested_cves=int(metadata.get("requested_cves", 0)) if isinstance(metadata, dict) else 0,
        source_path=metadata.get("source_path") if isinstance(metadata, dict) else None,
        locked_provider_data=locked_provider_data,
        missing=snapshot is None or bool(metadata.get("missing", False)),
    )
    sources = [
        ProviderSourceStatus(
            name="nvd",
            selected="nvd" in selected_sources,
            available=snapshot is not None and snapshot.nvd_last_sync is not None,
            value=snapshot.nvd_last_sync if snapshot is not None else None,
            detail="NVD last modified timestamp from the latest stored snapshot.",
        ),
        ProviderSourceStatus(
            name="epss",
            selected="epss" in selected_sources,
            available=snapshot is not None and snapshot.epss_date is not None,
            value=snapshot.epss_date if snapshot is not None else None,
            detail="EPSS date from the latest stored snapshot.",
        ),
        ProviderSourceStatus(
            name="kev",
            selected="kev" in selected_sources,
            available=snapshot is not None and snapshot.kev_catalog_version is not None,
            value=snapshot.kev_catalog_version if snapshot is not None else None,
            detail="Latest KEV date_added value from the latest stored snapshot.",
        ),
    ]
    if snapshot is None:
        warnings.append("No provider snapshot has been recorded by a Workbench import yet.")
    return ProviderStatusResponse(
        status="degraded" if snapshot is None or snapshot_status.missing else "ok",
        snapshot=snapshot_status,
        sources=sources,
        cache_dir=str(settings.provider_cache_dir),
        snapshot_dir=str(settings.provider_snapshot_dir),
        warnings=warnings,
    ).model_dump()


def _project_payload(project: Any) -> dict[str, Any]:
    return {
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "created_at": project.created_at.isoformat(),
    }


def _analysis_run_payload(run: Any) -> dict[str, Any]:
    attack_summary = run.attack_summary_json if isinstance(run.attack_summary_json, dict) else {}
    return {
        "id": run.id,
        "project_id": run.project_id,
        "input_type": run.input_type,
        "input_filename": run.input_filename,
        "status": run.status,
        "started_at": run.started_at.isoformat(),
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "error_message": run.error_message,
        "provider_snapshot_id": run.provider_snapshot_id,
        "summary": {
            "findings_count": run.metadata_json.get("findings_count", 0),
            "kev_hits": run.metadata_json.get("kev_hits", 0),
            "counts_by_priority": run.metadata_json.get("counts_by_priority", {}),
            "provider_snapshot_id": run.provider_snapshot_id,
            "provider_snapshot_missing": run.provider_snapshot_id is None
            and bool(run.metadata_json.get("locked_provider_data")),
            "attack_enabled": bool(run.metadata_json.get("attack_enabled", False)),
            "attack_mapped_cves": int(attack_summary.get("mapped_cves", 0)),
            "attack_source": str(run.metadata_json.get("attack_source", "none")),
            "attack_version": run.metadata_json.get("attack_version"),
            "attack_domain": run.metadata_json.get("attack_domain"),
            "attack_mapping_file_sha256": run.metadata_json.get("attack_mapping_file_sha256"),
            "attack_technique_metadata_file_sha256": run.metadata_json.get(
                "attack_technique_metadata_file_sha256"
            ),
            "attack_metadata_format": run.metadata_json.get("attack_metadata_format"),
            "attack_stix_spec_version": run.metadata_json.get("attack_stix_spec_version"),
        },
    }


def _finding_payload(finding: Any, *, include_detail: bool = False) -> dict[str, Any]:
    payload = {
        "id": finding.id,
        "project_id": finding.project_id,
        "analysis_run_id": finding.analysis_run_id,
        "cve_id": finding.cve_id,
        "priority": finding.priority,
        "priority_rank": finding.priority_rank,
        "operational_rank": finding.operational_rank,
        "status": finding.status,
        "in_kev": finding.in_kev,
        "epss": finding.epss,
        "cvss_base_score": finding.cvss_base_score,
        "component": finding.component.name if finding.component else None,
        "component_version": finding.component.version if finding.component else None,
        "asset": finding.asset.asset_id if finding.asset else None,
        "owner": finding.asset.owner if finding.asset else None,
        "service": finding.asset.business_service if finding.asset else None,
        "attack_mapped": finding.attack_mapped,
        "threat_context_rank": _latest_threat_context_rank(finding),
        "suppressed_by_vex": finding.suppressed_by_vex,
        "under_investigation": finding.under_investigation,
        "vex_statuses": _finding_vex_statuses(finding),
        "waived": finding.waived,
        "waiver_status": finding.waiver_status,
        "waiver_reason": finding.waiver_reason,
        "waiver_owner": finding.waiver_owner,
        "waiver_expires_on": finding.waiver_expires_on,
        "waiver_review_on": finding.waiver_review_on,
        "waiver_days_remaining": finding.waiver_days_remaining,
        "waiver_scope": finding.waiver_scope,
        "waiver_id": finding.waiver_id,
        "waiver_matched_scope": finding.waiver_matched_scope,
        "waiver_approval_ref": finding.waiver_approval_ref,
        "waiver_ticket_url": finding.waiver_ticket_url,
        "rationale": finding.rationale,
        "recommended_action": finding.recommended_action,
    }
    if include_detail:
        payload["finding"] = finding.finding_json
        payload["occurrences"] = [item.evidence_json for item in finding.occurrences]
    return payload


def _finding_vex_statuses(finding: Any) -> dict[str, int]:
    raw_provenance = finding.finding_json.get("provenance") if finding.finding_json else {}
    provenance = raw_provenance if isinstance(raw_provenance, dict) else {}
    raw_statuses = provenance.get("vex_statuses")
    if not isinstance(raw_statuses, dict):
        return {}
    statuses: dict[str, int] = {}
    for key, value in raw_statuses.items():
        if not key:
            continue
        try:
            statuses[str(key)] = int(value)
        except (TypeError, ValueError):
            continue
    return statuses


def _latest_threat_context_rank(finding: Any) -> int | None:
    contexts = getattr(finding, "attack_contexts", None) or []
    if not contexts:
        return None
    return min(int(context.threat_context_rank) for context in contexts)


def _attack_context_payload(context: Any, *, finding_id: str) -> dict[str, Any]:
    return {
        "finding_id": finding_id,
        "cve_id": context.cve_id,
        "mapped": context.mapped,
        "source": context.source,
        "source_version": context.source_version,
        "source_hash": context.source_hash,
        "source_path": context.source_path,
        "attack_version": context.attack_version,
        "domain": context.domain,
        "metadata_hash": context.metadata_hash,
        "metadata_path": context.metadata_path,
        "attack_relevance": context.attack_relevance,
        "threat_context_rank": context.threat_context_rank,
        "rationale": context.rationale,
        "review_status": context.review_status,
        "techniques": context.techniques_json or [],
        "tactics": context.tactics_json or [],
        "mappings": context.mappings_json or [],
    }


def _governance_payload(summary: Any) -> dict[str, Any]:
    return {
        "total_findings": summary.total_findings,
        "owners": [rollup.to_dict() for rollup in summary.owner_rollups],
        "services": [rollup.to_dict() for rollup in summary.service_rollups],
        "waiver_summary": summary.waiver_lifecycle.to_dict(),
        "vex_summary": summary.vex.to_dict(),
    }


def _report_payload(report: Any) -> dict[str, Any]:
    return {
        "id": report.id,
        "analysis_run_id": report.analysis_run_id,
        "format": report.format,
        "kind": report.kind,
        "sha256": report.sha256,
        "download_url": f"/api/reports/{report.id}/download",
    }


def _evidence_bundle_payload(bundle: Any) -> dict[str, Any]:
    return {
        "id": bundle.id,
        "analysis_run_id": bundle.analysis_run_id,
        "sha256": bundle.sha256,
        "download_url": f"/api/evidence-bundles/{bundle.id}/download",
        "verify_url": f"/api/evidence-bundles/{bundle.id}/verify",
    }
