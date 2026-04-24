"""JSON API routes for the Workbench MVP."""

from __future__ import annotations

import csv
import hashlib
import io
import os
import re
import secrets
import shutil
from collections.abc import Iterator
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import quote
from uuid import uuid4

import requests
import yaml
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session

from vuln_prioritizer import __version__
from vuln_prioritizer.api.deps import get_db_session, get_workbench_settings
from vuln_prioritizer.api.schemas import (
    AnalysisRunResponse,
    ApiTokenCreateRequest,
    ApiTokenCreateResponse,
    AssetResponse,
    AssetUpdateRequest,
    CoverageGapResponse,
    DetectionControlImportResponse,
    EvidenceBundleResponse,
    EvidenceBundleVerificationResponse,
    FindingAttackContextResponse,
    FindingsListResponse,
    GitHubIssueExportRequest,
    GitHubIssueExportResponse,
    GitHubIssuePreviewRequest,
    GitHubIssuePreviewResponse,
    GovernanceRollupsResponse,
    ProjectConfigRequest,
    ProjectConfigResponse,
    ProjectCreateRequest,
    ProjectResponse,
    ProviderSnapshotStatus,
    ProviderSourceStatus,
    ProviderStatusResponse,
    ProviderUpdateJobRequest,
    ProviderUpdateJobResponse,
    ReportCreateRequest,
    ReportResponse,
    TechniqueDetailResponse,
    TopTechniquesResponse,
    WaiverRequest,
    WaiverResponse,
)
from vuln_prioritizer.api.security import api_token_digest
from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.config import DEFAULT_CACHE_TTL_HOURS
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.models import (
    EpssData,
    KevData,
    NvdData,
    ProviderSnapshotItem,
    ProviderSnapshotMetadata,
    ProviderSnapshotReport,
)
from vuln_prioritizer.provider_snapshot import (
    generate_provider_snapshot_json,
    load_provider_snapshot,
    snapshot_items_by_cve,
)
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider
from vuln_prioritizer.runtime_config import RuntimeConfigDocument
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
from vuln_prioritizer.utils import iso_utc_now, normalize_cve_id
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
API_TOKEN_PREFIX = "vpr_"
PERSISTED_WAIVER_ID_PREFIX = "api:"
DETECTION_COVERAGE_LEVELS = {"covered", "partial", "not_covered", "unknown", "not_applicable"}
WEAK_DETECTION_COVERAGE_LEVELS = {"partial", "not_covered", "unknown"}
GITHUB_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


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


@api_router.post("/tokens", response_model=ApiTokenCreateResponse)
def create_api_token(
    payload: ApiTokenCreateRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Token name is required.")
    token_value = API_TOKEN_PREFIX + secrets.token_urlsafe(32)
    token = WorkbenchRepository(session).create_api_token(
        name=name,
        token_hash=_api_token_hash(token_value),
    )
    session.commit()
    return {
        "id": token.id,
        "name": token.name,
        "token": token_value,
        "created_at": token.created_at.isoformat(),
    }


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


@api_router.get("/projects/{project_id}/assets")
def list_project_assets(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    findings = repo.list_project_findings(project_id)
    finding_counts: dict[str, int] = {}
    for finding in findings:
        if finding.asset_id:
            finding_counts[finding.asset_id] = finding_counts.get(finding.asset_id, 0) + 1
    return {
        "items": [
            _asset_payload(asset, finding_count=finding_counts.get(asset.id, 0))
            for asset in repo.list_project_assets(project_id)
        ]
    }


@api_router.get("/assets/{asset_row_id}", response_model=AssetResponse)
def get_asset(
    asset_row_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    asset = WorkbenchRepository(session).get_asset(asset_row_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    return _asset_payload(asset, finding_count=len(asset.findings))


@api_router.patch("/assets/{asset_row_id}", response_model=AssetResponse)
def update_asset(
    asset_row_id: str,
    payload: AssetUpdateRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    asset = repo.get_asset(asset_row_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    updated_fields = payload.model_fields_set
    updated = repo.update_asset(
        asset,
        asset_id=(
            _strip_or_none(payload.asset_id) or asset.asset_id
            if "asset_id" in updated_fields
            else asset.asset_id
        ),
        target_ref=(
            _strip_or_none(payload.target_ref)
            if "target_ref" in updated_fields
            else asset.target_ref
        ),
        owner=_strip_or_none(payload.owner) if "owner" in updated_fields else asset.owner,
        business_service=(
            _strip_or_none(payload.business_service)
            if "business_service" in updated_fields
            else asset.business_service
        ),
        environment=(
            _strip_or_none(payload.environment)
            if "environment" in updated_fields
            else asset.environment
        ),
        exposure=(
            _strip_or_none(payload.exposure) if "exposure" in updated_fields else asset.exposure
        ),
        criticality=(
            _strip_or_none(payload.criticality)
            if "criticality" in updated_fields
            else asset.criticality
        ),
    )
    session.commit()
    return _asset_payload(updated, finding_count=len(updated.findings))


@api_router.get("/projects/{project_id}/waivers")
def list_project_waivers(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    findings = repo.list_project_findings(project_id)
    return {
        "items": [
            _waiver_payload(
                waiver, matched_findings=_count_matching_waiver_findings(waiver, findings)
            )
            for waiver in repo.list_project_waivers(project_id)
        ]
    }


@api_router.post("/projects/{project_id}/waivers", response_model=WaiverResponse)
def create_project_waiver(
    project_id: str,
    payload: WaiverRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    values = _validated_waiver_values(payload, project_id=project_id, repo=repo)
    waiver = repo.create_waiver(project_id=project_id, **values)
    matched = _sync_project_waivers(repo, project_id)
    session.commit()
    return _waiver_payload(waiver, matched_findings=matched.get(waiver.id, 0))


@api_router.patch("/waivers/{waiver_id}", response_model=WaiverResponse)
def update_project_waiver(
    waiver_id: str,
    payload: WaiverRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    waiver = repo.get_waiver(waiver_id)
    if waiver is None:
        raise HTTPException(status_code=404, detail="Waiver not found.")
    values = _validated_waiver_values(payload, project_id=waiver.project_id, repo=repo)
    updated = repo.update_waiver(waiver, **values)
    matched = _sync_project_waivers(repo, updated.project_id)
    session.commit()
    return _waiver_payload(updated, matched_findings=matched.get(updated.id, 0))


@api_router.delete("/waivers/{waiver_id}")
def delete_project_waiver(
    waiver_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    waiver = repo.get_waiver(waiver_id)
    if waiver is None:
        raise HTTPException(status_code=404, detail="Waiver not found.")
    project_id = waiver.project_id
    repo.delete_waiver(waiver)
    _sync_project_waivers(repo, project_id)
    session.commit()
    return {"deleted": True}


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


@api_router.get("/projects/{project_id}/detection-controls")
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


@api_router.post(
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
    controls = [repo.upsert_detection_control(project_id=project_id, **row) for row in rows]
    session.commit()
    return {
        "imported": len(controls),
        "items": [_detection_control_payload(control) for control in controls],
    }


@api_router.get(
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


@api_router.get("/projects/{project_id}/attack/coverage-gap-navigator-layer")
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


@api_router.get(
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


@api_router.get("/providers/update-jobs")
def list_provider_update_jobs(
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    return {
        "items": [
            _provider_update_job_payload(job)
            for job in WorkbenchRepository(session).list_provider_update_jobs()
        ]
    }


@api_router.post("/providers/update-jobs", response_model=ProviderUpdateJobResponse)
def create_provider_update_job(
    payload: ProviderUpdateJobRequest,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    job = _create_provider_update_job_record(repo=repo, settings=settings, payload=payload)
    session.commit()
    return _provider_update_job_payload(job)


def _create_provider_update_job_record(
    *,
    repo: WorkbenchRepository,
    settings: WorkbenchSettings,
    payload: ProviderUpdateJobRequest,
) -> Any:
    latest_snapshot = repo.get_latest_provider_snapshot()
    previous_metadata = {
        "snapshot_preserved": latest_snapshot is not None,
        "previous_snapshot_id": latest_snapshot.id if latest_snapshot is not None else None,
        "previous_snapshot_hash": latest_snapshot.content_hash
        if latest_snapshot is not None
        else None,
    }
    try:
        snapshot, refresh_metadata = _run_provider_snapshot_refresh(
            repo=repo,
            settings=settings,
            payload=payload,
            latest_snapshot=latest_snapshot,
        )
        metadata = {
            "mode": "synchronous-local-snapshot-refresh",
            **previous_metadata,
            **refresh_metadata,
            "new_snapshot_id": snapshot.id if snapshot is not None else None,
            "new_snapshot_hash": snapshot.content_hash if snapshot is not None else None,
        }
        status = "completed"
        error_message = None
    except HTTPException:
        raise
    except Exception as exc:
        metadata = {
            "mode": "synchronous-local-snapshot-refresh",
            **previous_metadata,
            "snapshot_created": False,
            "detail": "Provider refresh failed before replacing or mutating existing snapshots.",
        }
        status = "failed"
        error_message = str(exc)
    job = repo.create_provider_update_job(
        status=status,
        requested_sources_json=list(payload.sources),
        metadata_json=metadata,
        error_message=error_message,
    )
    return job


def _run_provider_snapshot_refresh(
    *,
    repo: WorkbenchRepository,
    settings: WorkbenchSettings,
    payload: ProviderUpdateJobRequest,
    latest_snapshot: Any | None,
) -> tuple[Any | None, dict[str, Any]]:
    selected_sources: list[str] = list(dict.fromkeys(payload.sources))
    cve_ids = _provider_update_cve_ids(repo, payload=payload)
    if not cve_ids:
        return None, {
            "snapshot_created": False,
            "selected_sources": selected_sources,
            "requested_cves": 0,
            "cache_only": payload.cache_only,
            "warnings": ["No CVEs were available for provider snapshot refresh."],
        }

    baseline_items, baseline_warnings = _load_latest_snapshot_items(latest_snapshot)
    cache = FileCache(settings.provider_cache_dir, DEFAULT_CACHE_TTL_HOURS)
    warnings = list(baseline_warnings)
    source_counts: dict[str, dict[str, int]] = {}

    nvd_results: dict[str, NvdData] = {}
    epss_results: dict[str, EpssData] = {}
    kev_results: dict[str, KevData] = {}
    if "nvd" in selected_sources:
        nvd_results, source_warnings, source_counts["nvd"] = _provider_records_for_snapshot(
            source="nvd",
            cve_ids=cve_ids,
            cache=cache,
            cache_only=payload.cache_only,
            baseline_items=baseline_items,
            settings=settings,
        )
        warnings.extend(source_warnings)
    if "epss" in selected_sources:
        epss_results, source_warnings, source_counts["epss"] = _provider_records_for_snapshot(
            source="epss",
            cve_ids=cve_ids,
            cache=cache,
            cache_only=payload.cache_only,
            baseline_items=baseline_items,
            settings=settings,
        )
        warnings.extend(source_warnings)
    if "kev" in selected_sources:
        kev_results, source_warnings, source_counts["kev"] = _provider_records_for_snapshot(
            source="kev",
            cve_ids=cve_ids,
            cache=cache,
            cache_only=payload.cache_only,
            baseline_items=baseline_items,
            settings=settings,
        )
        warnings.extend(source_warnings)

    output_path = settings.provider_snapshot_dir / f"workbench-provider-snapshot-{uuid4().hex}.json"
    report = ProviderSnapshotReport(
        metadata=ProviderSnapshotMetadata(
            generated_at=iso_utc_now(),
            input_paths=[],
            input_format="workbench-current-findings",
            selected_sources=selected_sources,
            requested_cves=len(cve_ids),
            output_path=str(output_path),
            cache_enabled=True,
            cache_only=payload.cache_only,
            cache_dir=str(settings.provider_cache_dir),
            nvd_api_key_env=settings.nvd_api_key_env,
        ),
        items=[
            ProviderSnapshotItem(
                cve_id=cve_id,
                nvd=nvd_results.get(cve_id) if "nvd" in selected_sources else None,
                epss=epss_results.get(cve_id) if "epss" in selected_sources else None,
                kev=kev_results.get(cve_id) if "kev" in selected_sources else None,
            )
            for cve_id in cve_ids
        ],
        warnings=warnings,
    )
    document = generate_provider_snapshot_json(report)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(document, encoding="utf-8")
    content_hash = hashlib.sha256(document.encode("utf-8")).hexdigest()
    existing_snapshot = repo.get_provider_snapshot_by_hash(content_hash)
    if existing_snapshot is not None:
        snapshot = existing_snapshot
    else:
        metadata_json = report.metadata.model_dump()
        metadata_json.update(
            {
                "source_path": str(output_path),
                "item_count": len(report.items),
                "warnings": warnings,
                "missing": False,
                "generated_by": "provider-update-job",
                "source_counts": source_counts,
            }
        )
        snapshot = repo.create_provider_snapshot(
            content_hash=content_hash,
            nvd_last_sync=_latest_nvd_sync(nvd_results.values()),
            epss_date=_latest_epss_date(epss_results.values()),
            kev_catalog_version=_latest_kev_date(kev_results.values()),
            metadata_json=metadata_json,
        )
    return snapshot, {
        "snapshot_created": True,
        "snapshot_path": str(output_path),
        "snapshot_sha256": content_hash,
        "selected_sources": selected_sources,
        "requested_cves": len(cve_ids),
        "cache_only": payload.cache_only,
        "source_counts": source_counts,
        "warnings": warnings,
    }


def _provider_update_cve_ids(
    repo: WorkbenchRepository,
    *,
    payload: ProviderUpdateJobRequest,
) -> list[str]:
    explicit_cves: list[str] = []
    invalid_cves: list[str] = []
    for value in payload.cve_ids:
        normalized = normalize_cve_id(value)
        if normalized is None:
            invalid_cves.append(value)
        else:
            explicit_cves.append(normalized)
    if invalid_cves:
        raise HTTPException(
            status_code=422,
            detail="Invalid CVE id(s): " + ", ".join(invalid_cves),
        )
    cve_ids = explicit_cves
    if not cve_ids:
        cve_ids = [
            finding.cve_id
            for project in repo.list_projects()
            for finding in repo.list_project_findings(project.id)
        ]
    unique_cves = sorted(dict.fromkeys(cve_ids))
    if payload.max_cves is not None:
        return unique_cves[: payload.max_cves]
    return unique_cves


def _load_latest_snapshot_items(
    latest_snapshot: Any | None,
) -> tuple[dict[str, ProviderSnapshotItem], list[str]]:
    if latest_snapshot is None:
        return {}, []
    metadata = (
        latest_snapshot.metadata_json if isinstance(latest_snapshot.metadata_json, dict) else {}
    )
    path_value = (
        metadata.get("source_path") or metadata.get("snapshot_path") or metadata.get("output_path")
    )
    if not isinstance(path_value, str) or not path_value:
        return {}, ["Latest provider snapshot has no readable source artifact path."]
    path = Path(path_value)
    if not path.is_file():
        return {}, ["Latest provider snapshot artifact is no longer available on disk."]
    try:
        return snapshot_items_by_cve(load_provider_snapshot(path)), []
    except ValueError as exc:
        return {}, [f"Latest provider snapshot artifact could not be reused: {exc}"]


def _provider_records_for_snapshot(
    *,
    source: str,
    cve_ids: list[str],
    cache: FileCache,
    cache_only: bool,
    baseline_items: dict[str, ProviderSnapshotItem],
    settings: WorkbenchSettings,
) -> tuple[dict[str, Any], list[str], dict[str, int]]:
    warnings: list[str] = []
    fetched: dict[str, Any]
    if cache_only:
        fetched, warnings = _cached_provider_records(source=source, cache=cache, cve_ids=cve_ids)
    elif source == "nvd":
        fetched, warnings = NvdProvider.from_env(
            api_key_env=settings.nvd_api_key_env,
            cache=cache,
        ).fetch_many(cve_ids, refresh=True)
    elif source == "epss":
        fetched, warnings = EpssProvider(cache=cache).fetch_many(cve_ids, refresh=True)
    else:
        fetched, warnings = KevProvider(cache=cache).fetch_many(cve_ids, refresh=True)

    merged: dict[str, Any] = {}
    fallback_count = 0
    missing_count = 0
    for cve_id in cve_ids:
        if cve_id in fetched:
            merged[cve_id] = fetched[cve_id]
            continue
        baseline_item = baseline_items.get(cve_id)
        baseline_value = getattr(baseline_item, source, None) if baseline_item is not None else None
        if baseline_value is not None:
            merged[cve_id] = baseline_value
            fallback_count += 1
            continue
        missing_count += 1
    if missing_count:
        warnings.append(f"{source.upper()} data missing for {missing_count} CVE(s).")
    return (
        merged,
        warnings,
        {
            "records": len(merged),
            "fetched": len(fetched),
            "fallback_from_previous_snapshot": fallback_count,
            "missing": missing_count,
        },
    )


def _cached_provider_records(
    *,
    source: str,
    cache: FileCache,
    cve_ids: list[str],
) -> tuple[dict[str, Any], list[str]]:
    if source == "kev":
        cached_catalog = cache.get_json("kev", "catalog")
        if not isinstance(cached_catalog, dict):
            return {}, ["Cache-only KEV catalog is missing from the local cache."]
        return _cached_kev_records(cached_catalog, cve_ids)

    model = NvdData if source == "nvd" else EpssData
    records: dict[str, Any] = {}
    invalid: list[str] = []
    for cve_id in cve_ids:
        cached_payload = cache.get_json(source, cve_id)
        if cached_payload is None:
            continue
        try:
            records[cve_id] = model.model_validate(cached_payload)
        except ValidationError:
            invalid.append(cve_id)
    warnings = (
        [f"Cache-only {source.upper()} data invalid for CVE(s): " + ", ".join(invalid) + "."]
        if invalid
        else []
    )
    return records, warnings


def _cached_kev_records(
    cached_catalog: dict[str, Any],
    cve_ids: list[str],
) -> tuple[dict[str, KevData], list[str]]:
    records: dict[str, KevData] = {}
    invalid: list[str] = []
    for cve_id in cve_ids:
        item = cached_catalog.get(cve_id)
        if item is None:
            continue
        try:
            records[cve_id] = KevData.model_validate(item)
        except ValidationError:
            invalid.append(cve_id)
    warnings = (
        ["Cache-only KEV data invalid for CVE(s): " + ", ".join(invalid) + "."] if invalid else []
    )
    return records, warnings


def _latest_nvd_sync(records: Any) -> str | None:
    values = [
        value for record in records for value in (record.last_modified, record.published) if value
    ]
    return sorted(values)[-1] if values else None


def _latest_epss_date(records: Any) -> str | None:
    values = [record.date for record in records if record.date]
    return sorted(values)[-1] if values else None


def _latest_kev_date(records: Any) -> str | None:
    values = [record.date_added for record in records if record.date_added]
    return sorted(values)[-1] if values else None


@api_router.post("/projects/{project_id}/settings/config", response_model=ProjectConfigResponse)
def save_project_config(
    project_id: str,
    payload: ProjectConfigRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    try:
        document = RuntimeConfigDocument.model_validate(payload.config)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid project config: {exc}") from exc
    snapshot = repo.save_project_config_snapshot(
        project_id=project_id,
        source="api",
        config_json=document.model_dump(),
    )
    session.commit()
    return _project_config_payload(snapshot)


@api_router.get("/projects/{project_id}/settings/config")
def get_project_config(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    snapshot = repo.get_latest_project_config_snapshot(project_id)
    return {"item": _project_config_payload(snapshot) if snapshot is not None else None}


@api_router.post(
    "/projects/{project_id}/github/issues/preview",
    response_model=GitHubIssuePreviewResponse,
)
def preview_github_issues(
    project_id: str,
    payload: GitHubIssuePreviewRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    findings = _sort_findings(
        _filter_findings(
            repo.list_project_findings(project_id),
            priority=payload.priority,
            status=None,
            q=None,
            kev=None,
            owner=None,
            service=None,
            min_epss=None,
            min_cvss=None,
        ),
        sort="operational",
    )
    preview_items = []
    duplicate_keys: set[str] = set()
    for finding in findings:
        item = _github_issue_preview_payload(finding, payload=payload)
        if item["duplicate_key"] in duplicate_keys:
            continue
        duplicate_keys.add(item["duplicate_key"])
        preview_items.append(item)
        if len(preview_items) >= payload.limit:
            break
    return {
        "dry_run": True,
        "items": preview_items,
    }


@api_router.post(
    "/projects/{project_id}/github/issues/export",
    response_model=GitHubIssueExportResponse,
)
def export_github_issues(
    project_id: str,
    payload: GitHubIssueExportRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    repository_path = _github_repository_path(payload.repository)
    token = None if payload.dry_run else _github_export_token(payload.token_env)
    findings = _sort_findings(
        _filter_findings(
            repo.list_project_findings(project_id),
            priority=payload.priority,
            status=None,
            q=None,
            kev=None,
            owner=None,
            service=None,
            min_epss=None,
            min_cvss=None,
        ),
        sort="operational",
    )
    exported_items = []
    batch_keys: set[str] = set()
    created_count = 0
    skipped_count = 0
    for finding in findings:
        item = _github_issue_preview_payload(finding, payload=payload)
        duplicate_key = item["duplicate_key"]
        already_exported = repo.github_issue_export_exists(project_id, duplicate_key)
        if duplicate_key in batch_keys or already_exported:
            skipped_count += 1
            exported_items.append(
                {
                    **item,
                    "status": "skipped_duplicate",
                    "issue_url": None,
                    "issue_number": None,
                }
            )
        elif payload.dry_run:
            exported_items.append(
                {
                    **item,
                    "status": "preview",
                    "issue_url": None,
                    "issue_number": None,
                }
            )
        else:
            if token is None:
                raise HTTPException(status_code=422, detail="GitHub token is not configured.")
            issue = _create_github_issue(
                repository_path=repository_path,
                token=token,
                item=item,
            )
            repo.create_github_issue_export(
                project_id=project_id,
                finding_id=finding.id,
                duplicate_key=duplicate_key,
                title=item["title"],
                html_url=issue["html_url"],
                issue_number=issue["number"],
            )
            created_count += 1
            exported_items.append(
                {
                    **item,
                    "status": "created",
                    "issue_url": issue["html_url"],
                    "issue_number": issue["number"],
                }
            )
        batch_keys.add(duplicate_key)
        if len(exported_items) >= payload.limit:
            break
    session.commit()
    return {
        "dry_run": payload.dry_run,
        "created_count": created_count,
        "skipped_count": skipped_count,
        "items": exported_items,
    }


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


def _api_token_hash(token_value: str) -> str:
    return api_token_digest(token_value)


def _strip_or_none(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _validated_date(value: str | None, *, field_name: str, required: bool) -> str | None:
    normalized = _strip_or_none(value)
    if normalized is None:
        if required:
            raise HTTPException(status_code=422, detail=f"{field_name} is required.")
        return None
    try:
        date.fromisoformat(normalized[:10])
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"{field_name} must be YYYY-MM-DD.") from exc
    return normalized[:10]


def _today() -> date:
    try:
        return date.fromisoformat(iso_utc_now()[:10])
    except ValueError:
        return datetime.now(UTC).date()


def _validated_waiver_values(
    payload: WaiverRequest,
    *,
    project_id: str,
    repo: WorkbenchRepository,
) -> dict[str, Any]:
    cve_id = normalize_cve_id(payload.cve_id) if payload.cve_id else None
    if payload.cve_id and cve_id is None:
        raise HTTPException(status_code=422, detail="cve_id is not a valid CVE identifier.")
    finding_id = _strip_or_none(payload.finding_id)
    if finding_id is not None:
        finding = repo.get_finding(finding_id)
        if finding is None or finding.project_id != project_id:
            raise HTTPException(status_code=422, detail="finding_id does not belong to project.")
    expires_on = _validated_date(payload.expires_on, field_name="expires_on", required=True)
    if expires_on is None:
        raise HTTPException(status_code=422, detail="expires_on is required.")
    review_on = _validated_date(payload.review_on, field_name="review_on", required=False)
    values = {
        "cve_id": cve_id,
        "finding_id": finding_id,
        "asset_id": _strip_or_none(payload.asset_id),
        "component_name": _strip_or_none(payload.component_name),
        "component_version": _strip_or_none(payload.component_version),
        "service": _strip_or_none(payload.service),
        "owner": _strip_or_none(payload.owner),
        "reason": _strip_or_none(payload.reason),
        "expires_on": expires_on,
        "review_on": review_on,
        "approval_ref": _strip_or_none(payload.approval_ref),
        "ticket_url": _strip_or_none(payload.ticket_url),
    }
    if values["owner"] is None:
        raise HTTPException(status_code=422, detail="owner is required.")
    if values["reason"] is None:
        raise HTTPException(status_code=422, detail="reason is required.")
    if review_on is not None and review_on > expires_on:
        raise HTTPException(status_code=422, detail="review_on must not be after expires_on.")
    if not any(
        values[name]
        for name in (
            "cve_id",
            "finding_id",
            "asset_id",
            "component_name",
            "component_version",
            "service",
        )
    ):
        raise HTTPException(status_code=422, detail="At least one waiver scope is required.")
    return values


def _sync_project_waivers(repo: WorkbenchRepository, project_id: str) -> dict[str, int]:
    findings = repo.list_project_findings(project_id)
    waivers = repo.list_project_waivers(project_id)
    matched_counts = {waiver.id: 0 for waiver in waivers}
    for finding in findings:
        if (finding.waiver_id or "").startswith(PERSISTED_WAIVER_ID_PREFIX):
            _clear_persisted_waiver_state(finding)
    for finding in findings:
        matches = [waiver for waiver in waivers if _waiver_matches_finding(waiver, finding)]
        if not matches:
            continue
        matches.sort(key=lambda waiver: (_waiver_status_sort_key(waiver), waiver.expires_on))
        waiver = matches[0]
        matched_counts[waiver.id] = matched_counts.get(waiver.id, 0) + 1
        status, days_remaining = _waiver_status(waiver)
        finding.waived = status in {"active", "review_due"}
        finding.waiver_status = status
        finding.waiver_reason = waiver.reason
        finding.waiver_owner = waiver.owner
        finding.waiver_expires_on = waiver.expires_on
        finding.waiver_review_on = waiver.review_on
        finding.waiver_days_remaining = days_remaining
        finding.waiver_scope = _waiver_scope_label(waiver)
        finding.waiver_id = PERSISTED_WAIVER_ID_PREFIX + waiver.id
        finding.waiver_matched_scope = _waiver_scope_label(waiver)
        finding.waiver_approval_ref = waiver.approval_ref
        finding.waiver_ticket_url = waiver.ticket_url
        if status == "expired":
            finding.waived = False
    repo.session.flush()
    return matched_counts


def _clear_persisted_waiver_state(finding: Any) -> None:
    finding.waived = False
    finding.waiver_status = None
    finding.waiver_reason = None
    finding.waiver_owner = None
    finding.waiver_expires_on = None
    finding.waiver_review_on = None
    finding.waiver_days_remaining = None
    finding.waiver_scope = None
    finding.waiver_id = None
    finding.waiver_matched_scope = None
    finding.waiver_approval_ref = None
    finding.waiver_ticket_url = None


def _waiver_matches_finding(waiver: Any, finding: Any) -> bool:
    if waiver.finding_id and waiver.finding_id != finding.id:
        return False
    if waiver.cve_id and waiver.cve_id != finding.cve_id:
        return False
    if waiver.asset_id and (finding.asset is None or waiver.asset_id != finding.asset.asset_id):
        return False
    if waiver.component_name and (
        finding.component is None
        or waiver.component_name.casefold() != (finding.component.name or "").casefold()
    ):
        return False
    if waiver.component_version and (
        finding.component is None or waiver.component_version != finding.component.version
    ):
        return False
    if waiver.service and (
        finding.asset is None
        or waiver.service.casefold() != (finding.asset.business_service or "").casefold()
    ):
        return False
    return True


def _count_matching_waiver_findings(waiver: Any, findings: list[Any]) -> int:
    return sum(1 for finding in findings if _waiver_matches_finding(waiver, finding))


def _waiver_status(waiver: Any) -> tuple[str, int | None]:
    today = _today()
    expires_on = date.fromisoformat(waiver.expires_on[:10])
    days_remaining = (expires_on - today).days
    if expires_on < today:
        return "expired", days_remaining
    if waiver.review_on is not None and date.fromisoformat(waiver.review_on[:10]) <= today:
        return "review_due", days_remaining
    if days_remaining <= 14:
        return "review_due", days_remaining
    return "active", days_remaining


def _waiver_status_sort_key(waiver: Any) -> int:
    status, _days_remaining = _waiver_status(waiver)
    return {"review_due": 0, "active": 1, "expired": 2}.get(status, 9)


def _waiver_scope_label(waiver: Any) -> str:
    parts = []
    for label, value in (
        ("finding", waiver.finding_id),
        ("cve", waiver.cve_id),
        ("asset", waiver.asset_id),
        ("component", waiver.component_name),
        ("version", waiver.component_version),
        ("service", waiver.service),
    ):
        if value:
            parts.append(f"{label}:{value}")
    return ", ".join(parts) or "project"


async def _read_bounded_upload(file: UploadFile, *, settings: WorkbenchSettings) -> bytes:
    total = 0
    chunks: list[bytes] = []
    while chunk := await file.read(1024 * 1024):
        total += len(chunk)
        if total > settings.max_upload_bytes:
            raise HTTPException(status_code=413, detail="Upload exceeds configured limit.")
        chunks.append(chunk)
    return b"".join(chunks)


def _parse_detection_control_rows(filename: str, content: bytes) -> list[dict[str, Any]]:
    suffix = Path(filename).suffix.lower()
    if suffix == ".csv":
        text = content.decode("utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(text)))
    elif suffix in {".yml", ".yaml"}:
        document = yaml.safe_load(content.decode("utf-8")) or {}
        raw_rows = document.get("controls", document) if isinstance(document, dict) else document
        if not isinstance(raw_rows, list):
            raise HTTPException(
                status_code=422, detail="Detection controls YAML must contain a list."
            )
        rows = [row for row in raw_rows if isinstance(row, dict)]
    else:
        raise HTTPException(status_code=422, detail="Detection controls must be CSV or YAML.")
    parsed = [
        _detection_control_values(row, index=index) for index, row in enumerate(rows, start=1)
    ]
    if not parsed:
        raise HTTPException(status_code=422, detail="Detection controls file is empty.")
    return parsed


def _detection_control_values(row: dict[str, Any], *, index: int) -> dict[str, Any]:
    technique_id = _strip_or_none(str(row.get("technique_id") or row.get("technique") or ""))
    if technique_id is None or not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique_id):
        raise HTTPException(
            status_code=422,
            detail=f"Detection control row {index} has an invalid technique_id.",
        )
    coverage_level = _normalize_coverage_level(row.get("coverage_level") or row.get("coverage"))
    name = _strip_or_none(str(row.get("name") or row.get("control_name") or "")) or technique_id
    return {
        "control_id": _strip_or_none(str(row.get("id") or row.get("control_id") or "")),
        "name": name,
        "technique_id": technique_id,
        "technique_name": _strip_or_none(str(row.get("technique_name") or "")),
        "source_type": _strip_or_none(str(row.get("source_type") or "")),
        "coverage_level": coverage_level,
        "environment": _strip_or_none(str(row.get("environment") or "")),
        "owner": _strip_or_none(str(row.get("owner") or "")),
        "evidence_ref": _strip_or_none(str(row.get("evidence_ref") or "")),
        "notes": _strip_or_none(str(row.get("notes") or "")),
        "last_verified_at": _strip_or_none(str(row.get("last_verified_at") or "")),
    }


def _normalize_coverage_level(value: object) -> str:
    normalized = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    if normalized not in DETECTION_COVERAGE_LEVELS:
        raise HTTPException(status_code=422, detail=f"Unsupported coverage level: {value!r}.")
    return normalized


def _coverage_gap_payload(
    contexts: list[Any],
    controls: list[Any],
    findings: list[Any],
) -> dict[str, Any]:
    finding_by_id = {finding.id: finding for finding in findings}
    controls_by_technique: dict[str, list[Any]] = {}
    for control in controls:
        controls_by_technique.setdefault(control.technique_id, []).append(control)
    rollups: dict[str, dict[str, Any]] = {}
    for context in contexts:
        if not context.mapped:
            continue
        for technique in context.techniques_json or []:
            if not isinstance(technique, dict):
                continue
            technique_id = _technique_id_from_dict(technique)
            if technique_id is None:
                continue
            rollup = rollups.setdefault(
                technique_id,
                {
                    "technique_id": technique_id,
                    "name": _technique_name_from_dict(technique),
                    "tactic_ids": _tactic_ids_from_dict(technique),
                    "finding_ids": set(),
                    "critical_finding_count": 0,
                    "kev_finding_count": 0,
                },
            )
            rollup["finding_ids"].add(context.finding_id)
            finding = finding_by_id.get(context.finding_id)
            if finding is not None and finding.priority.lower() == "critical":
                rollup["critical_finding_count"] += 1
            if finding is not None and finding.in_kev:
                rollup["kev_finding_count"] += 1
    for technique_id, technique_controls in controls_by_technique.items():
        if technique_id in rollups:
            continue
        first_control = technique_controls[0] if technique_controls else None
        rollups[technique_id] = {
            "technique_id": technique_id,
            "name": first_control.technique_name if first_control else None,
            "tactic_ids": [],
            "finding_ids": set(),
            "critical_finding_count": 0,
            "kev_finding_count": 0,
        }
    items = []
    for technique_id, rollup in sorted(rollups.items()):
        technique_controls = controls_by_technique.get(technique_id, [])
        coverage_level = _rollup_coverage_level(technique_controls)
        evidence_refs = [
            control.evidence_ref for control in technique_controls if control.evidence_ref
        ]
        owner = next((control.owner for control in technique_controls if control.owner), None)
        items.append(
            {
                "technique_id": technique_id,
                "name": rollup["name"],
                "tactic_ids": list(rollup["tactic_ids"]),
                "finding_count": len(rollup["finding_ids"]),
                "critical_finding_count": int(rollup["critical_finding_count"]),
                "kev_finding_count": int(rollup["kev_finding_count"]),
                "coverage_level": coverage_level,
                "control_count": len(technique_controls),
                "owner": owner,
                "evidence_refs": evidence_refs,
                "recommended_action": _coverage_recommended_action(coverage_level),
            }
        )
    summary: dict[str, int] = {level: 0 for level in sorted(DETECTION_COVERAGE_LEVELS)}
    for item in items:
        summary[item["coverage_level"]] = summary.get(item["coverage_level"], 0) + 1
    return {"items": items, "summary": summary}


def _rollup_coverage_level(controls: list[Any]) -> str:
    levels = {control.coverage_level for control in controls}
    if not levels:
        return "unknown"
    if "covered" in levels:
        return "covered"
    if "partial" in levels:
        return "partial"
    if "not_covered" in levels:
        return "not_covered"
    if "unknown" in levels:
        return "unknown"
    return "not_applicable"


def _coverage_recommended_action(level: str) -> str:
    if level == "covered":
        return "Maintain detection evidence and keep verification current."
    if level == "partial":
        return "Review partial coverage and add compensating telemetry or analytics."
    if level == "not_covered":
        return "Prioritize defensive coverage or document compensating controls."
    if level == "not_applicable":
        return "Keep not-applicable rationale documented for review."
    return "Treat coverage as unknown until an owner verifies detection evidence."


def _coverage_gap_score(level: str) -> int:
    return {"not_covered": 100, "unknown": 80, "partial": 60}.get(level, 0)


def _technique_id_from_dict(technique: dict[str, Any]) -> str | None:
    value = (
        technique.get("attack_object_id")
        or technique.get("technique_id")
        or technique.get("external_id")
        or technique.get("id")
    )
    return str(value) if value else None


def _technique_name_from_dict(technique: dict[str, Any]) -> str | None:
    value = (
        technique.get("attack_object_name")
        or technique.get("technique_name")
        or technique.get("name")
    )
    return str(value) if value else None


def _tactic_ids_from_dict(technique: dict[str, Any]) -> list[str]:
    raw = technique.get("tactic_ids") or technique.get("tactics") or []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(item) for item in raw if item]
    return []


def _technique_metadata_from_contexts(contexts: list[Any], technique_id: str) -> dict[str, Any]:
    for context in contexts:
        for technique in context.techniques_json or []:
            if not isinstance(technique, dict):
                continue
            if _technique_id_from_dict(technique) == technique_id:
                return {
                    "name": _technique_name_from_dict(technique),
                    "tactics": _tactic_ids_from_dict(technique),
                    "deprecated": bool(technique.get("deprecated")),
                    "revoked": bool(technique.get("revoked")),
                }
    return {"name": None, "tactics": [], "deprecated": False, "revoked": False}


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


def _asset_payload(asset: Any, *, finding_count: int = 0) -> dict[str, Any]:
    return {
        "id": asset.id,
        "project_id": asset.project_id,
        "asset_id": asset.asset_id,
        "target_ref": asset.target_ref,
        "owner": asset.owner,
        "business_service": asset.business_service,
        "environment": asset.environment,
        "exposure": asset.exposure,
        "criticality": asset.criticality,
        "finding_count": finding_count,
    }


def _waiver_payload(waiver: Any, *, matched_findings: int = 0) -> dict[str, Any]:
    status, days_remaining = _waiver_status(waiver)
    return {
        "id": waiver.id,
        "project_id": waiver.project_id,
        "cve_id": waiver.cve_id,
        "finding_id": waiver.finding_id,
        "asset_id": waiver.asset_id,
        "component_name": waiver.component_name,
        "component_version": waiver.component_version,
        "service": waiver.service,
        "owner": waiver.owner,
        "reason": waiver.reason,
        "expires_on": waiver.expires_on,
        "review_on": waiver.review_on,
        "approval_ref": waiver.approval_ref,
        "ticket_url": waiver.ticket_url,
        "status": status,
        "days_remaining": days_remaining,
        "matched_findings": matched_findings,
        "created_at": waiver.created_at.isoformat(),
        "updated_at": waiver.updated_at.isoformat(),
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


def _detection_control_payload(control: Any) -> dict[str, Any]:
    return {
        "id": control.id,
        "project_id": control.project_id,
        "control_id": control.control_id,
        "name": control.name,
        "technique_id": control.technique_id,
        "technique_name": control.technique_name,
        "source_type": control.source_type,
        "coverage_level": control.coverage_level,
        "environment": control.environment,
        "owner": control.owner,
        "evidence_ref": control.evidence_ref,
        "notes": control.notes,
        "last_verified_at": control.last_verified_at,
    }


def _provider_update_job_payload(job: Any) -> dict[str, Any]:
    return {
        "id": job.id,
        "status": job.status,
        "requested_sources": list(job.requested_sources_json or []),
        "started_at": job.started_at.isoformat(),
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "error_message": job.error_message,
        "metadata": job.metadata_json or {},
    }


def _project_config_payload(snapshot: Any) -> dict[str, Any]:
    return {
        "id": snapshot.id,
        "project_id": snapshot.project_id,
        "source": snapshot.source,
        "config": snapshot.config_json or {},
        "created_at": snapshot.created_at.isoformat(),
    }


def _github_export_token(token_env: str) -> str:
    env_name = token_env.strip()
    if not ENV_NAME_RE.fullmatch(env_name):
        raise HTTPException(
            status_code=422,
            detail="token_env must be an environment variable name.",
        )
    token = os.getenv(env_name)
    if not token:
        raise HTTPException(status_code=422, detail=f"{env_name} is not configured.")
    return token


def _github_repository_path(repository: str) -> str:
    if not GITHUB_REPOSITORY_RE.fullmatch(repository):
        raise HTTPException(status_code=422, detail="repository must use owner/name format.")
    owner, name = repository.split("/", 1)
    return f"{quote(owner, safe='')}/{quote(name, safe='')}"


def _create_github_issue(
    *,
    repository_path: str,
    token: str,
    item: dict[str, Any],
) -> dict[str, Any]:
    issue_payload: dict[str, Any] = {
        "title": item["title"],
        "body": (
            item["body"]
            + "\n\n"
            + f"<!-- vuln-prioritizer duplicate_key: {item['duplicate_key']} -->"
        ),
        "labels": item["labels"],
    }
    milestone = item.get("milestone")
    if isinstance(milestone, str) and milestone.isdigit():
        issue_payload["milestone"] = int(milestone)
    try:
        response = requests.post(
            f"https://api.github.com/repos/{repository_path}/issues",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "vuln-prioritizer-workbench",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json=issue_payload,
            timeout=10,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail="GitHub issue creation failed.") from exc
    if response.status_code != 201:
        raise HTTPException(
            status_code=502,
            detail=f"GitHub issue creation failed with status {response.status_code}.",
        )
    response_payload = response.json()
    return {
        "html_url": str(response_payload.get("html_url") or ""),
        "number": int(response_payload.get("number") or 0),
    }


def _github_issue_preview_payload(
    finding: Any, *, payload: GitHubIssuePreviewRequest
) -> dict[str, Any]:
    labels = [
        payload.label_prefix,
        f"{payload.label_prefix}:priority-{finding.priority.lower()}",
        "security",
    ]
    if finding.in_kev:
        labels.append(f"{payload.label_prefix}:kev")
    title = f"{finding.cve_id}: {finding.priority} priority remediation"
    body = "\n".join(
        [
            "## Finding",
            f"- CVE: `{finding.cve_id}`",
            f"- Priority: `{finding.priority}`",
            f"- Operational rank: `{finding.operational_rank}`",
            f"- Component: `{finding.component.name if finding.component else 'N.A.'}`",
            f"- Asset: `{finding.asset.asset_id if finding.asset else 'N.A.'}`",
            f"- Owner: `{finding.asset.owner if finding.asset else 'N.A.'}`",
            "",
            "## Why now",
            finding.rationale or "No rationale captured.",
            "",
            "## Recommended action",
            finding.recommended_action or "Review and remediate according to policy.",
            "",
            "Generated as a dry-run Workbench issue preview. Review before creating issues.",
        ]
    )
    return {
        "title": title,
        "body": body,
        "labels": labels,
        "milestone": payload.milestone,
        "duplicate_key": f"{finding.project_id}:{finding.cve_id}:{finding.asset_id or 'no-asset'}",
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
