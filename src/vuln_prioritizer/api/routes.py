"""JSON API routes for the Workbench MVP."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
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
from vuln_prioritizer.api.workbench_detection import (
    WEAK_DETECTION_COVERAGE_LEVELS,
    _coverage_gap_payload,
    _coverage_gap_score,
    _detection_control_payload,
    _parse_detection_control_rows,
    _technique_id_from_dict,
    _technique_metadata_from_contexts,
)
from vuln_prioritizer.api.workbench_findings import _filter_findings, _sort_findings
from vuln_prioritizer.api.workbench_github import (
    _create_github_issue,
    _github_export_token,
    _github_issue_preview_payload,
    _github_repository_path,
)
from vuln_prioritizer.api.workbench_payloads import (
    _analysis_run_payload,
    _asset_payload,
    _attack_context_payload,
    _evidence_bundle_payload,
    _finding_payload,
    _governance_payload,
    _project_config_payload,
    _project_payload,
    _report_payload,
)
from vuln_prioritizer.api.workbench_providers import (
    _create_provider_update_job_record,
    _provider_status_payload,
    _provider_update_job_payload,
)
from vuln_prioritizer.api.workbench_uploads import (
    _artifact_response,
    _cleanup_saved_uploads,
    _read_bounded_upload,
    _resolve_attack_artifact_path,
    _resolve_download_artifact,
    _resolve_provider_snapshot_path,
    _save_optional_context_upload,
    _save_upload,
)
from vuln_prioritizer.api.workbench_waivers import (
    _count_matching_waiver_findings,
    _strip_or_none,
    _sync_project_waivers,
    _validated_waiver_values,
    _waiver_payload,
)
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.runtime_config import RuntimeConfigDocument
from vuln_prioritizer.services.workbench_analysis import (
    WorkbenchAnalysisError,
    run_workbench_import,
)
from vuln_prioritizer.services.workbench_attack import (
    navigator_layer_from_contexts,
    top_technique_rows,
)
from vuln_prioritizer.services.workbench_executive_report import (
    WorkbenchExecutiveReportError,
    build_run_executive_report_model,
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

API_TOKEN_PREFIX = "vpr_"


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


@api_router.get("/analysis-runs/{run_id}/executive-report")
def get_run_executive_report(
    run_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    run = repo.get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found.")
    project = repo.get_project(run.project_id)
    try:
        return build_run_executive_report_model(repo=repo, run=run, project=project)
    except WorkbenchExecutiveReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


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
