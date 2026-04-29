"""Template import upload API routes."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from sqlmodel import Session

from app.api.deps import CurrentUser, SessionDep
from app.api.routes.workbench_access import require_visible_project
from app.core.config import Settings
from app.importers import (
    ImporterParseError,
    ImporterValidationError,
    UnsupportedInputTypeError,
    build_importer_registry,
)
from app.importers.contracts import NormalizedOccurrence
from app.models import (
    AnalysisRun,
    AnalysisRunPublic,
    AnalysisRunStatus,
    AssetCriticality,
    AssetEnvironment,
    AssetExposure,
    FindingAttackContext,
    FindingPriority,
    FindingStatus,
)
from app.models.base import get_datetime_utc
from app.repositories import AssetRepository, FindingRepository, RunRepository
from app.services import AnalysisService, TemplateAnalysisError, TemplateAnalysisResult
from vuln_prioritizer.cli_options import AttackSource
from vuln_prioritizer.inputs._occurrence_support import apply_asset_context
from vuln_prioritizer.inputs.loader import load_asset_context_file
from vuln_prioritizer.models import InputOccurrence, PrioritizedFinding

router = APIRouter(tags=["imports"])

ALLOWED_UPLOAD_SUFFIXES = {
    "cve-list": {".txt", ".csv"},
    "generic-occurrence-csv": {".csv"},
    "trivy-json": {".json"},
    "grype-json": {".json"},
    "cyclonedx-json": {".json"},
    "spdx-json": {".json"},
    "dependency-check-json": {".json"},
    "github-alerts-json": {".json"},
    "nessus-xml": {".nessus", ".xml"},
    "openvas-xml": {".xml"},
}
ALLOWED_UPLOAD_MIME_HINTS = {
    "cve-list": {"text/plain", "text/csv", "application/vnd.ms-excel"},
    "generic-occurrence-csv": {"text/csv", "text/plain", "application/vnd.ms-excel"},
    "trivy-json": {"application/json", "text/json"},
    "grype-json": {"application/json", "text/json"},
    "cyclonedx-json": {"application/json", "text/json"},
    "spdx-json": {"application/json", "text/json"},
    "dependency-check-json": {"application/json", "text/json"},
    "github-alerts-json": {"application/json", "text/json"},
    "nessus-xml": {"application/xml", "text/xml"},
    "openvas-xml": {"application/xml", "text/xml"},
}
SAFE_ATTACK_FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


@router.post("/projects/{project_id}/imports", response_model=AnalysisRunPublic)
async def import_project_upload(
    project_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    current_user: CurrentUser,
    input_type: str = Form(...),
    file: UploadFile = File(...),
    asset_context_file: UploadFile | None = File(None),
    provider_snapshot_file: str | None = Form(None),
    locked_provider_data: bool = Form(False),
    attack_source: str = Form("none"),
    attack_mapping_file: str | None = Form(None),
    attack_technique_metadata_file: str | None = Form(None),
) -> AnalysisRun:
    """Securely upload, normalize, and persist one Workbench import file."""
    require_visible_project(session, current_user, project_id)
    normalized_input_type = _normalize_input_type(input_type)
    _validate_input_type(normalized_input_type)
    original_filename = file.filename or "upload"
    _reject_unsafe_upload_filename(original_filename)
    stored_filename = _sanitize_filename(original_filename)
    _validate_upload_suffix(stored_filename, input_type=normalized_input_type)
    _validate_mime_hint(file.content_type, input_type=normalized_input_type)
    asset_context_upload = asset_context_file if _has_optional_upload(asset_context_file) else None
    asset_context_original_filename = (
        asset_context_upload.filename if asset_context_upload is not None else None
    )
    asset_context_stored_filename: str | None = None
    if asset_context_upload is not None and asset_context_original_filename is not None:
        _reject_unsafe_upload_filename(asset_context_original_filename)
        asset_context_stored_filename = _sanitize_context_filename(
            asset_context_original_filename,
            reserved_filename=stored_filename,
        )
        _validate_asset_context_upload(asset_context_stored_filename, asset_context_upload)
    provider_snapshot_path = _resolve_template_provider_snapshot_path(
        provider_snapshot_file,
        request=request,
    )
    attack_mapping_path = _resolve_template_attack_artifact_path(
        attack_mapping_file,
        request=request,
    )
    attack_metadata_path = _resolve_template_attack_artifact_path(
        attack_technique_metadata_file,
        request=request,
    )
    normalized_attack_source = _validate_attack_import_options(
        attack_source=attack_source,
        attack_mapping_path=attack_mapping_path,
        attack_metadata_path=attack_metadata_path,
    )

    upload_bytes = await _read_bounded_upload(file, settings=_template_settings(request))
    asset_context_bytes = (
        await _read_bounded_upload(asset_context_upload, settings=_template_settings(request))
        if asset_context_upload is not None
        else None
    )
    upload_sha256 = hashlib.sha256(upload_bytes).hexdigest()
    asset_context_sha256 = (
        hashlib.sha256(asset_context_bytes).hexdigest() if asset_context_bytes is not None else None
    )
    ignored_lines = _ignored_line_count(normalized_input_type, upload_bytes)
    job_id = str(uuid.uuid4())
    job_history = [_job_status_entry("pending")]
    run_repo = RunRepository(session)
    run = run_repo.create_analysis_run(
        project_id=project_id,
        input_type=normalized_input_type,
        filename=stored_filename,
        status=AnalysisRunStatus.PENDING,
        summary_json={
            "import_job": _job_payload(
                job_id=job_id,
                status="pending",
                status_history=job_history,
            ),
            "input_upload": _upload_summary(
                input_type=normalized_input_type,
                original_filename=original_filename,
                stored_filename=stored_filename,
                content_type=file.content_type,
                size_bytes=len(upload_bytes),
                sha256=upload_sha256,
                path=None,
            ),
            "asset_context_upload": _optional_upload_summary(
                input_type="asset-context-csv",
                original_filename=asset_context_original_filename,
                stored_filename=asset_context_stored_filename,
                content_type=asset_context_upload.content_type
                if asset_context_upload is not None
                else None,
                size_bytes=len(asset_context_bytes) if asset_context_bytes is not None else None,
                sha256=asset_context_sha256,
                path=None,
            ),
            "created_findings": 0,
            "updated_findings": 0,
            "ignored_lines": ignored_lines,
            "parse_errors": [],
        },
    )
    upload_path = _store_upload(
        request,
        project_id=project_id,
        run_id=run.id,
        filename=stored_filename,
        content=upload_bytes,
    )
    asset_context_path = (
        _store_upload(
            request,
            project_id=project_id,
            run_id=run.id,
            filename=asset_context_stored_filename or "asset_context.csv",
            content=asset_context_bytes,
        )
        if asset_context_bytes is not None
        else None
    )
    run.status = AnalysisRunStatus.RUNNING
    job_history = [*job_history, _job_status_entry("running")]
    run.summary_json = {
        **run.summary_json,
        "import_job": _job_payload(
            job_id=job_id,
            status="running",
            status_history=job_history,
        ),
        "input_upload": {
            **run.summary_json["input_upload"],
            "path": str(upload_path),
        },
        "asset_context_upload": _upload_summary_with_path(
            run.summary_json.get("asset_context_upload"),
            path=str(asset_context_path) if asset_context_path is not None else None,
        ),
    }
    session.flush()

    try:
        occurrences = build_importer_registry().parse(
            normalized_input_type,
            upload_bytes,
            filename=stored_filename,
        )
    except (ImporterParseError, ImporterValidationError) as exc:
        parse_errors = _parse_errors(
            exc, filename=stored_filename, input_type=normalized_input_type
        )
        failed_history = [*job_history, _job_status_entry("failed")]
        failed_run = run_repo.finish_analysis_run(
            run.id,
            status=AnalysisRunStatus.FAILED,
            error_message=str(exc),
            error_json={
                "parse_errors": parse_errors,
                "created_findings": 0,
                "updated_findings": 0,
                "ignored_lines": ignored_lines,
                "import_job": _job_payload(
                    job_id=job_id,
                    status="failed",
                    status_history=failed_history,
                ),
            },
            summary_json={
                **run.summary_json,
                "import_job": _job_payload(
                    job_id=job_id,
                    status="failed",
                    status_history=failed_history,
                ),
                "parse_errors": parse_errors,
                "created_findings": 0,
                "updated_findings": 0,
                "ignored_lines": ignored_lines,
            },
        )
        session.commit()
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Import parsing failed.",
                "analysis_run_id": str(failed_run.id),
                "ignored_lines": ignored_lines,
                "parse_errors": parse_errors,
            },
        ) from exc

    asset_context_summary: dict[str, Any] | None = None
    if asset_context_path is not None:
        try:
            occurrences, asset_context_summary = _apply_template_asset_context(
                occurrences,
                asset_context_path=asset_context_path,
            )
        except ValueError as exc:
            asset_context_error = {
                "message": str(exc),
                "filename": asset_context_stored_filename,
                "stage": "asset_context_parse",
                "error_type": exc.__class__.__name__,
            }
            failed_history = [*job_history, _job_status_entry("failed")]
            failed_run = run_repo.finish_analysis_run(
                run.id,
                status=AnalysisRunStatus.FAILED,
                error_message=str(exc),
                error_json={
                    "asset_context_error": asset_context_error,
                    "created_findings": 0,
                    "updated_findings": 0,
                    "ignored_lines": ignored_lines,
                    "import_job": _job_payload(
                        job_id=job_id,
                        status="failed",
                        status_history=failed_history,
                    ),
                },
                summary_json={
                    **run.summary_json,
                    "import_job": _job_payload(
                        job_id=job_id,
                        status="failed",
                        status_history=failed_history,
                    ),
                    "asset_context_error": asset_context_error,
                    "parse_errors": [],
                    "created_findings": 0,
                    "updated_findings": 0,
                    "ignored_lines": ignored_lines,
                },
            )
            session.commit()
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "Asset context parsing failed.",
                    "analysis_run_id": str(failed_run.id),
                    "asset_context_error": asset_context_error,
                },
            ) from exc

    try:
        analysis_result = AnalysisService(session, _template_settings(request)).analyze_import(
            input_path=upload_path,
            input_type=normalized_input_type,
            asset_context_file=asset_context_path,
            provider_snapshot_file=provider_snapshot_path,
            locked_provider_data=locked_provider_data,
            attack_source=normalized_attack_source,
            attack_mapping_file=attack_mapping_path,
            attack_technique_metadata_file=attack_metadata_path,
        )
    except TemplateAnalysisError as exc:
        failed_history = [*job_history, _job_status_entry("failed")]
        failed_run = run_repo.finish_analysis_run(
            run.id,
            status=AnalysisRunStatus.FAILED,
            error_message=str(exc),
            error_json={
                "analysis_error": {
                    "message": str(exc),
                    "stage": "enrich_score_explain",
                    "error_type": exc.__class__.__name__,
                },
                "created_findings": 0,
                "updated_findings": 0,
                "ignored_lines": ignored_lines,
                "import_job": _job_payload(
                    job_id=job_id,
                    status="failed",
                    status_history=failed_history,
                ),
            },
            summary_json={
                **run.summary_json,
                "import_job": _job_payload(
                    job_id=job_id,
                    status="failed",
                    status_history=failed_history,
                ),
                "analysis_error": {
                    "message": str(exc),
                    "stage": "enrich_score_explain",
                    "error_type": exc.__class__.__name__,
                },
                "parse_errors": [],
                "created_findings": 0,
                "updated_findings": 0,
                "ignored_lines": ignored_lines,
            },
        )
        session.commit()
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Import analysis failed.",
                "analysis_run_id": str(failed_run.id),
                "ignored_lines": ignored_lines,
                "analysis_error": failed_run.error_json["analysis_error"],
            },
        ) from exc

    persist_summary = _persist_template_occurrences(
        session=session,
        project_id=project_id,
        run_id=run.id,
        occurrences=occurrences,
        analysis_result=analysis_result,
    )
    run.provider_snapshot_id = analysis_result.provider_snapshot_id
    finished_run = run_repo.finish_analysis_run(
        run.id,
        status=AnalysisRunStatus.SUCCEEDED,
        summary_json={
            **run.summary_json,
            "import_job": _job_payload(
                job_id=job_id,
                status="succeeded",
                status_history=[*job_history, _job_status_entry("succeeded")],
            ),
            **analysis_result.summary_json,
            **persist_summary,
            "asset_context": asset_context_summary,
            "ignored_lines": ignored_lines,
            "input_sha256": upload_sha256,
            "parse_errors": [],
        },
    )
    session.commit()
    return finished_run


async def _read_bounded_upload(file: UploadFile, *, settings: Settings) -> bytes:
    total = 0
    chunks: list[bytes] = []
    while chunk := await file.read(1024 * 1024):
        total += len(chunk)
        if total > settings.max_upload_bytes:
            raise HTTPException(
                status_code=413,
                detail="Upload exceeds configured limit.",
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _has_optional_upload(file: UploadFile | None) -> bool:
    return bool(file is not None and file.filename and file.filename.strip())


def _validate_asset_context_upload(filename: str, file: UploadFile) -> None:
    if Path(filename).suffix.lower() != ".csv":
        raise HTTPException(status_code=422, detail="Asset context file must be a CSV.")
    normalized = (file.content_type or "").split(";", maxsplit=1)[0].strip().lower()
    if normalized in {"", "application/octet-stream"}:
        return
    if normalized not in {"text/csv", "text/plain", "application/vnd.ms-excel"}:
        raise HTTPException(
            status_code=422,
            detail="Asset context content type must be text/csv.",
        )


def _sanitize_context_filename(filename: str, *, reserved_filename: str) -> str:
    sanitized = _sanitize_filename(filename)
    if sanitized == reserved_filename:
        return f"asset_context_{sanitized}"
    return sanitized


def _optional_upload_summary(
    *,
    input_type: str,
    original_filename: str | None,
    stored_filename: str | None,
    content_type: str | None,
    size_bytes: int | None,
    sha256: str | None,
    path: str | None,
) -> dict[str, Any] | None:
    if original_filename is None or stored_filename is None or size_bytes is None or sha256 is None:
        return None
    return _upload_summary(
        input_type=input_type,
        original_filename=original_filename,
        stored_filename=stored_filename,
        content_type=content_type,
        size_bytes=size_bytes,
        sha256=sha256,
        path=path,
    )


def _upload_summary_with_path(value: Any, *, path: str | None) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return {**value, "path": path}


def _apply_template_asset_context(
    occurrences: list[NormalizedOccurrence],
    *,
    asset_context_path: Path,
) -> tuple[list[NormalizedOccurrence], dict[str, Any]]:
    catalog, load_diagnostics = load_asset_context_file(
        asset_context_path,
        return_diagnostics=True,
    )
    input_occurrences = [
        _input_occurrence_from_template_occurrence(occurrence) for occurrence in occurrences
    ]
    enriched_occurrences, match_diagnostics = apply_asset_context(
        input_occurrences,
        catalog,
        return_diagnostics=True,
    )
    return (
        [
            _template_occurrence_with_asset_context(original, enriched)
            for original, enriched in zip(occurrences, enriched_occurrences, strict=True)
        ],
        {
            "total_rows": load_diagnostics.total_rows,
            "loaded_rows": load_diagnostics.loaded_rows,
            "skipped_rows": load_diagnostics.skipped_rows,
            "exact_rules": load_diagnostics.exact_rules,
            "contains_rules": load_diagnostics.contains_rules,
            "regex_rules": load_diagnostics.regex_rules,
            "glob_rules": load_diagnostics.glob_rules,
            "matched_occurrences": match_diagnostics.matched_occurrences,
            "unmatched_occurrences": match_diagnostics.unmatched_occurrences,
            "ambiguous_occurrences": match_diagnostics.ambiguous_occurrences,
            "warnings": [
                *load_diagnostics.warnings,
                *match_diagnostics.warnings,
            ],
        },
    )


def _input_occurrence_from_template_occurrence(
    occurrence: NormalizedOccurrence,
) -> InputOccurrence:
    evidence = occurrence.raw_evidence
    fix_versions = [occurrence.fix_version] if occurrence.fix_version else []
    return InputOccurrence(
        cve_id=occurrence.cve,
        source_format=occurrence.source,
        source_id=_string_evidence(evidence, "source_id"),
        source_record_id=_string_evidence(evidence, "source_record_id"),
        component_name=occurrence.component,
        component_version=occurrence.version,
        purl=_string_evidence(evidence, "purl"),
        package_type=_string_evidence(evidence, "package_type"),
        file_path=_string_evidence(evidence, "file_path"),
        dependency_path=_string_evidence(evidence, "dependency_path"),
        fix_versions=fix_versions,
        raw_severity=(
            _string_evidence(evidence, "raw_severity") or _string_evidence(evidence, "severity")
        ),
        target_kind=_string_evidence(evidence, "target_kind") or "generic",
        target_ref=_string_evidence(evidence, "target_ref") or occurrence.asset_ref,
        asset_id=_string_evidence(evidence, "asset_id"),
        asset_criticality=_string_evidence(evidence, "asset_criticality"),
        asset_exposure=_string_evidence(evidence, "asset_exposure")
        or _string_evidence(evidence, "exposure"),
        asset_environment=_string_evidence(evidence, "asset_environment"),
        asset_owner=_string_evidence(evidence, "asset_owner")
        or _string_evidence(evidence, "owner"),
        asset_business_service=_string_evidence(evidence, "asset_business_service")
        or _string_evidence(evidence, "business_service"),
    )


def _template_occurrence_with_asset_context(
    occurrence: NormalizedOccurrence,
    enriched: InputOccurrence,
) -> NormalizedOccurrence:
    evidence = dict(occurrence.raw_evidence)
    updates: dict[str, Any] = {
        "target_kind": enriched.target_kind,
        "target_ref": enriched.target_ref,
        "asset_id": enriched.asset_id,
        "asset_criticality": enriched.asset_criticality,
        "asset_exposure": enriched.asset_exposure,
        "asset_environment": enriched.asset_environment,
        "asset_owner": enriched.asset_owner,
        "asset_business_service": enriched.asset_business_service,
        "owner": enriched.asset_owner,
        "business_service": enriched.asset_business_service,
        "asset_match_rule_id": enriched.asset_match_rule_id,
        "asset_match_row": enriched.asset_match_row,
        "asset_match_mode": enriched.asset_match_mode,
        "asset_match_pattern": enriched.asset_match_pattern,
        "asset_match_precedence": enriched.asset_match_precedence,
        "asset_match_candidate_count": enriched.asset_match_candidate_count,
    }
    evidence.update({key: value for key, value in updates.items() if value not in {None, ""}})
    return NormalizedOccurrence(
        cve=occurrence.cve,
        component=occurrence.component,
        version=occurrence.version,
        asset_ref=enriched.asset_id or occurrence.asset_ref or enriched.target_ref,
        source=occurrence.source,
        fix_version=occurrence.fix_version,
        raw_evidence=evidence,
    )


def _persist_template_occurrences(
    *,
    session: Session,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    occurrences: list[NormalizedOccurrence],
    analysis_result: TemplateAnalysisResult,
) -> dict[str, Any]:
    asset_repo = AssetRepository(session)
    finding_repo = FindingRepository(session)
    run_repo = RunRepository(session)
    decisions: list[dict[str, Any]] = []
    created_count = 0
    reused_count = 0
    touched_finding_ids: set[str] = set()
    attack_context_finding_ids: set[uuid.UUID] = set()
    for index, occurrence in enumerate(occurrences, start=1):
        decision = _decision_for_occurrence(analysis_result, occurrence)
        dedup_parts = _dedup_key_parts(project_id, occurrence)
        dedup_key = _finding_dedup_key(dedup_parts)
        asset = (
            asset_repo.upsert_asset(
                project_id=project_id,
                asset_key=occurrence.asset_ref,
                name=occurrence.asset_ref,
                target_ref=_string_evidence(occurrence.raw_evidence, "target_ref"),
                owner=_string_evidence(occurrence.raw_evidence, "owner"),
                business_service=_string_evidence(
                    occurrence.raw_evidence,
                    "business_service",
                ),
                environment=_asset_environment(occurrence.raw_evidence),
                exposure=_asset_exposure(occurrence.raw_evidence),
                criticality=_asset_criticality(occurrence.raw_evidence),
            )
            if occurrence.asset_ref
            else None
        )
        component = (
            finding_repo.upsert_component(
                name=occurrence.component,
                version=occurrence.version,
                purl=_string_evidence(occurrence.raw_evidence, "purl"),
                ecosystem=_string_evidence(occurrence.raw_evidence, "package_type"),
                package_type=_string_evidence(occurrence.raw_evidence, "package_type"),
            )
            if occurrence.component
            else None
        )
        vulnerability = finding_repo.upsert_vulnerability(
            cve_id=occurrence.cve,
            source_id=dedup_parts["source_id"],
            title=occurrence.cve,
            description=decision.description,
            cvss_score=decision.cvss_base_score,
            cvss_vector=_decision_cvss_vector(decision),
            severity=(
                decision.cvss_severity or _string_evidence(occurrence.raw_evidence, "severity")
            ),
            cwe=_decision_cwe(decision),
            published_at=_decision_published(decision),
            modified_at=_decision_modified(decision),
            provider_json=_decision_provider_json(decision),
        )
        existing_finding = finding_repo.get_project_finding_by_dedup_key(
            project_id=project_id,
            dedup_key=dedup_key,
        )
        if existing_finding is None:
            existing_finding = finding_repo.get_project_finding_by_identity(
                project_id=project_id,
                vulnerability_id=vulnerability.id,
                component_id=component.id if component else None,
                asset_id=asset.id if asset else None,
            )
        action = "reused" if existing_finding is not None else "created"
        finding = finding_repo.create_or_update_finding(
            project_id=project_id,
            vulnerability_id=vulnerability.id,
            cve_id=occurrence.cve,
            dedup_key=dedup_key,
            component_id=component.id if component else None,
            asset_id=asset.id if asset else None,
            status=_decision_status(decision),
            priority=_decision_priority(decision),
            priority_rank=decision.priority_rank,
            risk_score=float(decision.operational_score),
            operational_rank=decision.operational_rank or index,
            in_kev=decision.in_kev,
            epss=decision.epss,
            cvss_base_score=decision.cvss_base_score,
            attack_mapped=decision.attack_mapped,
            suppressed_by_vex=decision.suppressed_by_vex,
            under_investigation=decision.under_investigation,
            waived=decision.waived,
            recommended_action=decision.recommended_action,
            rationale=decision.rationale,
            explanation_json=decision.model_dump(),
            data_quality_json=_decision_data_quality_json(decision),
            evidence_json={
                "import": dict(occurrence.raw_evidence),
                "analysis": {
                    "priority_state": decision.priority_state,
                    "operational_score": decision.operational_score,
                    "provider_snapshot_id": str(analysis_result.provider_snapshot_id)
                    if analysis_result.provider_snapshot_id is not None
                    else None,
                    "provider_snapshot_hash": analysis_result.provider_snapshot_hash,
                },
                "dedup": {
                    "key": dedup_key,
                    "key_version": "vpw019-v1",
                    "action": action,
                    "parts": dedup_parts,
                },
            },
        )
        if finding.id not in attack_context_finding_ids and _attack_context_enabled(
            analysis_result,
            decision,
        ):
            _persist_template_finding_attack_context(
                session=session,
                run_id=run_id,
                finding_id=finding.id,
                decision=decision,
            )
            attack_context_finding_ids.add(finding.id)
        if action == "created":
            created_count += 1
        else:
            reused_count += 1
        touched_finding_ids.add(str(finding.id))
        run_repo.add_finding_occurrence(
            finding_id=finding.id,
            analysis_run_id=run_id,
            source=occurrence.source,
            raw_reference=_string_evidence(occurrence.raw_evidence, "source_record_id"),
            fix_version=occurrence.fix_version,
            evidence_json={
                **dict(occurrence.raw_evidence),
                "dedup_key": dedup_key,
                "dedup_action": action,
            },
        )
        decisions.append(
            {
                "action": action,
                "dedup_key": dedup_key,
                "finding_id": str(finding.id),
                "cve": occurrence.cve,
                "source_id": dedup_parts["source_id"],
                "component_identity": dedup_parts["component_identity"],
                "asset_ref": dedup_parts["asset_ref"],
            }
        )

    return {
        "occurrence_count": len(occurrences),
        "finding_count": len(touched_finding_ids),
        "created_findings": created_count,
        "updated_findings": reused_count,
        "dedup_summary": {
            "key_version": "vpw019-v1",
            "created_findings": created_count,
            "updated_findings": reused_count,
            "reused_findings": reused_count,
            "decision_count": len(decisions),
            "decisions": decisions,
        },
    }


def _attack_context_enabled(
    analysis_result: TemplateAnalysisResult,
    decision: PrioritizedFinding,
) -> bool:
    return analysis_result.context.attack_source != "none" or decision.attack_context.mapped


def _persist_template_finding_attack_context(
    *,
    session: Session,
    run_id: uuid.UUID,
    finding_id: uuid.UUID,
    decision: PrioritizedFinding,
) -> None:
    context = decision.attack_context
    mappings = _attack_mapping_payloads(context.mappings, context.techniques)
    techniques = [technique.model_dump() for technique in context.techniques]
    technique_ids = _technique_ids_from_context(techniques, mappings, context.techniques)
    session.add(
        FindingAttackContext(
            finding_id=finding_id,
            analysis_run_id=run_id,
            cve_id=decision.cve_id,
            mapped=context.mapped,
            source=context.source or "none",
            review_status=_attack_context_review_status(
                getattr(context, "review_status", None),
                context.mapped,
                mappings,
            ),
            defensive_note=_attack_context_defensive_note(context.mapped),
            rationale=context.rationale,
            technique_ids_json=technique_ids,
            tactic_ids_json=_valid_attack_tactic_ids(context.tactics),
            mappings_json=mappings,
        )
    )


def _attack_mapping_payloads(mappings: list[Any], techniques: list[Any]) -> list[dict[str, Any]]:
    techniques_by_id = {
        technique.attack_object_id: technique.model_dump()
        for technique in techniques
        if getattr(technique, "attack_object_id", None)
    }
    payloads: list[dict[str, Any]] = []
    for mapping in mappings:
        payload = mapping.model_dump()
        technique = techniques_by_id.get(payload.get("attack_object_id"))
        if technique:
            payload["technique"] = technique
            payload["tactics"] = technique.get("tactics", [])
            payload["technique_url"] = technique.get("url")
        payloads.append(payload)
    return payloads


def _technique_ids_from_context(
    techniques: list[dict[str, Any]],
    mappings: list[dict[str, Any]],
    technique_models: list[Any],
) -> list[str]:
    ids: list[str] = []
    for technique in techniques:
        candidate = _string_evidence(technique, "attack_object_id")
        if candidate and candidate not in ids:
            ids.append(candidate)
    for mapping in mappings:
        candidate = _string_evidence(mapping, "attack_object_id")
        if candidate and candidate not in ids:
            ids.append(candidate)
    for technique in technique_models:
        candidate = getattr(technique, "attack_object_id", None)
        if isinstance(candidate, str) and candidate and candidate not in ids:
            ids.append(candidate)
    return ids


def _valid_attack_tactic_ids(values: list[str]) -> list[str]:
    return [value for value in values if re.fullmatch(r"TA\d{4}", value)]


def _attack_context_review_status(
    review_status: str | None,
    mapped: bool,
    mappings: list[dict[str, Any]],
) -> str:
    mapping_statuses = {
        status
        for mapping in mappings
        if isinstance(status := mapping.get("review_status"), str)
        and status in {"unreviewed", "needs_review", "reviewed", "rejected", "stale"}
    }
    for status in ("needs_review", "stale", "rejected", "unreviewed"):
        if status in mapping_statuses:
            return status
    if review_status in {"unreviewed", "needs_review", "reviewed", "rejected", "stale"}:
        return review_status
    return "reviewed" if mapped else "unreviewed"


def _attack_context_defensive_note(mapped: bool) -> str:
    if mapped:
        return (
            "Use this ATT&CK context only for defensive triage, detection coverage, "
            "and mitigation review."
        )
    return "No reviewed ATT&CK mapping is stored for this finding."


def _dedup_key_parts(project_id: uuid.UUID, occurrence: NormalizedOccurrence) -> dict[str, str]:
    source_id = _normalized_identity_value(
        _string_evidence(occurrence.raw_evidence, "source_id")
        or _string_evidence(occurrence.raw_evidence, "vulnerability_id")
        or occurrence.cve
    )
    purl = _normalized_identity_value(_string_evidence(occurrence.raw_evidence, "purl"))
    component_identity = purl
    if component_identity == "__none__" and occurrence.component:
        component_identity = "|".join(
            [
                "component",
                _normalized_identity_value(occurrence.component),
                _normalized_identity_value(occurrence.version),
                _normalized_identity_value(
                    _string_evidence(occurrence.raw_evidence, "package_type")
                ),
            ]
        )
    return {
        "project_id": str(project_id),
        "source_id": source_id,
        "component_identity": component_identity,
        "asset_ref": _normalized_identity_value(occurrence.asset_ref),
    }


def _finding_dedup_key(parts: Mapping[str, str]) -> str:
    material = json.dumps(parts, sort_keys=True, separators=(",", ":"))
    return "vpw019:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def _normalized_identity_value(value: str | None) -> str:
    if value is None:
        return "__none__"
    normalized = value.strip()
    return normalized or "__none__"


def _decision_for_occurrence(
    analysis_result: TemplateAnalysisResult,
    occurrence: NormalizedOccurrence,
) -> PrioritizedFinding:
    decision = analysis_result.findings_by_cve.get(occurrence.cve)
    if decision is None:
        raise TemplateAnalysisError(f"Decision analysis did not produce {occurrence.cve}.")
    return decision


def _decision_priority(decision: PrioritizedFinding) -> FindingPriority:
    return FindingPriority(decision.priority_label.lower())


def _decision_status(decision: PrioritizedFinding) -> FindingStatus:
    if decision.suppressed_by_vex:
        return FindingStatus.SUPPRESSED
    if decision.waived:
        return FindingStatus.ACCEPTED
    return FindingStatus.OPEN


def _decision_provider_json(decision: PrioritizedFinding) -> dict[str, Any]:
    return decision.provider_evidence.model_dump() if decision.provider_evidence else {}


def _decision_cvss_vector(decision: PrioritizedFinding) -> str | None:
    if decision.provider_evidence is None:
        return None
    return decision.provider_evidence.nvd.cvss_vector


def _decision_cwe(decision: PrioritizedFinding) -> str | None:
    if decision.provider_evidence is None or not decision.provider_evidence.nvd.cwes:
        return None
    return ", ".join(decision.provider_evidence.nvd.cwes)


def _decision_published(decision: PrioritizedFinding) -> str | None:
    if decision.provider_evidence is None:
        return None
    return decision.provider_evidence.nvd.published


def _decision_modified(decision: PrioritizedFinding) -> str | None:
    if decision.provider_evidence is None:
        return None
    return decision.provider_evidence.nvd.last_modified


def _decision_data_quality_json(decision: PrioritizedFinding) -> dict[str, Any]:
    return {
        "flags": [item.model_dump() for item in decision.data_quality_flags],
        "confidence": decision.data_quality_confidence,
    }


def _resolve_template_provider_snapshot_path(
    provider_snapshot_file: str | None,
    *,
    request: Request,
) -> Path | None:
    value = provider_snapshot_file.strip() if provider_snapshot_file else ""
    if not value:
        return None
    if "/" in value or "\\" in value or Path(value).name != value:
        raise HTTPException(status_code=422, detail="Provider snapshot path is not allowed.")
    snapshot_root = _template_settings(request).provider_snapshot_dir_path.resolve(strict=False)
    candidate = (snapshot_root / value).resolve(strict=False)
    if not candidate.is_relative_to(snapshot_root):
        raise HTTPException(status_code=422, detail="Provider snapshot path is not allowed.")
    if not candidate.exists():
        raise HTTPException(status_code=422, detail="Provider snapshot file does not exist.")
    return candidate


def _resolve_template_attack_artifact_path(
    value: str | None,
    *,
    request: Request,
) -> Path | None:
    filename = value.strip() if value else ""
    if not filename:
        return None
    if (
        not SAFE_ATTACK_FILENAME_RE.fullmatch(filename)
        or "/" in filename
        or "\\" in filename
        or Path(filename).name != filename
    ):
        raise HTTPException(status_code=422, detail="ATT&CK artifact path is not allowed.")
    artifact_root = _template_settings(request).attack_artifact_dir_path.resolve(strict=False)
    candidate = (artifact_root / filename).resolve(strict=False)
    if not candidate.is_relative_to(artifact_root):
        raise HTTPException(status_code=422, detail="ATT&CK artifact path is not allowed.")
    if not candidate.exists() or not candidate.is_file():
        raise HTTPException(status_code=422, detail="ATT&CK artifact file does not exist.")
    return candidate


def _validate_attack_import_options(
    *,
    attack_source: str,
    attack_mapping_path: Path | None,
    attack_metadata_path: Path | None,
) -> AttackSource:
    raw_source = attack_source.strip() if attack_source else "none"
    try:
        normalized_source = AttackSource(raw_source)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported ATT&CK source: {raw_source}.",
        ) from exc
    if normalized_source == AttackSource.none:
        if attack_mapping_path is not None or attack_metadata_path is not None:
            raise HTTPException(
                status_code=422,
                detail="ATT&CK mapping files require attack_source=ctid-json.",
            )
        return normalized_source
    if normalized_source not in {AttackSource.ctid_json, AttackSource.local_curated}:
        raise HTTPException(
            status_code=422,
            detail="Template Workbench ATT&CK imports only support ctid-json or local-curated.",
        )
    if attack_mapping_path is None:
        raise HTTPException(
            status_code=422,
            detail="ATT&CK imports require a mapping file.",
        )
    return normalized_source


def _store_upload(
    request: Request,
    *,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    filename: str,
    content: bytes,
) -> Path:
    upload_root = _template_settings(request).import_upload_dir_path.resolve(strict=False)
    target_dir = upload_root / str(project_id) / str(run_id)
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = (target_dir / filename).resolve(strict=False)
    if not target_path.is_relative_to(upload_root):
        raise HTTPException(status_code=422, detail="Upload path is not allowed.")
    try:
        with target_path.open("wb") as output:
            output.write(content)
    except Exception:
        shutil.rmtree(target_dir, ignore_errors=True)
        raise
    return target_path


def _upload_summary(
    *,
    input_type: str,
    original_filename: str,
    stored_filename: str,
    content_type: str | None,
    size_bytes: int,
    sha256: str,
    path: str | None,
) -> dict[str, Any]:
    return {
        "input_type": input_type,
        "original_filename": original_filename,
        "stored_filename": stored_filename,
        "content_type": content_type,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "path": path,
    }


def _job_payload(
    *,
    job_id: str,
    status: str,
    status_history: list[dict[str, str]],
) -> dict[str, Any]:
    timestamp = get_datetime_utc().isoformat()
    return {
        "id": job_id,
        "status": status,
        "updated_at": timestamp,
        "status_history": status_history,
    }


def _job_status_entry(status: str) -> dict[str, str]:
    return {
        "status": status,
        "created_at": get_datetime_utc().isoformat(),
    }


def _parse_errors(
    exc: Exception,
    *,
    filename: str,
    input_type: str,
) -> list[dict[str, Any]]:
    message = str(exc)
    row_prefix = "generic-occurrence-csv row errors: "
    messages = (
        [item.strip() for item in message.removeprefix(row_prefix).split(";") if item.strip()]
        if message.startswith(row_prefix)
        else [message]
    )
    return [
        _parse_error_payload(
            item,
            filename=filename,
            input_type=input_type,
            error_type=exc.__class__.__name__,
        )
        for item in messages
    ]


def _parse_error_payload(
    message: str,
    *,
    filename: str,
    input_type: str,
    error_type: str,
) -> dict[str, Any]:
    return {
        "input_type": input_type,
        "filename": filename,
        "message": message,
        "error_type": error_type,
        "line": _parse_error_line(message),
        "field": _parse_error_field(message),
        "value": _parse_error_value(message),
    }


def _parse_error_line(message: str) -> int | None:
    match = re.search(r"\bline (?P<line>\d+)\b", message)
    return int(match.group("line")) if match else None


def _parse_error_field(message: str) -> str | None:
    lower_message = message.lower()
    if "cve_id column" in lower_message:
        return "cve_id"
    if "cve identifier" in lower_message:
        return "cve_id"
    return None


def _parse_error_value(message: str) -> str | None:
    match = re.search(r"(?P<quote>['\"])(?P<value>.+?)(?P=quote)", message)
    return match.group("value") if match else None


def _ignored_line_count(input_type: str, payload: bytes) -> int:
    if input_type not in {"cve-list", "generic-occurrence-csv"}:
        return 0
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return 0
    return sum(1 for line in text.splitlines() if _is_ignored_text_line(line))


def _is_ignored_text_line(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def _validate_input_type(input_type: str) -> None:
    try:
        build_importer_registry().get(input_type)
    except UnsupportedInputTypeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _validate_upload_suffix(filename: str, *, input_type: str) -> None:
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_UPLOAD_SUFFIXES.get(input_type, set()):
        raise HTTPException(status_code=422, detail="File extension does not match input type.")


def _validate_mime_hint(content_type: str | None, *, input_type: str) -> None:
    normalized = (content_type or "").split(";", maxsplit=1)[0].strip().lower()
    if normalized in {"", "application/octet-stream"}:
        return
    if normalized not in ALLOWED_UPLOAD_MIME_HINTS.get(input_type, set()):
        raise HTTPException(
            status_code=422, detail="Upload content type does not match input type."
        )


def _reject_unsafe_upload_filename(filename: str) -> None:
    if "/" in filename or "\\" in filename or Path(filename).name != filename:
        raise HTTPException(status_code=422, detail="Upload filename is not allowed.")
    if any(ord(character) < 32 for character in filename):
        raise HTTPException(status_code=422, detail="Upload filename is not allowed.")


def _sanitize_filename(filename: str) -> str:
    name = Path(filename).name.strip() or "upload"
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return sanitized or "upload"


def _normalize_input_type(input_type: str) -> str:
    normalized = input_type.strip().lower()
    if not normalized:
        raise HTTPException(status_code=422, detail="input_type is required.")
    return normalized


def _template_settings(request: Request) -> Settings:
    candidate = getattr(request.app.state, "template_settings", None)
    if isinstance(candidate, Settings):
        return candidate
    raise HTTPException(status_code=500, detail="Template settings are not configured.")


def _string_evidence(evidence: Mapping[str, Any], key: str) -> str | None:
    value = evidence.get(key)
    return str(value) if value else None


def _asset_exposure(evidence: Mapping[str, Any]) -> AssetExposure:
    raw = _string_evidence(evidence, "asset_exposure")
    if raw is None:
        return AssetExposure.UNKNOWN
    normalized = raw.strip().lower().replace("_", "-")
    aliases = {
        "external": AssetExposure.INTERNET_FACING,
        "internet": AssetExposure.INTERNET_FACING,
        "internet-facing": AssetExposure.INTERNET_FACING,
        "public": AssetExposure.INTERNET_FACING,
        "internal": AssetExposure.INTERNAL,
        "private": AssetExposure.PRIVATE,
        "unknown": AssetExposure.UNKNOWN,
    }
    return aliases.get(normalized, AssetExposure.UNKNOWN)


def _asset_environment(evidence: Mapping[str, Any]) -> AssetEnvironment:
    raw = _string_evidence(evidence, "asset_environment")
    if raw is None:
        return AssetEnvironment.UNKNOWN
    normalized = raw.strip().lower().replace("_", "-")
    aliases = {
        "prod": AssetEnvironment.PRODUCTION,
        "production": AssetEnvironment.PRODUCTION,
        "stage": AssetEnvironment.STAGING,
        "staging": AssetEnvironment.STAGING,
        "dev": AssetEnvironment.DEVELOPMENT,
        "development": AssetEnvironment.DEVELOPMENT,
        "test": AssetEnvironment.TEST,
        "testing": AssetEnvironment.TEST,
        "unknown": AssetEnvironment.UNKNOWN,
    }
    return aliases.get(normalized, AssetEnvironment.UNKNOWN)


def _asset_criticality(evidence: Mapping[str, Any]) -> AssetCriticality:
    raw = _string_evidence(evidence, "asset_criticality")
    if raw is None:
        return AssetCriticality.UNKNOWN
    normalized = raw.strip().lower().replace("_", "-")
    aliases = {
        "critical": AssetCriticality.CRITICAL,
        "high": AssetCriticality.HIGH,
        "medium": AssetCriticality.MEDIUM,
        "med": AssetCriticality.MEDIUM,
        "low": AssetCriticality.LOW,
        "unknown": AssetCriticality.UNKNOWN,
    }
    return aliases.get(normalized, AssetCriticality.UNKNOWN)
