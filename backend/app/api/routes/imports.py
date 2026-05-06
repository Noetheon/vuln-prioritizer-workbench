"""Template import upload API routes."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from sqlalchemy import insert
from sqlmodel import Session, col, select

from app.api.deps import ScopedImportUser, SessionDep
from app.api.routes.workbench_access import require_visible_project
from app.domain.import_asset_context import (
    asset_criticality_from_evidence as _asset_criticality,
)
from app.domain.import_asset_context import (
    asset_environment_from_evidence as _asset_environment,
)
from app.domain.import_asset_context import asset_exposure_from_evidence as _asset_exposure
from app.domain.import_asset_context import (
    canonicalize_occurrence_asset_context as _canonicalize_occurrence_asset_context,
)
from app.domain.import_asset_context import (
    input_occurrence_from_template_occurrence as _input_occurrence_from_template_occurrence,
)
from app.domain.import_asset_context import string_evidence as _string_evidence
from app.domain.import_asset_context import (
    template_occurrence_with_asset_context as _template_occurrence_with_asset_context,
)
from app.domain.import_asset_context import (
    template_occurrence_with_vex as _template_occurrence_with_vex,
)
from app.importers import ImporterParseError, ImporterValidationError, build_importer_registry
from app.importers.contracts import NormalizedOccurrence
from app.models import (
    AnalysisRun,
    AnalysisRunPublic,
    AnalysisRunStatus,
    Asset,
    Finding,
    FindingAttackContext,
    FindingOccurrence,
    FindingPriority,
    FindingStatus,
    User,
    Vulnerability,
)
from app.models.base import get_datetime_utc
from app.repositories import AssetRepository, FindingRepository, RunRepository
from app.services import AnalysisService, TemplateAnalysisError, TemplateAnalysisResult
from app.services.audit import record_audit_event
from app.services.import_artifacts import (
    resolve_template_attack_artifact_path as _resolve_template_attack_artifact_path,
)
from app.services.import_artifacts import (
    resolve_template_provider_snapshot_path as _resolve_template_provider_snapshot_path,
)
from app.services.import_artifacts import (
    validate_attack_import_options as _validate_attack_import_options,
)
from app.services.import_uploads import (
    has_optional_upload as _has_optional_upload,
)
from app.services.import_uploads import (
    ignored_line_count as _ignored_line_count,
)
from app.services.import_uploads import (
    normalize_input_type as _normalize_input_type,
)
from app.services.import_uploads import (
    optional_upload_summary as _optional_upload_summary,
)
from app.services.import_uploads import (
    read_bounded_upload as _read_bounded_upload,
)
from app.services.import_uploads import (
    reject_unsafe_upload_filename as _reject_unsafe_upload_filename,
)
from app.services.import_uploads import (
    sanitize_context_filename as _sanitize_context_filename,
)
from app.services.import_uploads import (
    sanitize_filename as _sanitize_filename,
)
from app.services.import_uploads import (
    sanitize_parser_error_message as _sanitize_parser_error_message,
)
from app.services.import_uploads import (
    sanitize_vex_filename as _sanitize_vex_filename,
)
from app.services.import_uploads import (
    store_upload as _store_upload,
)
from app.services.import_uploads import (
    template_settings as _template_settings,
)
from app.services.import_uploads import (
    upload_storage_ref as _upload_storage_ref,
)
from app.services.import_uploads import (
    upload_summary as _upload_summary,
)
from app.services.import_uploads import (
    upload_summary_with_path as _upload_summary_with_path,
)
from app.services.import_uploads import (
    validate_aggregate_upload_size as _validate_aggregate_upload_size,
)
from app.services.import_uploads import (
    validate_asset_context_upload as _validate_asset_context_upload,
)
from app.services.import_uploads import (
    validate_input_type as _validate_input_type,
)
from app.services.import_uploads import (
    validate_mime_hint as _validate_mime_hint,
)
from app.services.import_uploads import (
    validate_upload_suffix as _validate_upload_suffix,
)
from app.services.import_uploads import (
    validate_vex_upload as _validate_vex_upload,
)
from vuln_prioritizer.inputs._occurrence_support import apply_asset_context
from vuln_prioritizer.inputs._vex_support import apply_vex_statements
from vuln_prioritizer.inputs.loader import load_asset_context_file, load_vex_files
from vuln_prioritizer.models import PrioritizedFinding

router = APIRouter(tags=["imports"])

DEDUP_DECISION_SAMPLE_LIMIT = 500


@router.post("/projects/{project_id}/imports", response_model=AnalysisRunPublic)
async def import_project_upload(
    project_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    current_user: ScopedImportUser,
    input_type: str = Form(...),
    file: UploadFile = File(...),
    asset_context_file: UploadFile | None = File(None),
    vex_file: UploadFile | None = File(None),
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
    vex_upload = vex_file if _has_optional_upload(vex_file) else None
    vex_original_filename = vex_upload.filename if vex_upload is not None else None
    vex_stored_filename: str | None = None
    if vex_upload is not None and vex_original_filename is not None:
        _reject_unsafe_upload_filename(vex_original_filename)
        vex_stored_filename = _sanitize_vex_filename(
            vex_original_filename,
            reserved_filenames={stored_filename, asset_context_stored_filename},
        )
        _validate_vex_upload(vex_stored_filename, vex_upload)
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

    active_settings = _template_settings(request)
    upload_bytes = await _read_bounded_upload(file, settings=active_settings)
    remaining_upload_bytes = active_settings.max_upload_bytes - len(upload_bytes)
    asset_context_bytes = (
        await _read_bounded_upload(
            asset_context_upload,
            settings=active_settings,
            max_bytes=remaining_upload_bytes,
        )
        if asset_context_upload is not None
        else None
    )
    if asset_context_bytes is not None:
        remaining_upload_bytes -= len(asset_context_bytes)
    vex_bytes = (
        await _read_bounded_upload(
            vex_upload,
            settings=active_settings,
            max_bytes=remaining_upload_bytes,
        )
        if vex_upload is not None
        else None
    )
    _validate_aggregate_upload_size(
        settings=active_settings,
        payloads=[upload_bytes, asset_context_bytes, vex_bytes],
    )
    upload_sha256 = hashlib.sha256(upload_bytes).hexdigest()
    asset_context_sha256 = (
        hashlib.sha256(asset_context_bytes).hexdigest() if asset_context_bytes is not None else None
    )
    vex_sha256 = hashlib.sha256(vex_bytes).hexdigest() if vex_bytes is not None else None
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
            "vex_upload": _optional_upload_summary(
                input_type="vex-json",
                original_filename=vex_original_filename,
                stored_filename=vex_stored_filename,
                content_type=vex_upload.content_type if vex_upload is not None else None,
                size_bytes=len(vex_bytes) if vex_bytes is not None else None,
                sha256=vex_sha256,
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
    vex_path = (
        _store_upload(
            request,
            project_id=project_id,
            run_id=run.id,
            filename=vex_stored_filename or "openvex.json",
            content=vex_bytes,
        )
        if vex_bytes is not None
        else None
    )
    run.status = AnalysisRunStatus.RUNNING
    job_history = [*job_history, _job_status_entry("running")]
    upload_ref = _upload_storage_ref(
        project_id=project_id,
        run_id=run.id,
        filename=stored_filename,
    )
    asset_context_ref = (
        _upload_storage_ref(
            project_id=project_id,
            run_id=run.id,
            filename=asset_context_stored_filename or "asset_context.csv",
        )
        if asset_context_path is not None
        else None
    )
    vex_ref = (
        _upload_storage_ref(
            project_id=project_id,
            run_id=run.id,
            filename=vex_stored_filename or "openvex.json",
        )
        if vex_path is not None
        else None
    )
    run.summary_json = {
        **run.summary_json,
        "import_job": _job_payload(
            job_id=job_id,
            status="running",
            status_history=job_history,
        ),
        "input_upload": {
            **run.summary_json["input_upload"],
            "path": upload_ref,
            "storage_ref": upload_ref,
        },
        "asset_context_upload": _upload_summary_with_path(
            run.summary_json.get("asset_context_upload"),
            path=asset_context_ref,
        ),
        "vex_upload": _upload_summary_with_path(
            run.summary_json.get("vex_upload"),
            path=vex_ref,
        ),
    }
    session.flush()

    try:
        occurrences = build_importer_registry().parse(
            normalized_input_type,
            upload_bytes,
            filename=stored_filename,
        )
        occurrences = [_canonicalize_occurrence_asset_context(item) for item in occurrences]
    except (ImporterParseError, ImporterValidationError) as exc:
        parse_errors = _parse_errors(
            exc, filename=stored_filename, input_type=normalized_input_type
        )
        failed_history = [*job_history, _job_status_entry("failed")]
        failed_run = run_repo.finish_analysis_run(
            run.id,
            status=AnalysisRunStatus.FAILED,
            error_message=_sanitize_parser_error_message(str(exc)),
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
        _record_import_audit(
            session,
            current_user=current_user,
            project_id=project_id,
            run_id=failed_run.id,
            status="failure",
            stage="parse",
            input_type=normalized_input_type,
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
            error_message = _sanitize_parser_error_message(str(exc))
            asset_context_error = {
                "message": error_message,
                "filename": asset_context_stored_filename,
                "stage": "asset_context_parse",
                "error_type": exc.__class__.__name__,
            }
            failed_history = [*job_history, _job_status_entry("failed")]
            failed_run = run_repo.finish_analysis_run(
                run.id,
                status=AnalysisRunStatus.FAILED,
                error_message=error_message,
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
            _record_import_audit(
                session,
                current_user=current_user,
                project_id=project_id,
                run_id=failed_run.id,
                status="failure",
                stage="asset_context_parse",
                input_type=normalized_input_type,
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

    vex_summary: dict[str, Any] | None = None
    if vex_path is not None:
        try:
            occurrences, vex_summary = _apply_template_vex(
                occurrences,
                vex_path=vex_path,
            )
        except ValueError as exc:
            error_message = _sanitize_parser_error_message(str(exc))
            vex_error = {
                "message": error_message,
                "filename": vex_stored_filename,
                "stage": "vex_parse",
                "error_type": exc.__class__.__name__,
            }
            failed_history = [*job_history, _job_status_entry("failed")]
            failed_run = run_repo.finish_analysis_run(
                run.id,
                status=AnalysisRunStatus.FAILED,
                error_message=error_message,
                error_json={
                    "vex_error": vex_error,
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
                    "vex_error": vex_error,
                    "parse_errors": [],
                    "created_findings": 0,
                    "updated_findings": 0,
                    "ignored_lines": ignored_lines,
                },
            )
            _record_import_audit(
                session,
                current_user=current_user,
                project_id=project_id,
                run_id=failed_run.id,
                status="failure",
                stage="vex_parse",
                input_type=normalized_input_type,
            )
            session.commit()
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "VEX parsing failed.",
                    "analysis_run_id": str(failed_run.id),
                    "vex_error": vex_error,
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
            vex_files=[vex_path] if vex_path is not None else [],
        )
    except TemplateAnalysisError as exc:
        analysis_error_message = _sanitize_parser_error_message(str(exc))
        failed_history = [*job_history, _job_status_entry("failed")]
        failed_run = run_repo.finish_analysis_run(
            run.id,
            status=AnalysisRunStatus.FAILED,
            error_message=analysis_error_message,
            error_json={
                "analysis_error": {
                    "message": analysis_error_message,
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
                    "message": analysis_error_message,
                    "stage": "enrich_score_explain",
                    "error_type": exc.__class__.__name__,
                },
                "parse_errors": [],
                "created_findings": 0,
                "updated_findings": 0,
                "ignored_lines": ignored_lines,
            },
        )
        _record_import_audit(
            session,
            current_user=current_user,
            project_id=project_id,
            run_id=failed_run.id,
            status="failure",
            stage="analysis",
            input_type=normalized_input_type,
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
            "vex": vex_summary,
            "ignored_lines": ignored_lines,
            "input_sha256": upload_sha256,
            "parse_errors": [],
        },
    )
    _record_import_audit(
        session,
        current_user=current_user,
        project_id=project_id,
        run_id=finished_run.id,
        status="success",
        stage="succeeded",
        input_type=normalized_input_type,
    )
    session.commit()
    return finished_run


def _record_import_audit(
    session: Session,
    *,
    current_user: User,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    status: Literal["success", "failure"],
    stage: str,
    input_type: str,
) -> None:
    record_audit_event(
        session,
        action="import.run",
        resource_type="analysis_run",
        resource_id=run_id,
        status=status,
        actor=current_user,
        project_id=project_id,
        detail={"stage": stage, "input_type": input_type},
    )


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


def _apply_template_vex(
    occurrences: list[NormalizedOccurrence],
    *,
    vex_path: Path,
) -> tuple[list[NormalizedOccurrence], dict[str, Any]]:
    statements, load_diagnostics = load_vex_files(
        [vex_path],
        return_diagnostics=True,
    )
    input_occurrences = [
        _input_occurrence_from_template_occurrence(occurrence) for occurrence in occurrences
    ]
    enriched_occurrences, match_diagnostics = apply_vex_statements(
        input_occurrences,
        statements,
        return_diagnostics=True,
    )
    return (
        [
            _template_occurrence_with_vex(original, enriched)
            for original, enriched in zip(occurrences, enriched_occurrences, strict=True)
        ],
        {
            "file_count": load_diagnostics.file_count,
            "statement_count": load_diagnostics.statement_count,
            "skipped_statements": load_diagnostics.skipped_statements,
            "matched_occurrences": match_diagnostics.matched_occurrences,
            "unmatched_occurrences": match_diagnostics.unmatched_occurrences,
            "ambiguous_occurrences": match_diagnostics.ambiguous_occurrences,
            "conflict_occurrences": match_diagnostics.conflict_occurrences,
            "warnings": [
                *load_diagnostics.warnings,
                *match_diagnostics.warnings,
            ],
        },
    )


def _persist_template_occurrences(
    *,
    session: Session,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    occurrences: list[NormalizedOccurrence],
    analysis_result: TemplateAnalysisResult,
) -> dict[str, Any]:
    bulk_summary = _persist_template_occurrences_bulk_insert(
        session=session,
        project_id=project_id,
        run_id=run_id,
        occurrences=occurrences,
        analysis_result=analysis_result,
    )
    if bulk_summary is not None:
        return bulk_summary

    asset_repo = AssetRepository(session)
    finding_repo = FindingRepository(session)
    run_repo = RunRepository(session)
    decisions: list[dict[str, Any]] = []
    created_count = 0
    reused_count = 0
    touched_finding_ids: set[str] = set()
    attack_context_finding_ids: set[uuid.UUID] = set()
    dedup_keys = [
        _finding_dedup_key(_dedup_key_parts(project_id, occurrence)) for occurrence in occurrences
    ]
    findings_by_dedup_key = _existing_findings_by_dedup_key(
        session=session,
        project_id=project_id,
        dedup_keys=dedup_keys,
    )
    assets_by_key: dict[str, Any] = {}
    components_by_key: dict[tuple[str, str, str, str], Any] = {}
    vulnerabilities_by_cve: dict[str, Any] = {}
    decision_payloads_by_cve: dict[str, dict[str, Any]] = {}
    data_quality_by_cve: dict[str, dict[str, Any]] = {}
    with session.no_autoflush:
        for index, occurrence in enumerate(occurrences, start=1):
            decision = _decision_for_occurrence(analysis_result, occurrence)
            decision_payload = decision_payloads_by_cve.get(occurrence.cve)
            if decision_payload is None:
                decision_payload = decision.model_dump()
                decision_payloads_by_cve[occurrence.cve] = decision_payload
            data_quality_payload = data_quality_by_cve.get(occurrence.cve)
            if data_quality_payload is None:
                data_quality_payload = _decision_data_quality_json(decision)
                data_quality_by_cve[occurrence.cve] = data_quality_payload
            dedup_parts = _dedup_key_parts(project_id, occurrence)
            dedup_key = _finding_dedup_key(dedup_parts)
            asset = None
            if occurrence.asset_ref:
                asset = assets_by_key.get(occurrence.asset_ref)
                if asset is None:
                    asset = asset_repo.upsert_asset(
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
                        flush=False,
                    )
                    assets_by_key[occurrence.asset_ref] = asset
            component = None
            if occurrence.component:
                component_key = (
                    occurrence.component,
                    occurrence.version or "",
                    _string_evidence(occurrence.raw_evidence, "purl") or "",
                    _string_evidence(occurrence.raw_evidence, "package_type") or "",
                )
                component = components_by_key.get(component_key)
                if component is None:
                    component = finding_repo.upsert_component(
                        name=occurrence.component,
                        version=occurrence.version,
                        purl=_string_evidence(occurrence.raw_evidence, "purl"),
                        ecosystem=_string_evidence(occurrence.raw_evidence, "package_type"),
                        package_type=_string_evidence(occurrence.raw_evidence, "package_type"),
                        flush=False,
                    )
                    components_by_key[component_key] = component
            vulnerability = vulnerabilities_by_cve.get(occurrence.cve)
            if vulnerability is None:
                vulnerability = finding_repo.upsert_vulnerability(
                    cve_id=occurrence.cve,
                    source_id=dedup_parts["source_id"],
                    title=occurrence.cve,
                    description=decision.description,
                    cvss_score=decision.cvss_base_score,
                    cvss_vector=_decision_cvss_vector(decision),
                    severity=(
                        decision.cvss_severity
                        or _string_evidence(occurrence.raw_evidence, "severity")
                    ),
                    cwe=_decision_cwe(decision),
                    published_at=_decision_published(decision),
                    modified_at=_decision_modified(decision),
                    provider_json=_decision_provider_json(decision),
                    flush=False,
                )
                vulnerabilities_by_cve[occurrence.cve] = vulnerability
            existing_finding = findings_by_dedup_key.get(dedup_key)
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
                explanation_json=decision_payload,
                data_quality_json=data_quality_payload,
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
                existing_finding=existing_finding,
                lookup_existing=False,
                flush=False,
            )
            findings_by_dedup_key[dedup_key] = finding
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
                flush=False,
            )
            if len(decisions) < DEDUP_DECISION_SAMPLE_LIMIT:
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
    session.flush()

    return {
        "occurrence_count": len(occurrences),
        "finding_count": len(touched_finding_ids),
        "created_findings": created_count,
        "updated_findings": reused_count,
        "analysis_semantics": _analysis_semantics_summary(
            occurrences=occurrences,
            finding_count=len(touched_finding_ids),
        ),
        "dedup_summary": {
            "key_version": "vpw019-v1",
            "created_findings": created_count,
            "updated_findings": reused_count,
            "reused_findings": reused_count,
            "decision_count": len(occurrences),
            "decisions": decisions,
            "decision_sample_limit": DEDUP_DECISION_SAMPLE_LIMIT,
            "omitted_decisions": max(0, len(occurrences) - len(decisions)),
        },
    }


def _persist_template_occurrences_bulk_insert(
    *,
    session: Session,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    occurrences: list[NormalizedOccurrence],
    analysis_result: TemplateAnalysisResult,
) -> dict[str, Any] | None:
    """Fast path for large all-new occurrence imports with no component rows."""
    if len(occurrences) < 1000:
        return None
    if any(occurrence.component for occurrence in occurrences):
        return None
    if any(
        _attack_context_enabled(analysis_result, _decision_for_occurrence(analysis_result, item))
        for item in occurrences
    ):
        return None

    dedup_parts_by_index = [_dedup_key_parts(project_id, occurrence) for occurrence in occurrences]
    dedup_keys = [_finding_dedup_key(parts) for parts in dedup_parts_by_index]
    if _existing_findings_by_dedup_key(
        session=session,
        project_id=project_id,
        dedup_keys=dedup_keys,
    ):
        return None

    now = get_datetime_utc()
    asset_keys = sorted(
        {occurrence.asset_ref for occurrence in occurrences if occurrence.asset_ref}
    )
    existing_assets = _existing_assets_by_key(
        session=session,
        project_id=project_id,
        asset_keys=asset_keys,
    )
    if existing_assets:
        return None
    asset_rows: list[dict[str, Any]] = []
    asset_ids_by_key: dict[str, uuid.UUID] = {
        asset_key: asset.id for asset_key, asset in existing_assets.items()
    }
    first_occurrence_by_asset = {
        occurrence.asset_ref: occurrence
        for occurrence in occurrences
        if occurrence.asset_ref and occurrence.asset_ref not in existing_assets
    }
    for asset_key, occurrence in first_occurrence_by_asset.items():
        asset_id = uuid.uuid4()
        asset_ids_by_key[asset_key] = asset_id
        asset_rows.append(
            {
                "id": asset_id,
                "project_id": project_id,
                "asset_key": asset_key,
                "name": asset_key,
                "target_ref": _string_evidence(occurrence.raw_evidence, "target_ref"),
                "owner": _string_evidence(occurrence.raw_evidence, "owner"),
                "business_service": _string_evidence(
                    occurrence.raw_evidence,
                    "business_service",
                ),
                "environment": _asset_environment(occurrence.raw_evidence).value,
                "exposure": _asset_exposure(occurrence.raw_evidence).value,
                "criticality": _asset_criticality(occurrence.raw_evidence).value,
                "created_at": now,
                "updated_at": now,
            }
        )

    cves = sorted({occurrence.cve for occurrence in occurrences})
    vulnerabilities_by_cve = _existing_vulnerabilities_by_cve(session=session, cves=cves)
    if vulnerabilities_by_cve:
        return None
    vulnerability_rows: list[dict[str, Any]] = []
    vulnerability_ids_by_cve = {
        cve: vulnerability.id for cve, vulnerability in vulnerabilities_by_cve.items()
    }
    for cve in cves:
        if cve in vulnerability_ids_by_cve:
            continue
        decision = analysis_result.findings_by_cve[cve]
        dedup_parts = dedup_parts_by_index[
            next(index for index, occurrence in enumerate(occurrences) if occurrence.cve == cve)
        ]
        vulnerability_id = uuid.uuid4()
        vulnerability_ids_by_cve[cve] = vulnerability_id
        vulnerability_rows.append(
            {
                "id": vulnerability_id,
                "cve_id": cve,
                "source_id": dedup_parts["source_id"],
                "title": cve,
                "description": decision.description,
                "cvss_score": decision.cvss_base_score,
                "cvss_vector": _decision_cvss_vector(decision),
                "severity": decision.cvss_severity,
                "cwe": _decision_cwe(decision),
                "published_at": _decision_published(decision),
                "modified_at": _decision_modified(decision),
                "provider_json": _decision_provider_json(decision),
                "created_at": now,
                "updated_at": now,
            }
        )

    if asset_rows:
        for chunk in _chunks_any(asset_rows, size=500):
            session.execute(insert(Asset), chunk)
    if vulnerability_rows:
        session.execute(insert(Vulnerability), vulnerability_rows)

    decision_payloads_by_cve: dict[str, dict[str, Any]] = {}
    data_quality_by_cve: dict[str, dict[str, Any]] = {}
    finding_batch: list[dict[str, Any]] = []
    occurrence_batch: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    touched_finding_ids: set[str] = set()
    for index, (occurrence, dedup_parts, dedup_key) in enumerate(
        zip(occurrences, dedup_parts_by_index, dedup_keys, strict=True),
        start=1,
    ):
        decision = analysis_result.findings_by_cve[occurrence.cve]
        decision_payload = decision_payloads_by_cve.get(occurrence.cve)
        if decision_payload is None:
            decision_payload = _compact_decision_payload(decision)
            decision_payloads_by_cve[occurrence.cve] = decision_payload
        data_quality_payload = data_quality_by_cve.get(occurrence.cve)
        if data_quality_payload is None:
            data_quality_payload = _decision_data_quality_json(decision)
            data_quality_by_cve[occurrence.cve] = data_quality_payload

        finding_id = uuid.uuid4()
        finding_asset_id: uuid.UUID | None = (
            asset_ids_by_key.get(occurrence.asset_ref) if occurrence.asset_ref else None
        )
        finding_batch.append(
            {
                "id": finding_id,
                "project_id": project_id,
                "vulnerability_id": vulnerability_ids_by_cve[occurrence.cve],
                "component_id": None,
                "asset_id": finding_asset_id,
                "cve_id": occurrence.cve,
                "dedup_key": dedup_key,
                "status": _decision_status(decision).value,
                "priority": _decision_priority(decision).value,
                "priority_rank": decision.priority_rank,
                "risk_score": float(decision.operational_score),
                "operational_rank": decision.operational_rank or index,
                "in_kev": decision.in_kev,
                "epss": decision.epss,
                "cvss_base_score": decision.cvss_base_score,
                "attack_mapped": decision.attack_mapped,
                "suppressed_by_vex": decision.suppressed_by_vex,
                "under_investigation": decision.under_investigation,
                "waived": decision.waived,
                "recommended_action": decision.recommended_action,
                "rationale": decision.rationale,
                "explanation_json": decision_payload,
                "data_quality_json": data_quality_payload,
                "evidence_json": {
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
                        "action": "created",
                        "parts": dedup_parts,
                    },
                },
                "first_seen_at": now,
                "last_seen_at": now,
                "created_at": now,
                "updated_at": now,
            }
        )
        occurrence_batch.append(
            {
                "id": uuid.uuid4(),
                "finding_id": finding_id,
                "analysis_run_id": run_id,
                "source": occurrence.source,
                "scanner": None,
                "raw_reference": _string_evidence(occurrence.raw_evidence, "source_record_id"),
                "fix_version": occurrence.fix_version,
                "evidence_json": {
                    **dict(occurrence.raw_evidence),
                    "dedup_key": dedup_key,
                    "dedup_action": "created",
                },
            }
        )
        touched_finding_ids.add(str(finding_id))
        if len(decisions) < DEDUP_DECISION_SAMPLE_LIMIT:
            decisions.append(
                {
                    "action": "created",
                    "dedup_key": dedup_key,
                    "finding_id": str(finding_id),
                    "cve": occurrence.cve,
                    "source_id": dedup_parts["source_id"],
                    "component_identity": dedup_parts["component_identity"],
                    "asset_ref": dedup_parts["asset_ref"],
                }
            )
        if len(finding_batch) >= 250:
            session.execute(insert(Finding), finding_batch)
            finding_batch.clear()
        if len(occurrence_batch) >= 500:
            session.execute(insert(FindingOccurrence), occurrence_batch)
            occurrence_batch.clear()

    if finding_batch:
        session.execute(insert(Finding), finding_batch)
    if occurrence_batch:
        session.execute(insert(FindingOccurrence), occurrence_batch)
    session.flush()

    return {
        "occurrence_count": len(occurrences),
        "finding_count": len(touched_finding_ids),
        "created_findings": len(touched_finding_ids),
        "updated_findings": 0,
        "analysis_semantics": _analysis_semantics_summary(
            occurrences=occurrences,
            finding_count=len(touched_finding_ids),
        ),
        "dedup_summary": {
            "key_version": "vpw019-v1",
            "created_findings": len(touched_finding_ids),
            "updated_findings": 0,
            "reused_findings": 0,
            "decision_count": len(occurrences),
            "decisions": decisions,
            "decision_sample_limit": DEDUP_DECISION_SAMPLE_LIMIT,
            "omitted_decisions": max(0, len(occurrences) - len(decisions)),
        },
    }


def _attack_context_enabled(
    analysis_result: TemplateAnalysisResult,
    decision: PrioritizedFinding,
) -> bool:
    return analysis_result.context.attack_source != "none" or decision.attack_context.mapped


def _analysis_semantics_summary(
    *,
    occurrences: list[NormalizedOccurrence],
    finding_count: int,
) -> dict[str, Any]:
    return {
        "analysis_decision_scope": "cve",
        "persistence_scope": "asset_component_occurrence",
        "finding_dedup_key_version": "vpw019-v1",
        "cve_count": len({occurrence.cve for occurrence in occurrences}),
        "occurrence_count": len(occurrences),
        "finding_count": finding_count,
        "same_cve_can_create_distinct_asset_findings": True,
    }


def _compact_decision_payload(decision: PrioritizedFinding) -> dict[str, Any]:
    """Return the explain/score fields needed for large bulk imports without provider bloat."""
    explanation = _jsonable_model(getattr(decision, "explanation", None)) or {}
    guidance = _jsonable_model(getattr(decision, "decision_guidance", None)) or {}
    provenance = _jsonable_model(getattr(decision, "provenance", None)) or {}
    payload: dict[str, Any] = {
        "cve_id": decision.cve_id,
        "priority_label": decision.priority_label,
        "priority_rank": decision.priority_rank,
        "priority_state": decision.priority_state,
        "operational_score": decision.operational_score,
        "operational_score_reasons": list(decision.operational_score_reasons),
        "recommended_action": decision.recommended_action,
        "rationale": decision.rationale,
        "explanation": {
            "summary": explanation.get("summary"),
            "reasons": explanation.get("reasons", []),
        },
        "decision_guidance": {
            "decision_statement": guidance.get("decision_statement"),
            "recommended_next_steps": guidance.get("recommended_next_steps", []),
        },
        "provenance": {
            "vex_statuses": provenance.get("vex_statuses", {}),
            "provider_snapshot_hash": provenance.get("provider_snapshot_hash"),
        },
        "data_quality_flags": [_jsonable_model(item) for item in decision.data_quality_flags],
        "data_quality_confidence": decision.data_quality_confidence,
    }
    if decision.provider_evidence is not None:
        payload["provider_evidence"] = {
            "nvd": {
                "cvss_score": decision.cvss_base_score,
                "cvss_vector": _decision_cvss_vector(decision),
                "published": _decision_published(decision),
                "last_modified": _decision_modified(decision),
                "cwes": _decision_cwes(decision),
            },
            "epss": {"score": decision.epss},
            "kev": {"known_exploited": decision.in_kev},
        }
    return {key: value for key, value in payload.items() if value is not None}


def _jsonable_model(value: Any) -> Any:
    if value is None:
        return None
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if isinstance(value, list):
        return [_jsonable_model(item) for item in value]
    if isinstance(value, tuple):
        return [_jsonable_model(item) for item in value]
    return value


def _existing_findings_by_dedup_key(
    *,
    session: Session,
    project_id: uuid.UUID,
    dedup_keys: list[str],
) -> dict[str, Finding]:
    """Load existing project findings for a bulk import without per-row lookups."""
    if not dedup_keys:
        return {}
    findings: dict[str, Finding] = {}
    for chunk in _chunks(sorted(set(dedup_keys)), size=500):
        statement = select(Finding).where(
            Finding.project_id == project_id,
            col(Finding.dedup_key).in_(chunk),
        )
        for finding in session.exec(statement).all():
            findings[finding.dedup_key] = finding
    return findings


def _existing_assets_by_key(
    *,
    session: Session,
    project_id: uuid.UUID,
    asset_keys: list[str],
) -> dict[str, Asset]:
    if not asset_keys:
        return {}
    assets: dict[str, Asset] = {}
    for chunk in _chunks(sorted(set(asset_keys)), size=500):
        statement = select(Asset).where(
            Asset.project_id == project_id,
            col(Asset.asset_key).in_(chunk),
        )
        for asset in session.exec(statement).all():
            assets[asset.asset_key] = asset
    return assets


def _existing_vulnerabilities_by_cve(
    *,
    session: Session,
    cves: list[str],
) -> dict[str, Vulnerability]:
    if not cves:
        return {}
    vulnerabilities: dict[str, Vulnerability] = {}
    for chunk in _chunks(sorted(set(cves)), size=500):
        statement = select(Vulnerability).where(col(Vulnerability.cve_id).in_(chunk))
        for vulnerability in session.exec(statement).all():
            vulnerabilities[vulnerability.cve_id] = vulnerability
    return vulnerabilities


def _chunks(values: list[str], *, size: int) -> list[list[str]]:
    return [values[index : index + size] for index in range(0, len(values), size)]


def _chunks_any(values: list[dict[str, Any]], *, size: int) -> list[list[dict[str, Any]]]:
    return [values[index : index + size] for index in range(0, len(values), size)]


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
    if decision.priority_state == "Fixed":
        return FindingStatus.FIXED
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


def _decision_cwes(decision: PrioritizedFinding) -> list[str]:
    if decision.provider_evidence is None:
        return []
    return list(decision.provider_evidence.nvd.cwes)


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
    message = _sanitize_parser_error_message(str(exc))
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
