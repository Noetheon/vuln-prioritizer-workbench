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
from app.models import AnalysisRun, AnalysisRunPublic, AnalysisRunStatus, FindingPriority
from app.models.base import get_datetime_utc
from app.repositories import AssetRepository, FindingRepository, RunRepository

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


@router.post("/projects/{project_id}/imports", response_model=AnalysisRunPublic)
async def import_project_upload(
    project_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    current_user: CurrentUser,
    input_type: str = Form(...),
    file: UploadFile = File(...),
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

    upload_bytes = await _read_bounded_upload(file, settings=_template_settings(request))
    upload_sha256 = hashlib.sha256(upload_bytes).hexdigest()
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
            },
        )
        session.commit()
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Import parsing failed.",
                "analysis_run_id": str(failed_run.id),
                "parse_errors": parse_errors,
            },
        ) from exc

    persist_summary = _persist_template_occurrences(
        session=session,
        project_id=project_id,
        run_id=run.id,
        occurrences=occurrences,
    )
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
            **persist_summary,
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


def _persist_template_occurrences(
    *,
    session: Session,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    occurrences: list[NormalizedOccurrence],
) -> dict[str, Any]:
    asset_repo = AssetRepository(session)
    finding_repo = FindingRepository(session)
    run_repo = RunRepository(session)
    decisions: list[dict[str, Any]] = []
    created_count = 0
    reused_count = 0
    touched_finding_ids: set[str] = set()
    for index, occurrence in enumerate(occurrences, start=1):
        dedup_parts = _dedup_key_parts(project_id, occurrence)
        dedup_key = _finding_dedup_key(dedup_parts)
        asset = (
            asset_repo.upsert_asset(
                project_id=project_id,
                asset_key=occurrence.asset_ref,
                name=occurrence.asset_ref,
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
            severity=_string_evidence(occurrence.raw_evidence, "severity"),
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
            priority=FindingPriority.MEDIUM,
            priority_rank=99,
            operational_rank=index,
            evidence_json={
                "import": dict(occurrence.raw_evidence),
                "dedup": {
                    "key": dedup_key,
                    "key_version": "vpw019-v1",
                    "action": action,
                    "parts": dedup_parts,
                },
            },
        )
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
        "dedup_summary": {
            "key_version": "vpw019-v1",
            "created_findings": created_count,
            "reused_findings": reused_count,
            "decision_count": len(decisions),
            "decisions": decisions,
        },
    }


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
) -> list[dict[str, str]]:
    return [
        {
            "input_type": input_type,
            "filename": filename,
            "message": str(exc),
            "error_type": exc.__class__.__name__,
        }
    ]


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
