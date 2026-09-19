"""Content-verified SBOM rescans and portable scanner evidence downloads."""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from pathlib import Path

from pydantic import ValidationError
from sqlmodel import Session

from app.contracts.sbom import SbomAssessmentV1
from app.core.config import Settings
from app.core.local_actor import LocalWorkbenchActor
from app.decision_core.contracts import AnalysisEvidenceV2, EvidenceUploadRef
from app.models import AnalysisRun, AnalysisRunStatus, WorkflowRunKind
from app.repositories import EvidenceRepository, WorkflowRepository
from app.services.import_errors import ImportServiceError
from app.services.import_execution_types import ImportUploadContent, ProjectImportUploadRequest
from app.services.import_queue import queue_project_import


def _source_evidence(
    session: Session, run: AnalysisRun
) -> tuple[AnalysisEvidenceV2, SbomAssessmentV1]:
    if run.status not in {
        AnalysisRunStatus.SUCCEEDED,
        AnalysisRunStatus.COMPLETED,
        AnalysisRunStatus.COMPLETED_WITH_ERRORS,
    }:
        raise ImportServiceError(status_code=409, detail="A completed SBOM assessment is required.")
    try:
        evidence = EvidenceRepository(session).get_analysis_evidence(run.id)
    except ValidationError as exc:
        raise ImportServiceError(
            status_code=409, detail="Stored SBOM evidence is invalid."
        ) from exc
    if evidence is None or evidence.sbom_assessment is None:
        raise ImportServiceError(
            status_code=409, detail="This run has no recorded SBOM assessment."
        )
    assessment = evidence.sbom_assessment
    upload = evidence.uploads.input
    if (
        evidence.analysis_run_id != str(run.id)
        or evidence.project_id != str(run.project_id)
        or assessment.input_format != run.input_type
        or upload is None
        or upload.sha256 != assessment.input_sha256
        or evidence.input_sha256 != assessment.input_sha256
        or (upload.storage_ref or upload.path) != assessment.artifact_refs.get("input")
    ):
        raise ImportServiceError(status_code=409, detail="Stored SBOM evidence is inconsistent.")
    return evidence, assessment


def _read_managed_artifact(
    settings: Settings,
    run: AnalysisRun,
    storage_ref: str | None,
    *,
    label: str,
    limit: int,
    sha256: str | None = None,
) -> bytes:
    """Read only this run's managed, bounded artifact, never a caller-selected path."""
    if (
        not storage_ref
        or "\\" in storage_ref
        or "\x00" in storage_ref
        or Path(storage_ref).is_absolute()
        or ".." in Path(storage_ref).parts
    ):
        raise ImportServiceError(status_code=409, detail=f"Stored {label} reference is invalid.")
    root = settings.import_upload_dir_path.resolve()
    run_root = root / str(run.project_id) / str(run.id)
    try:
        candidate = (root / storage_ref).resolve(strict=True)
        if not candidate.is_relative_to(run_root) or not candidate.is_file():
            raise ImportServiceError(
                status_code=409, detail=f"Stored {label} reference is invalid."
            )
        with candidate.open("rb") as source:
            content = source.read(limit + 1)
    except (OSError, ValueError, RuntimeError) as exc:
        if isinstance(exc, ImportServiceError):
            raise
        raise ImportServiceError(status_code=409, detail=f"Stored {label} is unavailable.") from exc
    if len(content) > limit:
        raise ImportServiceError(status_code=413, detail=f"Stored {label} exceeds the size limit.")
    if sha256 is not None and (
        not re.fullmatch(r"[0-9a-f]{64}", sha256) or hashlib.sha256(content).hexdigest() != sha256
    ):
        raise ImportServiceError(status_code=409, detail=f"Stored {label} checksum does not match.")
    return content


def _verified_upload(
    settings: Settings,
    run: AnalysisRun,
    upload: EvidenceUploadRef | None,
    *,
    label: str,
) -> ImportUploadContent | None:
    if upload is None:
        return None
    if upload.sha256 is None:
        raise ImportServiceError(
            status_code=409, detail=f"Stored {label} has no recorded checksum."
        )
    content = _read_managed_artifact(
        settings,
        run,
        upload.storage_ref or upload.path,
        label=label,
        limit=settings.max_upload_bytes,
        sha256=upload.sha256,
    )
    if upload.size_bytes is not None and upload.size_bytes != len(content):
        raise ImportServiceError(status_code=409, detail=f"Stored {label} size does not match.")
    return ImportUploadContent(
        filename=upload.original_filename or upload.stored_filename,
        content_type=upload.content_type,
        content=content,
    )


async def queue_sbom_rescan(
    *,
    session: Session,
    settings: Settings,
    local_actor: LocalWorkbenchActor,
    run: AnalysisRun,
    sbom_db_update: bool,
) -> AnalysisRun:
    """Queue a new assessment of the exact recorded inventory and original observation time."""
    evidence, assessment = _source_evidence(session, run)
    if not assessment.observed_at:
        raise ImportServiceError(status_code=409, detail="SBOM observation time is unavailable.")
    workflow = WorkflowRepository(session).get_latest_analysis_workflow(
        analysis_run_id=run.id, kind=WorkflowRunKind.IMPORT
    )
    if workflow is None:
        raise ImportServiceError(
            status_code=409, detail="Original SBOM import options are unavailable."
        )
    payload = workflow.payload_json
    source = _verified_upload(settings, run, evidence.uploads.input, label="SBOM")
    assert source is not None
    upload = ProjectImportUploadRequest(
        input_type=assessment.input_format,
        file=source,
        asset_context_file=_verified_upload(
            settings, run, evidence.uploads.asset_context, label="asset context"
        ),
        vex_file=_verified_upload(settings, run, evidence.uploads.vex, label="VEX"),
        provider_snapshot_file=_optional_string(payload.get("provider_snapshot_file")),
        locked_provider_data=bool(payload.get("locked_provider_data", False)),
        attack_source=_optional_string(payload.get("attack_source")) or "none",
        attack_mapping_file=_optional_string(payload.get("attack_mapping_file")),
        attack_technique_metadata_file=_optional_string(
            payload.get("attack_technique_metadata_file")
        ),
        sbom_scanner="grype",
        sbom_target_ref=assessment.target_ref,
        sbom_db_update=sbom_db_update,
        sbom_source_run_id=str(run.id),
        sbom_observed_at=assessment.observed_at,
    )
    return await queue_project_import(
        project_id=run.project_id,
        session=session,
        local_actor=local_actor,
        settings=settings,
        upload=upload,
    )


def sbom_evidence_zip(*, session: Session, settings: Settings, run: AnalysisRun) -> bytes:
    """Package hash-verified source bytes and a manifest bound to the Decision Ledger."""
    _evidence, assessment = _source_evidence(session, run)
    input_bytes = _read_managed_artifact(
        settings,
        run,
        assessment.artifact_refs.get("input"),
        label="SBOM",
        limit=settings.max_upload_bytes,
        sha256=assessment.input_sha256,
    )
    report_bytes = _read_managed_artifact(
        settings,
        run,
        assessment.artifact_refs.get("report"),
        label="scanner report",
        limit=settings.SBOM_SCAN_MAX_OUTPUT_MB * 1024 * 1024,
        sha256=assessment.output_sha256,
    )
    assessment_bytes = _read_managed_artifact(
        settings,
        run,
        assessment.artifact_refs.get("manifest"),
        label="assessment manifest",
        limit=2 * 1024 * 1024,
    )
    try:
        recorded = SbomAssessmentV1.model_validate_json(assessment_bytes)
    except ValidationError as exc:
        raise ImportServiceError(
            status_code=409, detail="Stored assessment manifest is invalid."
        ) from exc
    if recorded != assessment:
        raise ImportServiceError(
            status_code=409, detail="Stored assessment manifest does not match."
        )
    entries = {
        "sbom.json": input_bytes,
        "grype-report.json": report_bytes,
        "assessment.json": assessment_bytes,
    }
    manifest = {
        "schema_version": "sbom-evidence-bundle.v1",
        "analysis_run_id": str(run.id),
        "project_id": str(run.project_id),
        "assessment": assessment.model_dump(mode="json"),
        "files": [
            {
                "path": name,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content),
            }
            for name, content in entries.items()
        ],
    }
    entries["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)
    return buffer.getvalue()


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None
