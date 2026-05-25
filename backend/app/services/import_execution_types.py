"""Shared request and state types for Workbench import execution."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.models import AnalysisRun


@dataclass(frozen=True, slots=True)
class ImportUploadContent:
    """HTTP-independent upload payload accepted by the import service."""

    filename: str | None
    content_type: str | None
    content: bytes


@dataclass(frozen=True, slots=True)
class ProjectImportUploadRequest:
    """Workbench import request normalized at the route boundary."""

    input_type: str
    file: ImportUploadContent
    asset_context_file: ImportUploadContent | None = None
    vex_file: ImportUploadContent | None = None
    provider_snapshot_file: str | None = None
    locked_provider_data: bool = False
    attack_source: str = "none"
    attack_mapping_file: str | None = None
    attack_technique_metadata_file: str | None = None


@dataclass(frozen=True, slots=True)
class PreparedSidecarUpload:
    """Data representation and logic for Prepared Sidecar Upload."""

    payload: ImportUploadContent | None
    original_filename: str | None
    stored_filename: str | None
    content: bytes | None
    sha256: str | None
    summary_input_type: str
    default_filename: str


@dataclass(frozen=True, slots=True)
class PreparedImportUpload:
    """Data representation and logic for Prepared Import Upload."""

    input_type: str
    file: ImportUploadContent
    original_filename: str
    stored_filename: str
    upload_bytes: bytes
    upload_sha256: str
    ignored_lines: int
    asset_context: PreparedSidecarUpload
    vex: PreparedSidecarUpload
    provider_snapshot_path: Path | None
    attack_mapping_path: Path | None
    attack_metadata_path: Path | None
    attack_source: str
    locked_provider_data: bool


@dataclass(frozen=True, slots=True)
class ResolvedImportRun:
    """Data representation and logic for Resolved Import Run."""

    run: AnalysisRun
    job_id: str
    job_history: list[dict[str, str]]
    already_finished: bool = False


@dataclass(frozen=True, slots=True)
class StoredImportArtifacts:
    """Data representation and logic for Stored Import Artifacts."""

    upload_path: Path
    asset_context_path: Path | None
    vex_path: Path | None
    upload_ref: str
    asset_context_ref: str | None
    vex_ref: str | None
