"""Report artifact DTO and filesystem validation helpers."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from app.core.config import Settings
from app.domain.engine.security_redaction import redact_value
from app.models import Report, ReportPublic, WorkflowRunPublic


class ReportArtifactNotFoundError(RuntimeError):
    """Raised when a report artifact is missing or outside the report root."""


class ReportArtifactChecksumError(RuntimeError):
    """Raised when a report artifact no longer matches stored metadata."""


def build_report_public(
    report: Report,
    settings: Settings,
    *,
    workflow: WorkflowRunPublic | None = None,
) -> ReportPublic:
    """Build the public report DTO without exposing the server path."""
    return ReportPublic(
        id=report.id,
        project_id=report.project_id,
        analysis_run_id=report.analysis_run_id,
        kind=report.kind,
        format=report.format,
        filename=report.filename,
        content_type=report.content_type,
        sha256=report.sha256,
        size_bytes=report.size_bytes,
        metadata_json=_public_metadata(report.metadata_json or {}),
        created_at=report.created_at,
        download_url=f"{settings.API_V1_STR}/reports/{report.id}/download",
        workflow=workflow,
    )


def validated_report_path(report: Report, settings: Settings) -> Path:
    """Return a report artifact path after root and checksum validation."""
    root = settings.report_dir_path.resolve(strict=False)
    try:
        resolved = Path(report.path).resolve(strict=True)
        resolved.relative_to(root)
    except (FileNotFoundError, ValueError) as exc:
        raise ReportArtifactNotFoundError("Report artifact not found") from exc

    if not resolved.is_file():
        raise ReportArtifactNotFoundError("Report artifact not found")
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    if digest != report.sha256:
        raise ReportArtifactChecksumError("Report artifact checksum mismatch")
    return resolved


def _dict_value(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _public_metadata(value: object) -> dict[str, Any]:
    redacted, _paths = redact_value(value)
    return _dict_value(redacted)
