"""Database record helpers for generated Workbench reports."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlmodel import Session

from app.models import AnalysisRun, Project, Report
from app.repositories import ReportRepository


def create_report_record(
    session: Session,
    *,
    report_id: uuid.UUID,
    run: AnalysisRun,
    project: Project,
    generated_at: datetime,
    finding_count: int,
    provider_snapshot_id: uuid.UUID | None,
    content_bytes: bytes,
    report_path: Path,
    kind: str,
    report_format: str,
    filename: str,
    content_type: str,
    extra_metadata: dict[str, Any] | None = None,
) -> Report:
    """Create report record function."""
    sha256 = hashlib.sha256(content_bytes).hexdigest()
    metadata_json = {
        "generated_at": generated_at.isoformat(),
        "project_id": str(project.id),
        "analysis_run_id": str(run.id),
        "provider_snapshot_id": str(provider_snapshot_id)
        if provider_snapshot_id is not None
        else None,
        "finding_count": finding_count,
        "format": report_format,
        "kind": kind,
        "service": "workbench-report-service",
    }
    if extra_metadata:
        metadata_json.update(extra_metadata)
    return ReportRepository(session).create_report(
        report_id=report_id,
        project_id=project.id,
        analysis_run_id=run.id,
        kind=kind,
        format=report_format,
        filename=filename,
        content_type=content_type,
        path=str(report_path),
        sha256=sha256,
        size_bytes=len(content_bytes),
        metadata_json=metadata_json,
    )


__all__ = ["create_report_record"]
