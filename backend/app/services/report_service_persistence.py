"""Persistence helpers for generated Workbench report artifacts."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlmodel import Session

from app.core.config import Settings
from app.models import AnalysisRun, Project, Report
from app.repositories import ReportRepository


def persist_text_report(
    session: Session,
    settings: Settings,
    *,
    run: AnalysisRun,
    project: Project,
    generated_at: datetime,
    finding_count: int,
    provider_snapshot_id: uuid.UUID | None,
    content: str,
    kind: str,
    report_format: str,
    filename: str,
    content_type: str,
    extra_metadata: dict[str, Any] | None = None,
) -> Report:
    report_id = uuid.uuid4()
    path = report_path(
        settings,
        project_id=project.id,
        run_id=run.id,
        report_id=report_id,
        filename=filename,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return create_report_record(
        session,
        report_id=report_id,
        run=run,
        project=project,
        generated_at=generated_at,
        finding_count=finding_count,
        provider_snapshot_id=provider_snapshot_id,
        content_bytes=content.encode("utf-8"),
        report_path=path,
        kind=kind,
        report_format=report_format,
        filename=filename,
        content_type=content_type,
        extra_metadata=extra_metadata,
    )


def persist_binary_report(
    session: Session,
    settings: Settings,
    *,
    run: AnalysisRun,
    project: Project,
    generated_at: datetime,
    finding_count: int,
    provider_snapshot_id: uuid.UUID | None,
    content: bytes,
    kind: str,
    report_format: str,
    filename: str,
    content_type: str,
    extra_metadata: dict[str, Any] | None = None,
) -> Report:
    report_id = uuid.uuid4()
    path = report_path(
        settings,
        project_id=project.id,
        run_id=run.id,
        report_id=report_id,
        filename=filename,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return create_report_record(
        session,
        report_id=report_id,
        run=run,
        project=project,
        generated_at=generated_at,
        finding_count=finding_count,
        provider_snapshot_id=provider_snapshot_id,
        content_bytes=content,
        report_path=path,
        kind=kind,
        report_format=report_format,
        filename=filename,
        content_type=content_type,
        extra_metadata=extra_metadata,
    )


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


def report_path(
    settings: Settings,
    *,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    report_id: uuid.UUID,
    filename: str,
) -> Path:
    return settings.report_dir_path / str(project_id) / str(run_id) / str(report_id) / filename


__all__ = [
    "create_report_record",
    "persist_binary_report",
    "persist_text_report",
    "report_path",
]
