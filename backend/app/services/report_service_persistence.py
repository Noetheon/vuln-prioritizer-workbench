"""Persistence helpers for generated Workbench report artifacts."""

from __future__ import annotations

import shutil
import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlmodel import Session

from app.core.config import Settings
from app.models import AnalysisRun, Project, Report
from app.services.report_models import ReportGenerationError
from app.services.report_service_records import create_report_record
from app.services.report_service_retention import prune_run_reports


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
    content_bytes = content.encode("utf-8")
    return _persist_report_artifact(
        session,
        settings,
        run=run,
        project=project,
        generated_at=generated_at,
        finding_count=finding_count,
        provider_snapshot_id=provider_snapshot_id,
        content_bytes=content_bytes,
        write_artifact=lambda path: path.write_text(content, encoding="utf-8"),
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
    return _persist_report_artifact(
        session,
        settings,
        run=run,
        project=project,
        generated_at=generated_at,
        finding_count=finding_count,
        provider_snapshot_id=provider_snapshot_id,
        content_bytes=content,
        write_artifact=lambda path: path.write_bytes(content),
        kind=kind,
        report_format=report_format,
        filename=filename,
        content_type=content_type,
        extra_metadata=extra_metadata,
    )


def _persist_report_artifact(
    session: Session,
    settings: Settings,
    *,
    run: AnalysisRun,
    project: Project,
    generated_at: datetime,
    finding_count: int,
    provider_snapshot_id: uuid.UUID | None,
    content_bytes: bytes,
    write_artifact: Callable[[Path], object],
    kind: str,
    report_format: str,
    filename: str,
    content_type: str,
    extra_metadata: dict[str, Any] | None,
) -> Report:
    _ensure_report_size_allowed(settings, content_size=len(content_bytes), filename=filename)
    report_id = uuid.uuid4()
    path = report_path(
        settings,
        project_id=project.id,
        run_id=run.id,
        report_id=report_id,
        filename=filename,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        write_artifact(path)
        report = create_report_record(
            session,
            report_id=report_id,
            run=run,
            project=project,
            generated_at=generated_at,
            finding_count=finding_count,
            provider_snapshot_id=provider_snapshot_id,
            content_bytes=content_bytes,
            report_path=path,
            kind=kind,
            report_format=report_format,
            filename=filename,
            content_type=content_type,
            extra_metadata=extra_metadata,
        )
        prune_run_reports(session, settings, report)
        return report
    except Exception:
        _remove_report_artifact_dir(settings, path)
        raise


def report_path(
    settings: Settings,
    *,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    report_id: uuid.UUID,
    filename: str,
) -> Path:
    return settings.report_dir_path / str(project_id) / str(run_id) / str(report_id) / filename


def _ensure_report_size_allowed(settings: Settings, *, content_size: int, filename: str) -> None:
    if content_size <= settings.max_report_bytes:
        return
    raise ReportGenerationError(
        f"Generated report {filename} exceeds configured report size limit "
        f"({settings.MAX_REPORT_MB} MiB)."
    )


def _remove_report_artifact_dir(settings: Settings, path: Path) -> None:
    report_root = settings.report_dir_path.resolve(strict=False)
    try:
        report_path = path.resolve(strict=False)
    except OSError:
        return
    if not report_path.is_relative_to(report_root):
        return
    report_dir = report_path.parent
    if report_dir == report_root or not report_dir.is_relative_to(report_root):
        return
    shutil.rmtree(report_dir, ignore_errors=True)


__all__ = [
    "create_report_record",
    "persist_binary_report",
    "persist_text_report",
    "report_path",
]
