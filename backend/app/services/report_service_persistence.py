"""Persistence helpers for generated Workbench report artifacts."""

from __future__ import annotations

import hashlib
import shutil
import uuid
import zlib
from collections.abc import Callable, Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlmodel import Session

from app.core.config import Settings
from app.models import AnalysisRun, Project, Report
from app.services.report_artifact_transactions import track_report_artifact_creation
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
    before_publication: Callable[[], None] | None = None,
) -> Report:
    """Persist text report function."""
    return persist_binary_report(
        session,
        settings,
        run=run,
        project=project,
        generated_at=generated_at,
        finding_count=finding_count,
        provider_snapshot_id=provider_snapshot_id,
        content=content.encode("utf-8"),
        kind=kind,
        report_format=report_format,
        filename=filename,
        content_type=content_type,
        extra_metadata=extra_metadata,
        before_publication=before_publication,
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
    before_publication: Callable[[], None] | None = None,
) -> Report:
    """Persist binary report function."""
    _ensure_report_size_allowed(settings, content_size=len(content), filename=filename)
    return persist_stream_report(
        session,
        settings,
        run=run,
        project=project,
        generated_at=generated_at,
        finding_count=finding_count,
        provider_snapshot_id=provider_snapshot_id,
        chunks=(content,),
        kind=kind,
        report_format=report_format,
        filename=filename,
        content_type=content_type,
        extra_metadata=extra_metadata,
        before_publication=before_publication,
    )


def persist_stream_report(
    session: Session,
    settings: Settings,
    *,
    run: AnalysisRun,
    project: Project,
    generated_at: datetime,
    finding_count: int,
    provider_snapshot_id: uuid.UUID | None,
    chunks: Iterable[bytes],
    compress: bool = False,
    kind: str,
    report_format: str,
    filename: str,
    content_type: str,
    extra_metadata: dict[str, Any] | None = None,
    before_publication: Callable[[], None] | None = None,
) -> Report:
    """Persist report artifact function."""
    report_id = uuid.uuid4()
    path = report_path(
        settings,
        project_id=project.id,
        run_id=run.id,
        report_id=report_id,
        filename=filename,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    iterator = iter(chunks)
    try:
        digest = hashlib.sha256()
        size = expanded_size = 0
        compressor = zlib.compressobj(wbits=31) if compress else None
        with path.open("wb") as output:

            def write(data: bytes) -> None:
                nonlocal size
                size += len(data)
                _ensure_report_size_allowed(settings, content_size=size, filename=filename)
                digest.update(data)
                output.write(data)

            for chunk in iterator:
                expanded_size += len(chunk)
                if compress and expanded_size > settings.max_report_bytes * 20:
                    raise ReportGenerationError(
                        "Expanded JSON exceeds configured report size limit "
                        "(20 times MAX_REPORT_MB)."
                    )
                write(compressor.compress(chunk) if compressor is not None else chunk)
            if compressor is not None:
                write(compressor.flush())
        if before_publication is not None:
            before_publication()
        track_report_artifact_creation(session, settings, path)
        report = create_report_record(
            session,
            report_id=report_id,
            run=run,
            project=project,
            generated_at=generated_at,
            finding_count=finding_count,
            provider_snapshot_id=provider_snapshot_id,
            sha256=digest.hexdigest(),
            size_bytes=size,
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
    finally:
        close = getattr(iterator, "close", None)
        if close is not None:
            close()


def report_path(
    settings: Settings,
    *,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    report_id: uuid.UUID,
    filename: str,
) -> Path:
    """Report path function."""
    return settings.report_dir_path / str(project_id) / str(run_id) / str(report_id) / filename


def _ensure_report_size_allowed(settings: Settings, *, content_size: int, filename: str) -> None:
    """Ensure report size allowed function."""
    if content_size <= settings.max_report_bytes:
        return
    raise ReportGenerationError(
        f"Generated report {filename} exceeds configured report size limit "
        f"({settings.MAX_REPORT_MB} MiB)."
    )


def _remove_report_artifact_dir(settings: Settings, path: Path) -> None:
    """Remove report artifact dir function."""
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
