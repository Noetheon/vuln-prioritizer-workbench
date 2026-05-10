"""Retention helpers for generated Workbench report artifacts."""

from __future__ import annotations

import shutil
from pathlib import Path

from sqlmodel import Session

from app.core.config import Settings
from app.models import Report
from app.repositories import ReportRepository
from app.services.audit import record_audit_event


def prune_run_reports(session: Session, settings: Settings, report: Report) -> None:
    """Keep report storage bounded by deleting oldest reports for the run."""
    repository = ReportRepository(session)
    reports = repository.list_run_reports(report.analysis_run_id)
    for stale_report in reports[settings.MAX_REPORTS_PER_RUN :]:
        if stale_report.id == report.id:
            continue
        artifact_deleted = _delete_report_artifact(settings, stale_report)
        record_audit_event(
            session,
            action="report.retention.delete",
            resource_type="report",
            resource_id=stale_report.id,
            project_id=stale_report.project_id,
            detail={
                "analysis_run_id": str(stale_report.analysis_run_id),
                "retained_report_id": str(report.id),
                "format": stale_report.format,
                "kind": stale_report.kind,
                "filename": stale_report.filename,
                "artifact_deleted": artifact_deleted,
                "max_reports_per_run": settings.MAX_REPORTS_PER_RUN,
            },
        )
        repository.delete_report(stale_report)


def _delete_report_artifact(settings: Settings, report: Report) -> bool:
    report_root = settings.report_dir_path.resolve(strict=False)
    report_path_value = Path(report.path)
    try:
        report_path_resolved = report_path_value.resolve(strict=False)
    except OSError:
        return False
    if not report_path_resolved.is_relative_to(report_root):
        return False
    report_dir = report_path_resolved.parent
    if report_dir == report_root or not report_dir.is_relative_to(report_root):
        return False
    shutil.rmtree(report_dir, ignore_errors=True)
    return not report_dir.exists()


__all__ = ["prune_run_reports"]
