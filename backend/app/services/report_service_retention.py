"""Retention helpers for generated Workbench report artifacts."""

from __future__ import annotations

from pathlib import Path

from sqlmodel import Session

from app.core.config import Settings
from app.models import Report
from app.repositories import ReportRepository
from app.services.audit import record_audit_event
from app.services.report_artifact_transactions import schedule_report_artifact_deletion


def prune_run_reports(session: Session, settings: Settings, report: Report) -> None:
    """Keep report storage bounded by deleting oldest reports for the run."""
    repository = ReportRepository(session)
    reports = repository.list_run_reports(report.analysis_run_id)
    for stale_report in reports[settings.MAX_REPORTS_PER_RUN :]:
        if stale_report.id == report.id:
            continue
        deletion_scheduled = schedule_report_artifact_deletion(
            session, settings, Path(stale_report.path)
        )
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
                "artifact_deletion": "scheduled_after_commit"
                if deletion_scheduled
                else "outside_managed_directory",
                "max_reports_per_run": settings.MAX_REPORTS_PER_RUN,
            },
        )
        repository.delete_report(stale_report)


__all__ = ["prune_run_reports"]
