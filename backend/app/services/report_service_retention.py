"""Retention helpers for generated Workbench report artifacts."""

from __future__ import annotations

import shutil
from pathlib import Path

from sqlmodel import Session

from app.core.config import Settings
from app.models import Report
from app.repositories import ReportRepository


def prune_run_reports(session: Session, settings: Settings, report: Report) -> None:
    """Keep report storage bounded by deleting oldest reports for the run."""
    repository = ReportRepository(session)
    reports = repository.list_run_reports(report.analysis_run_id)
    for stale_report in reports[settings.MAX_REPORTS_PER_RUN :]:
        if stale_report.id == report.id:
            continue
        _delete_report_artifact(settings, stale_report)
        repository.delete_report(stale_report)


def _delete_report_artifact(settings: Settings, report: Report) -> None:
    report_root = settings.report_dir_path.resolve(strict=False)
    report_path_value = Path(report.path)
    try:
        report_path_resolved = report_path_value.resolve(strict=False)
    except OSError:
        return
    if not report_path_resolved.is_relative_to(report_root):
        return
    report_dir = report_path_resolved.parent
    if report_dir == report_root or not report_dir.is_relative_to(report_root):
        return
    shutil.rmtree(report_dir, ignore_errors=True)


__all__ = ["prune_run_reports"]
