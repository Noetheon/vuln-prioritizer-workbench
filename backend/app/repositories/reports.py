"""Report metadata repository for Workbench persistence."""

from __future__ import annotations

import uuid
from typing import Any

from sqlmodel import Session, col, select

from app.models import Report


class ReportRepository:
    """Persistence helpers for generated report artifacts."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create_report(
        self,
        *,
        report_id: uuid.UUID,
        project_id: uuid.UUID,
        analysis_run_id: uuid.UUID,
        kind: str,
        format: str,
        filename: str,
        content_type: str,
        path: str,
        sha256: str,
        size_bytes: int,
        metadata_json: dict[str, Any] | None = None,
    ) -> Report:
        """Create report metadata without committing the transaction."""
        report = Report(
            id=report_id,
            project_id=project_id,
            analysis_run_id=analysis_run_id,
            kind=kind,
            format=format,
            filename=filename,
            content_type=content_type,
            path=path,
            sha256=sha256,
            size_bytes=size_bytes,
            metadata_json=metadata_json or {},
        )
        self.session.add(report)
        self.session.flush()
        return report

    def get_report(self, report_id: uuid.UUID) -> Report | None:
        """Return a report by primary key."""
        return self.session.get(Report, report_id)

    def list_run_reports(self, analysis_run_id: uuid.UUID) -> list[Report]:
        """Return reports for one run newest first."""
        statement = (
            select(Report)
            .where(Report.analysis_run_id == analysis_run_id)
            .order_by(col(Report.created_at).desc())
        )
        return list(self.session.exec(statement).all())

    def list_project_reports(self, project_id: uuid.UUID) -> list[Report]:
        """Return reports for one project newest first."""
        statement = (
            select(Report)
            .where(Report.project_id == project_id)
            .order_by(col(Report.created_at).desc())
        )
        return list(self.session.exec(statement).all())
