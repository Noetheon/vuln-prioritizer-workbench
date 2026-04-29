"""Project, analysis-run, and project configuration persistence helpers."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from vuln_prioritizer.db.models import (
    AnalysisRun,
    Project,
    ProjectConfigSnapshot,
    utc_now,
)


class ProjectRunRepositoryMixin:
    """ProjectRun repository methods."""

    session: Session

    def create_project(self, name: str, description: str | None = None) -> Project:
        project = Project(name=name, description=description)
        self.session.add(project)
        self.session.flush()
        return project

    def get_project(self, project_id: str) -> Project | None:
        return self.session.get(Project, project_id)

    def get_project_by_name(self, name: str) -> Project | None:
        return self.session.scalar(select(Project).where(Project.name == name))

    def list_projects(self) -> list[Project]:
        statement = select(Project).order_by(Project.created_at, Project.name)
        return list(self.session.scalars(statement))

    def create_analysis_run(
        self,
        *,
        project_id: str,
        input_type: str,
        input_filename: str | None = None,
        input_path: str | None = None,
        status: str = "pending",
        provider_snapshot_id: str | None = None,
        metadata_json: dict[str, Any] | None = None,
        attack_summary_json: dict[str, Any] | None = None,
        summary_json: dict | None = None,
    ) -> AnalysisRun:
        run = AnalysisRun(
            project_id=project_id,
            input_type=input_type,
            input_filename=input_filename,
            input_path=input_path,
            status=status,
            provider_snapshot_id=provider_snapshot_id,
            metadata_json=metadata_json or {},
            attack_summary_json=attack_summary_json or {},
            summary_json=summary_json or {},
        )
        self.session.add(run)
        self.session.flush()
        return run

    def finish_analysis_run(
        self,
        run_id: str,
        *,
        status: str = "completed",
        finished_at: datetime | None = None,
        error_message: str | None = None,
        metadata_json: dict[str, Any] | None = None,
        attack_summary_json: dict[str, Any] | None = None,
        summary_json: dict | None = None,
    ) -> AnalysisRun:
        run = self.session.get(AnalysisRun, run_id)
        if run is None:
            raise LookupError(f"AnalysisRun not found: {run_id}")
        run.status = status
        run.finished_at = finished_at or utc_now()
        run.error_message = error_message
        if metadata_json is not None:
            run.metadata_json = metadata_json
        if attack_summary_json is not None:
            run.attack_summary_json = attack_summary_json
        if summary_json is not None:
            run.summary_json = summary_json
        self.session.flush()
        return run

    def list_analysis_runs(self, project_id: str) -> list[AnalysisRun]:
        statement = (
            select(AnalysisRun)
            .where(AnalysisRun.project_id == project_id)
            .order_by(AnalysisRun.started_at.desc())
        )
        return list(self.session.scalars(statement))

    def get_analysis_run(self, run_id: str) -> AnalysisRun | None:
        return self.session.get(AnalysisRun, run_id)

    def save_project_config_snapshot(
        self,
        *,
        project_id: str,
        source: str,
        config_json: dict[str, Any],
    ) -> ProjectConfigSnapshot:
        snapshot = ProjectConfigSnapshot(
            project_id=project_id,
            source=source,
            config_json=config_json,
        )
        self.session.add(snapshot)
        self.session.flush()
        return snapshot

    def get_latest_project_config_snapshot(self, project_id: str) -> ProjectConfigSnapshot | None:
        statement = (
            select(ProjectConfigSnapshot)
            .where(ProjectConfigSnapshot.project_id == project_id)
            .order_by(ProjectConfigSnapshot.created_at.desc())
            .limit(1)
        )
        return self.session.scalar(statement)

    def get_project_config_snapshot(self, snapshot_id: str) -> ProjectConfigSnapshot | None:
        return self.session.get(ProjectConfigSnapshot, snapshot_id)

    def list_project_config_snapshots(
        self,
        project_id: str,
        *,
        limit: int = 50,
    ) -> list[ProjectConfigSnapshot]:
        statement = (
            select(ProjectConfigSnapshot)
            .where(ProjectConfigSnapshot.project_id == project_id)
            .order_by(ProjectConfigSnapshot.created_at.desc())
            .limit(limit)
        )
        return list(self.session.scalars(statement))
