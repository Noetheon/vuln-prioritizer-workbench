"""Workbench status and local demo workspace DTOs."""

from __future__ import annotations

import uuid

from sqlmodel import Field, SQLModel

from app.models.projects import ProjectPublic
from app.models.reports import ReportPublic
from app.models.runs import AnalysisRunPublic


class WorkbenchStatus(SQLModel):
    """Status response returned by the active Workbench runtime."""

    status: str
    app: str
    core_package: str
    core_version: str
    database_status: str
    schema_status: str


class WorkbenchHealth(SQLModel):
    """Minimal local health response."""

    status: str


class DemoWorkspaceCreate(SQLModel):
    """Request payload for creating or resetting the local demo workspace."""

    reset: bool = False


class DemoWorkspaceStatusPublic(SQLModel):
    """Status for the optional local demo workspace."""

    enabled: bool
    seeded: bool = False
    project_id: uuid.UUID | None = None
    project_name: str | None = None
    latest_run_id: uuid.UUID | None = None
    finding_count: int = 0
    asset_count: int = 0
    report_count: int = 0
    waiver_count: int = 0
    message: str | None = None


class DemoWorkspacePublic(DemoWorkspaceStatusPublic):
    """Materialized local demo workspace response."""

    project: ProjectPublic
    latest_run: AnalysisRunPublic
    reports: list[ReportPublic] = Field(default_factory=list)
