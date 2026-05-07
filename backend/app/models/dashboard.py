"""Dashboard aggregate API response models."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlmodel import Field, SQLModel

from app.models.decisions import ProjectDecisionSummaryPublic
from app.models.findings import FindingsPublic
from app.models.governance import ProjectGovernanceRollupsPublic
from app.models.runs import AnalysisRunsPublic


class DashboardEpssBucketsPublic(SQLModel):
    """EPSS bucket counts for the Workbench dashboard."""

    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0


class DashboardSignalCountsPublic(SQLModel):
    """Dashboard signal counts that previously required multiple findings queries."""

    high_epss: int = 0
    internet_facing_criticals: int = 0
    epss_buckets: DashboardEpssBucketsPublic = Field(default_factory=DashboardEpssBucketsPublic)


class ProjectDashboardFindingsPublic(SQLModel):
    """Findings data needed by the Workbench dashboard."""

    remediation_queue: FindingsPublic
    signal_counts: DashboardSignalCountsPublic


class ProjectDashboardPublic(SQLModel):
    """One-call aggregate for the project dashboard route."""

    project_id: uuid.UUID
    generated_at: datetime
    summary: ProjectDecisionSummaryPublic
    governance: ProjectGovernanceRollupsPublic
    runs: AnalysisRunsPublic
    findings: ProjectDashboardFindingsPublic
