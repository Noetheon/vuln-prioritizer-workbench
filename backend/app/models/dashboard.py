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


class RiskContributionPublic(SQLModel):
    """Largest visible contributor to current project risk."""

    dimension: str
    label: str
    risk_score_total: float = 0.0
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    kev_count: int = 0


class RiskReductionOpportunityPublic(SQLModel):
    """Actionable remediation group with its expected score reduction."""

    id: str
    label: str
    cve_id: str
    component: str | None = None
    recommended_action: str
    expected_reduction: float = 0.0
    residual_after: float = 0.0
    finding_count: int = 0
    affected_assets: list[str] = Field(default_factory=list)
    business_services: list[str] = Field(default_factory=list)
    owners: list[str] = Field(default_factory=list)
    max_epss: float | None = None
    max_cvss: float | None = None
    in_kev: bool = False
    search_query: str


class ResidualRiskStepPublic(SQLModel):
    """One step in the dashboard residual-risk ladder."""

    label: str
    risk_score: float = 0.0
    reduction: float = 0.0


class RiskIndexHistoryPointPublic(SQLModel):
    """Persisted risk index of one completed analysis run."""

    run_id: uuid.UUID
    finished_at: datetime
    risk_index: float = 0.0


class ProjectRiskReductionPublic(SQLModel):
    """Risk-reduction opportunities for the project dashboard."""

    current_actionable_risk: float = 0.0
    actionable_finding_count: int = 0
    largest_driver: RiskContributionPublic | None = None
    top_opportunities: list[RiskReductionOpportunityPublic] = Field(default_factory=list)
    residual_steps: list[ResidualRiskStepPublic] = Field(default_factory=list)
    history: list[RiskIndexHistoryPointPublic] = Field(default_factory=list)
    governance_debt_risk: float = 0.0
    methodology: str = (
        "Simulates score reduction by removing open actionable findings when "
        "their remediation opportunity is completed."
    )


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
    risk_reduction: ProjectRiskReductionPublic = Field(default_factory=ProjectRiskReductionPublic)
