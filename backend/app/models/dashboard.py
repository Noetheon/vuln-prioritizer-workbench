"""Dashboard aggregate API response models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

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
    component_identity: str | None = None
    finding_ids: list[uuid.UUID] = Field(default_factory=list)
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
    actionable_finding_count: int = 0
    risk_index: float = 0.0


class RiskIndexHistoryPointPublic(SQLModel):
    """Open risk recorded when one analysis run completed."""

    run_id: uuid.UUID
    finished_at: datetime
    # Secondary figure: the average score of open findings.
    risk_index: float = 0.0
    # Absolute figures; None for runs recorded before they were kept.
    open_risk: float | None = None
    open_findings: int | None = None
    open_critical: int | None = None
    open_kev: int | None = None


class ProjectRiskKpisPublic(SQLModel):
    """Absolute risk KPIs of a project's open work, as defined in issue #674."""

    metric: Literal["open-risk-kpis.v1"] = "open-risk-kpis.v1"
    open_findings: int = 0
    open_by_priority: dict[str, int] = Field(default_factory=dict)
    open_critical: int = 0
    open_high: int = 0
    open_kev: int = 0
    overdue: int = 0
    due_soon: int = 0
    # Sum of the operational scores of open work; closing findings lowers it.
    open_risk: float = 0.0
    mean_open_score: float = 0.0
    accepted_findings: int = 0
    accepted_risk: float = 0.0
    # Closures (resolved or fixed) in the last `closure_window_days` days.
    closure_window_days: int = 90
    closed_findings: int = 0
    mttr_days: float | None = None
    closed_with_sla: int = 0
    closed_within_sla: int = 0
    sla_compliance_rate: float | None = None


class ProjectRiskReductionPublic(SQLModel):
    """Risk-reduction opportunities for the project dashboard."""

    current_actionable_risk: float = 0.0
    current_risk_index: float = 0.0
    # v2 leads with the absolute open risk; the mean is a secondary figure.
    metric: Literal["open-risk-sum.v2"] = "open-risk-sum.v2"
    actionable_finding_count: int = 0
    largest_driver: RiskContributionPublic | None = None
    top_opportunities: list[RiskReductionOpportunityPublic] = Field(default_factory=list)
    residual_steps: list[ResidualRiskStepPublic] = Field(default_factory=list)
    history: list[RiskIndexHistoryPointPublic] = Field(default_factory=list)
    governance_debt_risk: float = 0.0
    methodology: str = (
        "Open risk is the sum of the scores of open, in-review, and remediating "
        "findings that are neither accepted nor suppressed by VEX. It rises when "
        "findings are added and falls when they are closed. The simulation removes "
        "the scores of the checked remediation groups. The average score of open "
        "findings is shown as a secondary figure. Historical imports can cover "
        "different evidence and are not proof of remediation."
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
    kpis: ProjectRiskKpisPublic = Field(default_factory=ProjectRiskKpisPublic)
