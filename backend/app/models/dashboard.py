"""Dashboard aggregate API response models."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlmodel import Field, SQLModel

from app.models.decisions import ProjectDecisionSummaryPublic
from app.models.enums import AnalysisRunStatus
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


class RiskTrendPointPublic(SQLModel):
    """Aggregate open-risk level observed by one analysis run."""

    run_id: uuid.UUID
    started_at: datetime
    finished_at: datetime | None = None
    status: AnalysisRunStatus
    average_risk_score: float | None = None
    max_risk_score: float | None = None
    open_finding_count: int = 0
    counts_by_priority: dict[str, int] = Field(default_factory=dict)
    kev_count: int = 0


class RiskTopDriverPublic(SQLModel):
    """The finding that currently contributes the most operational risk."""

    finding_id: uuid.UUID
    cve_id: str
    priority: str
    risk_score: float | None = None
    in_kev: bool = False
    epss: float | None = None
    component_label: str | None = None
    asset_label: str | None = None
    recommended_action: str | None = None
    score_reasons: list[str] = Field(default_factory=list)


class MitigationAttackTechniquePublic(SQLModel):
    """Reviewed ATT&CK technique context covered by a mitigation lever."""

    technique_id: str
    name: str | None = None
    tactics: list[str] = Field(default_factory=list)
    finding_count: int = 0


class MitigationLeverPublic(SQLModel):
    """One remediation action ranked by the total open risk it would remove."""

    lever_id: str
    action_label: str
    kind: str
    component_name: str | None = None
    component_version: str | None = None
    target_version: str | None = None
    resolved_finding_count: int = 0
    resolved_kev_count: int = 0
    risk_score_sum: float = 0.0
    risk_score_share_percent: int = 0
    projected_average_risk_score: float | None = None
    average_delta: float | None = None
    top_cve_ids: list[str] = Field(default_factory=list)
    roadmap_lane: str = "later"
    roadmap_reason: str = ""
    nist_csf_function: str = "Unclassified"
    nist_csf_reason: str = "No clear control category from current evidence."
    attack_techniques: list[MitigationAttackTechniquePublic] = Field(default_factory=list)
    attack_tactics: list[str] = Field(default_factory=list)


class ProjectRiskInsightsPublic(SQLModel):
    """One-call aggregate for the dashboard risk posture views."""

    project_id: uuid.UUID
    generated_at: datetime
    baseline_average_risk_score: float | None = None
    baseline_open_finding_count: int = 0
    baseline_total_risk_score: float = 0.0
    risk_target_score: float = 30.0
    recommended_lever_id: str | None = None
    trend: list[RiskTrendPointPublic] = Field(default_factory=list)
    top_driver: RiskTopDriverPublic | None = None
    mitigation_levers: list[MitigationLeverPublic] = Field(default_factory=list)
