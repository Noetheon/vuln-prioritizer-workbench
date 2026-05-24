"""Governance rollup response models for the Workbench."""

import uuid
from datetime import date, datetime

from sqlmodel import Field, SQLModel


class GovernanceRollupPublic(SQLModel):
    """Aggregated finding risk for one owner, service, asset, or environment."""

    dimension: str
    label: str
    finding_count: int = 0
    open_count: int = 0
    accepted_count: int = 0
    fixed_count: int = 0
    suppressed_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    kev_count: int = 0
    attack_mapped_count: int = 0
    suppressed_by_vex_count: int = 0
    under_investigation_count: int = 0
    waived_count: int = 0
    expired_waiver_count: int = 0
    review_due_waiver_count: int = 0
    risk_score_total: float = 0.0
    risk_score_max: float | None = None
    highest_priority: str | None = None
    priority_counts: dict[str, int] = Field(default_factory=dict)
    status_counts: dict[str, int] = Field(default_factory=dict)
    top_cves: list[str] = Field(default_factory=list)


class GovernanceWaiverDebtEntryPublic(SQLModel):
    """One waiver lifecycle row in the aggregate debt view."""

    id: uuid.UUID
    owner: str
    scope: str
    status: str
    days_remaining: int
    expires_at: date
    review_at: date | None = None
    matched_findings: int = 0
    cve_id: str | None = None
    service: str | None = None
    asset_key: str | None = None
    finding_id: uuid.UUID | None = None
    reason: str | None = None
    approval_ref: str | None = None
    ticket_url: str | None = None


class GovernanceWaiverDebtPublic(SQLModel):
    """Project-level accepted-risk lifecycle debt summary."""

    waiver_count: int = 0
    active_count: int = 0
    review_due_count: int = 0
    expired_count: int = 0
    expiring_soon_count: int = 0
    matched_finding_count: int = 0
    accepted_finding_count: int = 0
    expired_finding_count: int = 0
    review_due_finding_count: int = 0
    owner_counts: dict[str, int] = Field(default_factory=dict)
    service_counts: dict[str, int] = Field(default_factory=dict)
    items: list[GovernanceWaiverDebtEntryPublic] = Field(default_factory=list)


class ProjectGovernanceRollupsPublic(SQLModel):
    """Owner, service, asset, environment, and waiver-debt rollups for one project."""

    project_id: uuid.UUID
    generated_at: datetime
    owners: list[GovernanceRollupPublic] = Field(default_factory=list)
    services: list[GovernanceRollupPublic] = Field(default_factory=list)
    assets: list[GovernanceRollupPublic] = Field(default_factory=list)
    environments: list[GovernanceRollupPublic] = Field(default_factory=list)
    top_services_by_risk: list[GovernanceRollupPublic] = Field(default_factory=list)
    top_assets_by_risk: list[GovernanceRollupPublic] = Field(default_factory=list)
    waiver_debt: GovernanceWaiverDebtPublic = Field(default_factory=GovernanceWaiverDebtPublic)
