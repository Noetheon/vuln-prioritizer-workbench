"""Decision API response models for template Workbench routes."""

from __future__ import annotations

import uuid
from typing import Any

from sqlmodel import Field, SQLModel

from app.models.enums import AnalysisRunStatus, FindingPriority


class FindingExplanationPublic(SQLModel):
    """Structured decision explanation for one persisted finding."""

    finding_id: uuid.UUID
    project_id: uuid.UUID
    cve_id: str
    priority: FindingPriority
    priority_rank: int
    priority_state: str | None = None
    risk_score: float | None = None
    operational_rank: int = 0
    rationale: str | None = None
    recommended_action: str | None = None
    decision_guidance: dict[str, Any] | None = None
    decision_explanation: dict[str, Any] | None = None
    provider_evidence: dict[str, Any] | None = None
    data_quality_flags: list[dict[str, Any]] = Field(default_factory=list)
    data_quality_confidence: str = "high"
    explanation: dict[str, Any] = Field(default_factory=dict)


class ProjectDecisionSummaryPublic(SQLModel):
    """Dashboard-oriented decision summary for one visible project."""

    project_id: uuid.UUID
    finding_count: int = 0
    open_finding_count: int = 0
    counts_by_priority: dict[str, int] = Field(default_factory=dict)
    counts_by_status: dict[str, int] = Field(default_factory=dict)
    kev_hits: int = 0
    epss_hits: int = 0
    cvss_known_count: int = 0
    provider_degraded: bool = False
    latest_run_id: uuid.UUID | None = None
    latest_run_status: AnalysisRunStatus | None = None
    latest_run_summary: dict[str, Any] = Field(default_factory=dict)


class ProjectCvssOnlyComparisonPublic(SQLModel):
    """CVSS-only baseline comparison for stored template findings."""

    project_id: uuid.UUID
    methodology: dict[str, Any]
    summary: dict[str, int]
    counts: dict[str, dict[str, int]]
    top_changes: list[dict[str, Any]] = Field(default_factory=list)
    comparisons: list[dict[str, Any]] = Field(default_factory=list)
