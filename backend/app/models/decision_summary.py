"""Typed executive projections of immutable finding decision guidance."""

from __future__ import annotations

import uuid

from sqlmodel import Field, SQLModel

from app.domain.engine.models_decision import FindingDecisionGuidance, SlaTarget


class ExecutiveFindingDecisionPublic(SQLModel):
    """One recorded decision with its original scope and guidance."""

    finding_id: uuid.UUID
    cve_id: str
    component: str | None = None
    target: str | None = None
    status: str
    guidance: FindingDecisionGuidance


class RunDecisionSummaryPublic(SQLModel):
    """Executive facts derived solely from one run's immutable decisions."""

    finding_count: int = 0
    actionable_finding_count: int = 0
    findings_with_guidance: int = 0
    missing_guidance_count: int = 0
    recommendation_counts: dict[str, int] = Field(default_factory=dict)
    shortest_actionable_sla: SlaTarget | None = None
    top_decisions: list[ExecutiveFindingDecisionPublic] = Field(default_factory=list)
