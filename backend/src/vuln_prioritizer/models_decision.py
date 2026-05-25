"""Decision guidance models for recommendation and SLA output."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from vuln_prioritizer.model_base import StrictModel

DecisionRecommendation = Literal["patch", "mitigate", "monitor", "review", "waiver"]


class SlaTarget(StrictModel):
    """Data representation and logic for Sla Target."""

    priority: str
    label: str
    target_hours: int | None = None
    target_days: int | None = None
    guidance: str
    source: str = "default-priority-sla"


class BusinessImpactBlock(StrictModel):
    """Data representation and logic for Business Impact Block."""

    level: Literal["critical", "high", "medium", "low", "governance"]
    text: str
    drivers: list[str] = Field(default_factory=list)


class FindingDecisionGuidance(StrictModel):
    """Data representation and logic for Finding Decision Guidance."""

    recommendation: DecisionRecommendation
    recommendation_label: str
    sla: SlaTarget
    business_impact: BusinessImpactBlock
    decision_statement: str
    visibility: str
    wording_policy: str = "defensive_no_exploit_steps"
    reason_codes: list[str] = Field(default_factory=list)
