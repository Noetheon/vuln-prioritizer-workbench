"""ATT&CK summary projection models."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlmodel import Field, SQLModel


@dataclass(frozen=True)
class AttackSummaryFindingRow:
    """Lightweight finding projection for ATT&CK summary aggregates."""

    id: uuid.UUID
    risk_score: float | None


@dataclass(frozen=True)
class AttackSummaryContextRow:
    """Lightweight ATT&CK context projection for summary aggregates."""

    finding_id: uuid.UUID
    mapped: bool
    technique_ids_json: list[str]
    tactic_ids_json: list[str]
    mappings_json: list[dict[str, Any]]
    review_status: str
    source: str | None
    created_at: datetime


class ProjectAttackTechniqueSummaryPublic(SQLModel):
    """Dashboard row for a top ATT&CK technique across project findings."""

    technique_id: str
    name: str | None = None
    tactics: list[str] = Field(default_factory=list)
    finding_count: int = 0
    risk_score_total: float = 0.0
    highest_risk_score: float = 0.0
    confidence_counts: dict[str, int] = Field(default_factory=dict)
    review_status_counts: dict[str, int] = Field(default_factory=dict)
    source_counts: dict[str, int] = Field(default_factory=dict)


class ProjectAttackTacticSummaryPublic(SQLModel):
    """Dashboard row for a top ATT&CK tactic across project findings."""

    tactic: str
    finding_count: int = 0
    technique_count: int = 0
    risk_score_total: float = 0.0


class ProjectAttackSummaryPublic(SQLModel):
    """Project-level ATT&CK summary for the React dashboard widget."""

    project_id: uuid.UUID
    finding_count: int = 0
    mapped_finding_count: int = 0
    unmapped_finding_count: int = 0
    mapped_coverage_percent: float = 0.0
    top_techniques: list[ProjectAttackTechniqueSummaryPublic] = Field(default_factory=list)
    top_tactics: list[ProjectAttackTacticSummaryPublic] = Field(default_factory=list)
    confidence_distribution: dict[str, int] = Field(default_factory=dict)
    review_status_counts: dict[str, int] = Field(default_factory=dict)
    source_counts: dict[str, int] = Field(default_factory=dict)
    defensive_note: str = (
        "ATT&CK summary is defensive triage context only. "
        "Mappings are reviewed inputs, not generated exploit guidance."
    )
