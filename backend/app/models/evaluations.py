"""Native reevaluation requests and immutable decision revision history."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EvaluationCreate(BaseModel):
    """Choose existing observations and optional recorded provider facts."""

    model_config = ConfigDict(extra="forbid")
    provider_snapshot_id: uuid.UUID | None = None
    finding_ids: list[uuid.UUID] | None = Field(default=None, min_length=1, max_length=10000)
    reason: str | None = Field(default=None, min_length=1, max_length=1000)

    @field_validator("finding_ids")
    @classmethod
    def unique_findings(cls, value: list[uuid.UUID] | None) -> list[uuid.UUID] | None:
        """Reject accidental duplicate scope selection."""
        if value is not None and len(value) != len(set(value)):
            raise ValueError("finding_ids must contain unique finding IDs.")
        return value


class DecisionRevisionPublic(BaseModel):
    """One immutable historical decision, compared with its predecessor."""

    id: uuid.UUID
    analysis_run_id: uuid.UUID
    evaluated_at: datetime
    observed_at: datetime | None = None
    cause: str
    provider_snapshot_id: uuid.UUID | None = None
    engine_version: str | None = None
    input_sha256: str | None = None
    replay_status: Literal["available", "legacy_unavailable"]
    priority: str
    status: str
    risk_score: float | None = None
    operational_rank: int
    rationale: str | None = None
    recommended_action: str | None = None
    is_current: bool
    changed_fields: list[str] = Field(default_factory=list)

    @field_validator("evaluated_at", "observed_at")
    @classmethod
    def utc_timestamps(cls, value: datetime | None) -> datetime | None:
        """SQLite stores UTC timestamps without their timezone annotation."""
        return value.replace(tzinfo=UTC) if value is not None and value.tzinfo is None else value


class DecisionRevisionsPublic(BaseModel):
    """Paginated immutable history, newest first."""

    data: list[DecisionRevisionPublic]
    count: int
