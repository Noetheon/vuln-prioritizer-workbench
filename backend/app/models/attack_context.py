"""Finding-level ATT&CK context models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import field_validator, model_validator
from sqlalchemy import JSON, Column, DateTime, Index, String, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from app.models.attack_common import (
    ATTACK_REVIEW_STATUSES,
    require_non_empty,
)
from app.models.attack_common import (
    validate_tactic_id as _validate_tactic_id,
)
from app.models.attack_common import (
    validate_technique_id as _validate_technique_id,
)
from app.models.base import get_datetime_utc


class FindingAttackContextBase(SQLModel):
    """Shared finding-level ATT&CK context fields."""

    cve_id: str = Field(min_length=13, max_length=64)
    mapped: bool = False
    source: str = Field(default="none", min_length=1, max_length=200)
    review_status: str = Field(
        default="unreviewed",
        sa_column=Column(String(80), nullable=False),
    )
    defensive_note: str = Field(sa_column=Column(Text, nullable=False))
    rationale: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    technique_ids_json: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    tactic_ids_json: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    mappings_json: list[dict[str, Any]] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )

    @field_validator("source", "defensive_note")
    @classmethod
    def validate_required_text(cls, value: str, info: Any) -> str:
        """Validate the required text field."""
        return require_non_empty(value, str(info.field_name))

    @field_validator("review_status")
    @classmethod
    def validate_review_status(cls, value: str) -> str:
        """Validate the review status field."""
        normalized = value.strip()
        if normalized not in ATTACK_REVIEW_STATUSES:
            raise ValueError(f"review_status must be one of {sorted(ATTACK_REVIEW_STATUSES)}.")
        return normalized

    @model_validator(mode="after")
    def validate_context_ids(self) -> FindingAttackContextBase:
        """Validate the context ids field."""
        for technique_id in self.technique_ids_json:
            _validate_technique_id(technique_id)
        for tactic_id in self.tactic_ids_json:
            _validate_tactic_id(tactic_id)
        if self.mapped and not self.mappings_json:
            raise ValueError("mapped finding ATT&CK context requires at least one mapping.")
        return self


class FindingAttackContext(FindingAttackContextBase, table=True):
    """Persisted ATT&CK context for one finding in one analysis run."""

    __tablename__ = "finding_attack_context"
    __table_args__ = (
        UniqueConstraint(
            "finding_id",
            "analysis_run_id",
            name="uq_finding_attack_context_finding_run",
        ),
        Index("ix_finding_attack_context_run_review", "analysis_run_id", "review_status"),
        Index("ix_finding_attack_context_cve_id", "cve_id"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    finding_id: uuid.UUID = Field(
        foreign_key="finding.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    analysis_run_id: uuid.UUID = Field(
        foreign_key="analysis_run.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class FindingAttackContextPublic(FindingAttackContextBase):
    """Public finding ATT&CK context response shape."""

    id: uuid.UUID
    finding_id: uuid.UUID
    analysis_run_id: uuid.UUID
    created_at: datetime
    updated_at: datetime
