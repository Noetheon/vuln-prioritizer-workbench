"""ATT&CK Lite domain models for the template backend."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

from pydantic import field_validator, model_validator
from sqlalchemy import JSON, Column, DateTime, Float, Index, String, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from app.models.base import get_datetime_utc

ATTACK_TECHNIQUE_ID_PATTERN = r"^T\d{4}(?:\.\d{3})?$"
ATTACK_TACTIC_ID_PATTERN = r"^TA\d{4}$"
ATTACK_REVIEW_STATUSES = {"unreviewed", "needs_review", "reviewed", "rejected", "stale"}
ATTACK_MAPPING_TYPES = {
    "exploitation",
    "impact",
    "post_exploitation",
    "mitigation_context",
    "detection_context",
}

_TECHNIQUE_ID_RE = re.compile(ATTACK_TECHNIQUE_ID_PATTERN)
_TACTIC_ID_RE = re.compile(ATTACK_TACTIC_ID_PATTERN)


def _require_non_empty(value: str, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} is required.")
    return normalized


def _validate_technique_id(value: str) -> str:
    normalized = value.strip()
    if not _TECHNIQUE_ID_RE.fullmatch(normalized):
        raise ValueError("ATT&CK technique IDs must match T#### or T####.###.")
    return normalized


def _validate_tactic_id(value: str) -> str:
    normalized = value.strip()
    if not _TACTIC_ID_RE.fullmatch(normalized):
        raise ValueError("ATT&CK tactic IDs must match TA####.")
    return normalized


class AttackTacticBase(SQLModel):
    """Shared ATT&CK tactic fields."""

    tactic_id: str = Field(min_length=6, max_length=16)
    name: str = Field(min_length=1, max_length=200)
    short_name: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    attack_version: str | None = Field(default=None, max_length=40)
    url: str | None = Field(default=None, max_length=500)

    @field_validator("tactic_id")
    @classmethod
    def validate_tactic_id(cls, value: str) -> str:
        return _validate_tactic_id(value)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _require_non_empty(value, "name")


class AttackTactic(AttackTacticBase, table=True):
    """Persisted ATT&CK tactic metadata."""

    __tablename__ = "attack_tactic"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    tactic_id: str = Field(min_length=6, max_length=16, unique=True, index=True)
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class AttackTacticPublic(AttackTacticBase):
    """Public ATT&CK tactic response shape."""

    id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class AttackTechniqueBase(SQLModel):
    """Shared ATT&CK technique fields."""

    technique_id: str = Field(min_length=5, max_length=16)
    name: str = Field(min_length=1, max_length=300)
    tactic_ids_json: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    description: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    attack_version: str | None = Field(default=None, max_length=40)
    url: str | None = Field(default=None, max_length=500)
    revoked: bool = False
    deprecated: bool = False
    defensive_note: str | None = Field(default=None, sa_column=Column(Text, nullable=True))

    @field_validator("technique_id")
    @classmethod
    def validate_technique_id(cls, value: str) -> str:
        return _validate_technique_id(value)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _require_non_empty(value, "name")

    @model_validator(mode="after")
    def validate_tactic_ids(self) -> AttackTechniqueBase:
        for tactic_id in self.tactic_ids_json:
            _validate_tactic_id(tactic_id)
        return self


class AttackTechnique(AttackTechniqueBase, table=True):
    """Persisted ATT&CK technique or sub-technique metadata."""

    __tablename__ = "attack_technique"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    technique_id: str = Field(min_length=5, max_length=16, unique=True, index=True)
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class AttackTechniquePublic(AttackTechniqueBase):
    """Public ATT&CK technique response shape."""

    id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class AttackStixSnapshotBase(SQLModel):
    """Shared versioned ATT&CK STIX snapshot catalog fields."""

    attack_version: str = Field(min_length=1, max_length=40)
    domain: str = Field(min_length=1, max_length=80)
    stix_spec_version: str | None = Field(default=None, max_length=40)
    bundle_sha256: str = Field(min_length=64, max_length=64)
    source_path: str | None = Field(default=None, max_length=1000)
    object_counts_json: dict[str, int] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    source_metadata_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )

    @field_validator("attack_version", "domain", "bundle_sha256")
    @classmethod
    def validate_required_snapshot_text(cls, value: str, info: Any) -> str:
        return _require_non_empty(value, str(info.field_name))


class AttackStixSnapshot(AttackStixSnapshotBase, table=True):
    """Persisted versioned ATT&CK STIX bundle import."""

    __tablename__ = "attack_stix_snapshot"
    __table_args__ = (
        UniqueConstraint("bundle_sha256", name="uq_attack_stix_snapshot_bundle_sha256"),
        Index("ix_attack_stix_snapshot_domain_version", "domain", "attack_version"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    provider_snapshot_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="provider_snapshot.id",
        index=True,
        ondelete="SET NULL",
    )
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class AttackStixSnapshotPublic(AttackStixSnapshotBase):
    """Public ATT&CK STIX snapshot response shape."""

    id: uuid.UUID
    provider_snapshot_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class AttackStixTacticBase(SQLModel):
    """Shared tactic row for one imported ATT&CK STIX snapshot."""

    stix_id: str = Field(min_length=1, max_length=120)
    tactic_id: str = Field(min_length=6, max_length=16)
    name: str = Field(min_length=1, max_length=200)
    short_name: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    url: str | None = Field(default=None, max_length=500)
    revoked: bool = False
    deprecated: bool = False

    @field_validator("tactic_id")
    @classmethod
    def validate_tactic_id(cls, value: str) -> str:
        return _validate_tactic_id(value)

    @field_validator("name", "stix_id")
    @classmethod
    def validate_required_text(cls, value: str, info: Any) -> str:
        return _require_non_empty(value, str(info.field_name))


class AttackStixTactic(AttackStixTacticBase, table=True):
    """Persisted tactic catalog row for one imported STIX snapshot."""

    __tablename__ = "attack_stix_tactic"
    __table_args__ = (
        UniqueConstraint(
            "snapshot_id",
            "tactic_id",
            name="uq_attack_stix_tactic_snapshot_tactic",
        ),
        Index("ix_attack_stix_tactic_tactic_id", "tactic_id"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    snapshot_id: uuid.UUID = Field(
        foreign_key="attack_stix_snapshot.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class AttackStixTechniqueBase(SQLModel):
    """Shared technique row for one imported ATT&CK STIX snapshot."""

    stix_id: str = Field(min_length=1, max_length=120)
    technique_id: str = Field(min_length=5, max_length=16)
    name: str = Field(min_length=1, max_length=300)
    tactic_ids_json: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    tactic_short_names_json: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    description: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    url: str | None = Field(default=None, max_length=500)
    revoked: bool = False
    deprecated: bool = False
    is_subtechnique: bool = False

    @field_validator("technique_id")
    @classmethod
    def validate_technique_id(cls, value: str) -> str:
        return _validate_technique_id(value)

    @field_validator("name", "stix_id")
    @classmethod
    def validate_required_text(cls, value: str, info: Any) -> str:
        return _require_non_empty(value, str(info.field_name))

    @model_validator(mode="after")
    def validate_snapshot_tactic_ids(self) -> AttackStixTechniqueBase:
        for tactic_id in self.tactic_ids_json:
            _validate_tactic_id(tactic_id)
        return self


class AttackStixTechnique(AttackStixTechniqueBase, table=True):
    """Persisted technique catalog row for one imported STIX snapshot."""

    __tablename__ = "attack_stix_technique"
    __table_args__ = (
        UniqueConstraint(
            "snapshot_id",
            "technique_id",
            name="uq_attack_stix_technique_snapshot_technique",
        ),
        Index("ix_attack_stix_technique_technique_id", "technique_id"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    snapshot_id: uuid.UUID = Field(
        foreign_key="attack_stix_snapshot.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class AttackStixMitigationBase(SQLModel):
    """Shared mitigation row for one imported ATT&CK STIX snapshot."""

    stix_id: str = Field(min_length=1, max_length=120)
    mitigation_id: str = Field(min_length=5, max_length=16)
    name: str = Field(min_length=1, max_length=300)
    description: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    url: str | None = Field(default=None, max_length=500)
    revoked: bool = False
    deprecated: bool = False

    @field_validator("name", "stix_id", "mitigation_id")
    @classmethod
    def validate_required_text(cls, value: str, info: Any) -> str:
        return _require_non_empty(value, str(info.field_name))


class AttackStixMitigation(AttackStixMitigationBase, table=True):
    """Persisted mitigation catalog row for one imported STIX snapshot."""

    __tablename__ = "attack_stix_mitigation"
    __table_args__ = (
        UniqueConstraint(
            "snapshot_id",
            "mitigation_id",
            name="uq_attack_stix_mitigation_snapshot_mitigation",
        ),
        Index("ix_attack_stix_mitigation_mitigation_id", "mitigation_id"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    snapshot_id: uuid.UUID = Field(
        foreign_key="attack_stix_snapshot.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class AttackStixTechniqueMitigationBase(SQLModel):
    """Shared relationship row linking a STIX mitigation to a technique."""

    relationship_id: str = Field(min_length=1, max_length=120)
    technique_id: str = Field(min_length=5, max_length=16)
    mitigation_id: str = Field(min_length=5, max_length=16)
    description: str | None = Field(default=None, sa_column=Column(Text, nullable=True))

    @field_validator("technique_id")
    @classmethod
    def validate_technique_id(cls, value: str) -> str:
        return _validate_technique_id(value)

    @field_validator("relationship_id", "mitigation_id")
    @classmethod
    def validate_required_text(cls, value: str, info: Any) -> str:
        return _require_non_empty(value, str(info.field_name))


class AttackStixTechniqueMitigation(AttackStixTechniqueMitigationBase, table=True):
    """Persisted mitigation relationship row for one imported STIX snapshot."""

    __tablename__ = "attack_stix_technique_mitigation"
    __table_args__ = (
        UniqueConstraint(
            "snapshot_id",
            "technique_id",
            "mitigation_id",
            "relationship_id",
            name="uq_attack_stix_technique_mitigation_snapshot_relationship",
        ),
        Index(
            "ix_attack_stix_technique_mitigation_technique",
            "snapshot_id",
            "technique_id",
        ),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    snapshot_id: uuid.UUID = Field(
        foreign_key="attack_stix_snapshot.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class CveAttackMappingBase(SQLModel):
    """Shared curated CVE-to-ATT&CK mapping fields."""

    cve_id: str = Field(min_length=13, max_length=64)
    technique_id: str = Field(min_length=5, max_length=16)
    technique_name: str | None = Field(default=None, max_length=300)
    tactic_ids_json: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    mapping_type: str = Field(default="exploitation", sa_column=Column(String(80), nullable=False))
    source: str = Field(min_length=1, max_length=200)
    source_url: str | None = Field(default=None, max_length=500)
    confidence: float = Field(ge=0.0, le=1.0, sa_column=Column(Float, nullable=False))
    rationale: str = Field(sa_column=Column(Text, nullable=False))
    review_status: str = Field(
        default="unreviewed",
        sa_column=Column(String(80), nullable=False),
    )
    defensive_note: str = Field(sa_column=Column(Text, nullable=False))
    references_json: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    metadata_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )

    @field_validator("technique_id")
    @classmethod
    def validate_technique_id(cls, value: str) -> str:
        return _validate_technique_id(value)

    @field_validator("source", "rationale", "defensive_note")
    @classmethod
    def validate_required_text(cls, value: str, info: Any) -> str:
        return _require_non_empty(value, str(info.field_name))

    @field_validator("review_status")
    @classmethod
    def validate_review_status(cls, value: str) -> str:
        normalized = value.strip()
        if normalized not in ATTACK_REVIEW_STATUSES:
            raise ValueError(f"review_status must be one of {sorted(ATTACK_REVIEW_STATUSES)}.")
        return normalized

    @field_validator("mapping_type")
    @classmethod
    def validate_mapping_type(cls, value: str) -> str:
        normalized = value.strip()
        if normalized not in ATTACK_MAPPING_TYPES:
            raise ValueError(f"mapping_type must be one of {sorted(ATTACK_MAPPING_TYPES)}.")
        return normalized

    @model_validator(mode="after")
    def validate_tactic_ids(self) -> CveAttackMappingBase:
        for tactic_id in self.tactic_ids_json:
            _validate_tactic_id(tactic_id)
        return self


class CveAttackMapping(CveAttackMappingBase, table=True):
    """Persisted curated CVE-to-ATT&CK mapping."""

    __tablename__ = "cve_attack_mapping"
    __table_args__ = (
        UniqueConstraint(
            "source",
            "cve_id",
            "technique_id",
            "mapping_type",
            name="uq_cve_attack_mapping_source_cve_technique_type",
        ),
        Index("ix_cve_attack_mapping_cve_id", "cve_id"),
        Index("ix_cve_attack_mapping_technique_id", "technique_id"),
        Index("ix_cve_attack_mapping_review_status", "review_status"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    vulnerability_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="vulnerability.id",
        index=True,
        ondelete="SET NULL",
    )
    technique_id: str = Field(
        min_length=5,
        max_length=16,
        foreign_key="attack_technique.technique_id",
        nullable=False,
    )
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class CveAttackMappingPublic(CveAttackMappingBase):
    """Public curated CVE-to-ATT&CK mapping response shape."""

    id: uuid.UUID
    vulnerability_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


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
        return _require_non_empty(value, str(info.field_name))

    @field_validator("review_status")
    @classmethod
    def validate_review_status(cls, value: str) -> str:
        normalized = value.strip()
        if normalized not in ATTACK_REVIEW_STATUSES:
            raise ValueError(f"review_status must be one of {sorted(ATTACK_REVIEW_STATUSES)}.")
        return normalized

    @model_validator(mode="after")
    def validate_context_ids(self) -> FindingAttackContextBase:
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
