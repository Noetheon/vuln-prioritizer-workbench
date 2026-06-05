"""ATT&CK enrichment models."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.domain.engine.model_base import StrictModel

ATTACK_TECHNIQUE_ID_PATTERN = r"^T\d{4}(?:\.\d{3})?$"
ATTACK_TACTIC_ID_PATTERN = r"^TA\d{4}$"
ATTACK_REVIEW_STATUSES = ("unreviewed", "needs_review", "reviewed", "rejected", "stale")
ATTACK_CONFIDENCE_LEVELS = ("low", "medium", "high")
ATTACK_MAPPING_TYPES = (
    "exploitation",
    "impact",
    "post_exploitation",
    "mitigation_context",
    "detection_context",
)

_TECHNIQUE_ID_RE = re.compile(ATTACK_TECHNIQUE_ID_PATTERN)
_TACTIC_ID_RE = re.compile(ATTACK_TACTIC_ID_PATTERN)

AttackReviewStatus = Literal["unreviewed", "needs_review", "reviewed", "rejected", "stale"]
AttackConfidence = Literal["low", "medium", "high"]
AttackMappingType = Literal[
    "exploitation",
    "impact",
    "post_exploitation",
    "mitigation_context",
    "detection_context",
]


def _require_non_empty(value: str, field_name: str) -> str:
    """Require non empty function."""
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} is required.")
    return normalized


def _validate_attack_technique_id(value: str) -> str:
    """Validate attack technique id function."""
    normalized = value.strip()
    if not _TECHNIQUE_ID_RE.fullmatch(normalized):
        raise ValueError("ATT&CK technique IDs must match T#### or T####.###.")
    return normalized


def _validate_attack_tactic_id(value: str) -> str:
    """Validate attack tactic id function."""
    normalized = value.strip()
    if not _TACTIC_ID_RE.fullmatch(normalized):
        raise ValueError("ATT&CK tactic IDs must match TA####.")
    return normalized


def require_attack_non_empty_text(value: str, field_name: str) -> str:
    """Normalize and validate required ATT&CK text fields."""
    return _require_non_empty(value, field_name)


def validate_attack_technique_id(value: str) -> str:
    """Normalize and validate an ATT&CK technique or sub-technique ID."""
    return _validate_attack_technique_id(value)


def validate_attack_tactic_id(value: str) -> str:
    """Normalize and validate an ATT&CK tactic ID."""
    return _validate_attack_tactic_id(value)


class AttackTactic(StrictModel):
    """Data representation and logic for Attack Tactic."""

    tactic_id: str
    name: str
    short_name: str | None = None
    description: str | None = None
    attack_version: str | None = None
    url: str | None = None

    @field_validator("tactic_id")
    @classmethod
    def validate_tactic_id(cls, value: str) -> str:
        """Validate the tactic id field."""
        return validate_attack_tactic_id(value)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        """Validate the name field."""
        return require_attack_non_empty_text(value, "name")


class AttackMapping(StrictModel):
    """Data representation and logic for Attack Mapping."""

    capability_id: str
    attack_object_id: str
    attack_object_name: str | None = None
    mapping_type: str | None = None
    capability_group: str | None = None
    capability_description: str | None = None
    comments: str | None = None
    source: str | None = None
    confidence: AttackConfidence | None = None
    review_status: AttackReviewStatus | None = None
    defensive_note: str | None = None
    reviewer: str | None = None
    reviewed_at: str | None = None
    references: list[str] = Field(default_factory=list)


class AttackTechnique(StrictModel):
    """Data representation and logic for Attack Technique."""

    attack_object_id: str
    name: str
    tactics: list[str] = Field(default_factory=list)
    url: str | None = None
    revoked: bool = False
    deprecated: bool = False

    @field_validator("attack_object_id")
    @classmethod
    def validate_attack_object_id(cls, value: str) -> str:
        """Validate the attack object id field."""
        return validate_attack_technique_id(value)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        """Validate the name field."""
        return require_attack_non_empty_text(value, "name")


class CveAttackMapping(StrictModel):
    """Data representation and logic for Cve Attack Mapping."""

    cve_id: str
    technique_id: str
    technique_name: str | None = None
    tactic_ids: list[str] = Field(default_factory=list)
    mapping_type: AttackMappingType = "exploitation"
    source: str
    source_url: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    review_status: AttackReviewStatus = "unreviewed"
    defensive_note: str
    references: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("technique_id")
    @classmethod
    def validate_technique_id(cls, value: str) -> str:
        """Validate the technique id field."""
        return validate_attack_technique_id(value)

    @field_validator("source", "rationale", "defensive_note")
    @classmethod
    def validate_required_text(cls, value: str, info: object) -> str:
        """Validate the required text field."""
        field_name = getattr(info, "field_name", "value")
        return require_attack_non_empty_text(value, str(field_name))

    @model_validator(mode="after")
    def validate_tactics(self) -> CveAttackMapping:
        """Validate the tactics field."""
        for tactic_id in self.tactic_ids:
            validate_attack_tactic_id(tactic_id)
        return self


class FindingAttackContext(StrictModel):
    """Data representation and logic for Finding Attack Context."""

    finding_id: str
    cve_id: str
    mapped: bool = False
    mappings: list[CveAttackMapping] = Field(default_factory=list)
    techniques: list[AttackTechnique] = Field(default_factory=list)
    tactics: list[AttackTactic] = Field(default_factory=list)
    review_status: AttackReviewStatus = "unreviewed"
    defensive_note: str | None = None

    @model_validator(mode="after")
    def require_mappings_when_mapped(self) -> FindingAttackContext:
        """Require mappings when mapped method for FindingAttackContext."""
        if self.mapped and not self.mappings:
            raise ValueError("mapped finding ATT&CK context requires at least one mapping.")
        return self


class FindingAttackContextSummary(StrictModel):
    """Data representation and logic for Finding Attack Context Summary."""

    cve_id: str = ""
    mapped: bool = False
    source: str = "none"
    source_version: str | None = None
    attack_version: str | None = None
    domain: str | None = None
    attack_relevance: str = "Unmapped"
    rationale: str | None = None
    confidence: AttackConfidence | None = None
    low_confidence: bool = False
    techniques: list[AttackTechnique] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    mappings: list[AttackMapping] = Field(default_factory=list)


class AttackSummary(StrictModel):
    """Data representation and logic for Attack Summary."""

    mapped_cves: int = 0
    unmapped_cves: int = 0
    mapping_type_distribution: dict[str, int] = Field(default_factory=dict)
    technique_distribution: dict[str, int] = Field(default_factory=dict)
    tactic_distribution: dict[str, int] = Field(default_factory=dict)


class AttackData(StrictModel):
    """Data representation and logic for Attack Data."""

    cve_id: str
    mapped: bool = False
    source: str = "none"
    source_version: str | None = None
    attack_version: str | None = None
    domain: str | None = None
    mappings: list[AttackMapping] = Field(default_factory=list)
    techniques: list[AttackTechnique] = Field(default_factory=list)
    mapping_types: list[str] = Field(default_factory=list)
    capability_groups: list[str] = Field(default_factory=list)
    attack_relevance: str = "Unmapped"
    attack_rationale: str | None = None
    attack_techniques: list[str] = Field(default_factory=list)
    attack_tactics: list[str] = Field(default_factory=list)
    attack_note: str | None = None
