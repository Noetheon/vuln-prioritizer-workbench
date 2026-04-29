"""ATT&CK enrichment models."""

from __future__ import annotations

from pydantic import Field

from vuln_prioritizer.model_base import StrictModel


class AttackMapping(StrictModel):
    capability_id: str
    attack_object_id: str
    attack_object_name: str | None = None
    mapping_type: str | None = None
    capability_group: str | None = None
    capability_description: str | None = None
    comments: str | None = None
    references: list[str] = Field(default_factory=list)


class AttackTechnique(StrictModel):
    attack_object_id: str
    name: str
    tactics: list[str] = Field(default_factory=list)
    url: str | None = None
    revoked: bool = False
    deprecated: bool = False


class AttackSummary(StrictModel):
    mapped_cves: int = 0
    unmapped_cves: int = 0
    mapping_type_distribution: dict[str, int] = Field(default_factory=dict)
    technique_distribution: dict[str, int] = Field(default_factory=dict)
    tactic_distribution: dict[str, int] = Field(default_factory=dict)


class AttackData(StrictModel):
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
