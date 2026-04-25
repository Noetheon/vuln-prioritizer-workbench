"""Remediation guidance models."""

from __future__ import annotations

from pydantic import Field

from vuln_prioritizer.model_base import StrictModel


class RemediationComponent(StrictModel):
    name: str | None = None
    current_version: str | None = None
    fixed_versions: list[str] = Field(default_factory=list)
    package_type: str | None = None
    purl: str | None = None
    path: str | None = None
    occurrence_count: int = 0
    targets: list[str] = Field(default_factory=list)
    asset_ids: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    owners: list[str] = Field(default_factory=list)


class RemediationPlan(StrictModel):
    strategy: str = "generic-priority-guidance"
    ecosystem: str | None = None
    components: list[RemediationComponent] = Field(default_factory=list)
    evidence_level: str = "none"
    kev_required_action: str | None = None
    kev_due_date: str | None = None
    suppressed_occurrence_count: int = 0
