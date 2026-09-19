"""Evidence recorded for a local SBOM vulnerability assessment."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SbomAssessmentV1(BaseModel):
    """Separate scanner observation and coverage from downstream prioritization."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["sbom-assessment.v1"] = "sbom-assessment.v1"
    scanner: Literal["grype"] = "grype"
    scanner_version: str
    database_built_at: str | None = None
    database_sha256: str | None = None
    database_metadata: dict[str, str | int | bool] = Field(default_factory=dict)
    scanned_at: str
    observed_at: str | None = None
    input_sha256: str
    output_sha256: str
    target_ref: str
    target_kind: Literal["sbom"] = "sbom"
    input_format: Literal["cyclonedx-json", "spdx-json"]
    component_count: int = Field(ge=0)
    identified_component_count: int = Field(ge=0)
    version_missing_count: int = Field(ge=0)
    scanner_match_count: int = Field(ge=0)
    prioritized_match_count: int = Field(ge=0)
    unassigned_match_count: int = Field(ge=0)
    warnings: list[str] = Field(default_factory=list)
    status: Literal["complete", "partial"] = "complete"
    artifact_refs: dict[str, str] = Field(default_factory=dict)
    source_run_id: str | None = None
