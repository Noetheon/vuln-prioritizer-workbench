"""Evidence bundle response models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from app.domain.engine.model_base import StrictModel


class EvidenceBundleFile(StrictModel):
    """Data representation and logic for Evidence Bundle File."""

    path: str
    kind: str
    size_bytes: int
    sha256: str


class EvidenceBundleInputHash(StrictModel):
    """Data representation and logic for Evidence Bundle Input Hash."""

    path: str
    size_bytes: int
    sha256: str


class EvidenceBundleGovernanceArtifact(StrictModel):
    """Data representation and logic for Evidence Bundle Governance Artifact."""

    bundle_path: str
    kind: str
    sha256: str


class EvidenceBundleManifest(StrictModel):
    """Data representation and logic for Evidence Bundle Manifest."""

    schema_version: str = "1.1.0"
    bundle_kind: str = "evidence-bundle"
    generated_at: str
    source_analysis_path: str
    source_analysis_sha256: str | None = None
    source_input_path: str | None = None
    source_input_paths: list[str] = Field(default_factory=list)
    source_input_hashes: list[EvidenceBundleInputHash] = Field(default_factory=list)
    provider_snapshot: dict[str, Any] = Field(default_factory=dict)
    governance_artifacts: list[EvidenceBundleGovernanceArtifact] = Field(default_factory=list)
    attack_navigator_layer: dict[str, Any] | None = None
    artifact_hashes: dict[str, str] = Field(default_factory=dict)
    findings_count: int = 0
    kev_hits: int = 0
    waived_count: int = 0
    attack_mapped_cves: int = 0
    included_input_copy: bool = False
    redaction: dict[str, Any] = Field(default_factory=dict)
    files: list[EvidenceBundleFile] = Field(default_factory=list)


class EvidenceBundleVerificationMetadata(StrictModel):
    """Data representation and logic for Evidence Bundle Verification Metadata."""

    schema_version: str = "1.2.0"
    generated_at: str
    bundle_path: str
    manifest_schema_version: str | None = None
    bundle_kind: str | None = None


class EvidenceBundleVerificationSummary(StrictModel):
    """Data representation and logic for Evidence Bundle Verification Summary."""

    ok: bool = False
    total_members: int = 0
    expected_files: int = 0
    verified_files: int = 0
    missing_files: int = 0
    modified_files: int = 0
    unexpected_files: int = 0
    manifest_errors: int = 0


class EvidenceBundleVerificationItem(StrictModel):
    """Data representation and logic for Evidence Bundle Verification Item."""

    path: str
    kind: str | None = None
    status: str
    detail: str
    expected_size_bytes: int | None = None
    actual_size_bytes: int | None = None
    expected_sha256: str | None = None
    actual_sha256: str | None = None
