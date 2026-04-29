"""Doctor and evidence bundle response models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from vuln_prioritizer.model_base import StrictModel


class DoctorCheck(StrictModel):
    check_id: str
    name: str
    scope: str = "local"
    category: str = "general"
    status: str
    detail: str
    hint: str | None = None


class DoctorSummary(StrictModel):
    overall_status: str = "ok"
    ok_count: int = 0
    degraded_count: int = 0
    error_count: int = 0


class DoctorReport(StrictModel):
    schema_version: str = "1.2.0"
    generated_at: str
    live: bool = False
    config_file: str | None = None
    summary: DoctorSummary = Field(default_factory=DoctorSummary)
    checks: list[DoctorCheck] = Field(default_factory=list)


class EvidenceBundleFile(StrictModel):
    path: str
    kind: str
    size_bytes: int
    sha256: str


class EvidenceBundleInputHash(StrictModel):
    path: str
    size_bytes: int
    sha256: str


class EvidenceBundleManifest(StrictModel):
    schema_version: str = "1.1.0"
    bundle_kind: str = "evidence-bundle"
    generated_at: str
    source_analysis_path: str
    source_analysis_sha256: str | None = None
    source_input_path: str | None = None
    source_input_paths: list[str] = Field(default_factory=list)
    source_input_hashes: list[EvidenceBundleInputHash] = Field(default_factory=list)
    provider_snapshot: dict[str, Any] = Field(default_factory=dict)
    artifact_hashes: dict[str, str] = Field(default_factory=dict)
    findings_count: int = 0
    kev_hits: int = 0
    waived_count: int = 0
    attack_mapped_cves: int = 0
    included_input_copy: bool = False
    files: list[EvidenceBundleFile] = Field(default_factory=list)


class EvidenceBundleVerificationMetadata(StrictModel):
    schema_version: str = "1.2.0"
    generated_at: str
    bundle_path: str
    manifest_schema_version: str | None = None
    bundle_kind: str | None = None


class EvidenceBundleVerificationSummary(StrictModel):
    ok: bool = False
    total_members: int = 0
    expected_files: int = 0
    verified_files: int = 0
    missing_files: int = 0
    modified_files: int = 0
    unexpected_files: int = 0
    manifest_errors: int = 0


class EvidenceBundleVerificationItem(StrictModel):
    path: str
    kind: str | None = None
    status: str
    detail: str
    expected_size_bytes: int | None = None
    actual_size_bytes: int | None = None
    expected_sha256: str | None = None
    actual_sha256: str | None = None
