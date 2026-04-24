"""Pydantic DTOs for the Workbench JSON API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from vuln_prioritizer.models import StrictModel


class ProjectCreateRequest(StrictModel):
    name: str
    description: str | None = None


class ReportCreateRequest(StrictModel):
    format: Literal["json", "markdown", "html", "csv"] = "html"


class ErrorDetails(StrictModel):
    code: str
    message: str
    details: Any | None = None


class ErrorResponse(StrictModel):
    detail: Any
    error: ErrorDetails


class ProjectResponse(StrictModel):
    id: str
    name: str
    description: str | None = None
    created_at: str


class AnalysisRunSummary(StrictModel):
    findings_count: int = 0
    kev_hits: int = 0
    counts_by_priority: dict[str, int] = Field(default_factory=dict)
    provider_snapshot_id: str | None = None
    provider_snapshot_missing: bool = False
    attack_enabled: bool = False
    attack_mapped_cves: int = 0
    attack_source: str = "none"
    attack_version: str | None = None
    attack_domain: str | None = None
    attack_mapping_file_sha256: str | None = None
    attack_technique_metadata_file_sha256: str | None = None
    attack_metadata_format: str | None = None
    attack_stix_spec_version: str | None = None


class AnalysisRunResponse(StrictModel):
    id: str
    project_id: str
    input_type: str
    input_filename: str | None = None
    status: str
    started_at: str
    finished_at: str | None = None
    error_message: str | None = None
    provider_snapshot_id: str | None = None
    summary: AnalysisRunSummary


class FindingResponse(StrictModel):
    id: str
    project_id: str
    analysis_run_id: str | None = None
    cve_id: str
    priority: str
    priority_rank: int
    operational_rank: int
    status: str
    in_kev: bool
    epss: float | None = None
    cvss_base_score: float | None = None
    component: str | None = None
    component_version: str | None = None
    asset: str | None = None
    owner: str | None = None
    service: str | None = None
    attack_mapped: bool = False
    threat_context_rank: int | None = None
    suppressed_by_vex: bool = False
    under_investigation: bool = False
    vex_statuses: dict[str, int] = Field(default_factory=dict)
    waived: bool = False
    waiver_status: str | None = None
    waiver_reason: str | None = None
    waiver_owner: str | None = None
    waiver_expires_on: str | None = None
    waiver_review_on: str | None = None
    waiver_days_remaining: int | None = None
    waiver_scope: str | None = None
    waiver_id: str | None = None
    waiver_matched_scope: str | None = None
    waiver_approval_ref: str | None = None
    waiver_ticket_url: str | None = None
    rationale: str | None = None
    recommended_action: str | None = None
    finding: dict[str, Any] | None = None
    occurrences: list[dict[str, Any]] | None = None


class FindingsListResponse(StrictModel):
    items: list[FindingResponse] = Field(default_factory=list)
    total: int
    limit: int
    offset: int


class ReportResponse(StrictModel):
    id: str
    analysis_run_id: str
    format: str
    kind: str
    sha256: str
    download_url: str


class EvidenceBundleResponse(StrictModel):
    id: str
    analysis_run_id: str
    sha256: str
    download_url: str
    verify_url: str


class ProviderSourceStatus(StrictModel):
    name: str
    selected: bool = False
    available: bool = False
    stale: bool = False
    value: str | None = None
    detail: str | None = None


class ProviderSnapshotStatus(StrictModel):
    id: str | None = None
    content_hash: str | None = None
    generated_at: str | None = None
    selected_sources: list[str] = Field(default_factory=list)
    requested_cves: int = 0
    source_path: str | None = None
    locked_provider_data: bool = False
    missing: bool = True


class ProviderStatusResponse(StrictModel):
    status: str
    snapshot: ProviderSnapshotStatus
    sources: list[ProviderSourceStatus] = Field(default_factory=list)
    cache_dir: str
    snapshot_dir: str
    warnings: list[str] = Field(default_factory=list)


class AttackTechniqueSummary(StrictModel):
    technique_id: str
    name: str
    tactics: list[str] = Field(default_factory=list)
    url: str | None = None
    count: int
    cves: list[str] = Field(default_factory=list)


class FindingAttackContextResponse(StrictModel):
    finding_id: str
    cve_id: str
    mapped: bool
    source: str
    source_version: str | None = None
    source_hash: str | None = None
    source_path: str | None = None
    attack_version: str | None = None
    domain: str | None = None
    metadata_hash: str | None = None
    metadata_path: str | None = None
    attack_relevance: str
    threat_context_rank: int
    rationale: str | None = None
    review_status: str
    techniques: list[dict[str, Any]] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    mappings: list[dict[str, Any]] = Field(default_factory=list)


class TopTechniquesResponse(StrictModel):
    items: list[AttackTechniqueSummary] = Field(default_factory=list)


class GovernanceRollupItem(StrictModel):
    label: str
    dimension: str
    finding_count: int = 0
    actionable_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    kev_count: int = 0
    attack_mapped_count: int = 0
    waived_count: int = 0
    waiver_review_due_count: int = 0
    expired_waiver_count: int = 0
    suppressed_by_vex_count: int = 0
    under_investigation_count: int = 0
    highest_priority: str
    top_cves: list[str] = Field(default_factory=list)
    priority_counts: dict[str, int] = Field(default_factory=dict)
    status_counts: dict[str, int] = Field(default_factory=dict)


class GovernanceWaiverSummary(StrictModel):
    total_findings: int = 0
    waived_count: int = 0
    active_count: int = 0
    review_due_count: int = 0
    expired_count: int = 0
    unwaived_count: int = 0
    unknown_status_count: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)
    waiver_owner_counts: dict[str, int] = Field(default_factory=dict)


class GovernanceVexSummary(StrictModel):
    total_findings: int = 0
    suppressed_findings: int = 0
    unsuppressed_findings: int = 0
    under_investigation_findings: int = 0
    findings_with_vex_status: int = 0
    status_counts: dict[str, int] = Field(default_factory=dict)


class GovernanceRollupsResponse(StrictModel):
    total_findings: int = 0
    owners: list[GovernanceRollupItem] = Field(default_factory=list)
    services: list[GovernanceRollupItem] = Field(default_factory=list)
    waiver_summary: GovernanceWaiverSummary = Field(default_factory=GovernanceWaiverSummary)
    vex_summary: GovernanceVexSummary = Field(default_factory=GovernanceVexSummary)


class EvidenceBundleVerificationResponse(StrictModel):
    metadata: dict[str, Any]
    summary: dict[str, Any]
    items: list[dict[str, Any]] = Field(default_factory=list)
