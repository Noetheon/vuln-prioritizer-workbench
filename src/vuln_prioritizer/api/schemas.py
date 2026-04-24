"""Pydantic DTOs for the Workbench JSON API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from vuln_prioritizer.models import StrictModel

ProviderSourceName = Literal["nvd", "epss", "kev"]


def _default_provider_sources() -> list[ProviderSourceName]:
    return ["nvd", "epss", "kev"]


class ProjectCreateRequest(StrictModel):
    name: str
    description: str | None = None


class ReportCreateRequest(StrictModel):
    format: Literal["json", "markdown", "html", "csv", "sarif"] = "html"


class AssetUpdateRequest(StrictModel):
    asset_id: str | None = None
    target_ref: str | None = None
    owner: str | None = None
    business_service: str | None = None
    environment: str | None = None
    exposure: str | None = None
    criticality: str | None = None


class WaiverRequest(StrictModel):
    cve_id: str | None = None
    finding_id: str | None = None
    asset_id: str | None = None
    component_name: str | None = None
    component_version: str | None = None
    service: str | None = None
    owner: str
    reason: str
    expires_on: str
    review_on: str | None = None
    approval_ref: str | None = None
    ticket_url: str | None = None


class ApiTokenCreateRequest(StrictModel):
    name: str


class ProviderUpdateJobRequest(StrictModel):
    sources: list[ProviderSourceName] = Field(default_factory=_default_provider_sources)
    cve_ids: list[str] = Field(default_factory=list)
    max_cves: int | None = Field(default=None, ge=1, le=500)
    cache_only: bool = True


class GitHubIssuePreviewRequest(StrictModel):
    limit: int = Field(default=20, ge=1, le=100)
    priority: str | None = None
    label_prefix: str = "vuln-prioritizer"
    milestone: str | None = None


class GitHubIssueExportRequest(GitHubIssuePreviewRequest):
    repository: str
    token_env: str = "GITHUB_TOKEN"
    dry_run: bool = True


class ProjectConfigRequest(StrictModel):
    config: dict[str, Any]


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


class AssetResponse(StrictModel):
    id: str
    project_id: str
    asset_id: str
    target_ref: str | None = None
    owner: str | None = None
    business_service: str | None = None
    environment: str | None = None
    exposure: str | None = None
    criticality: str | None = None
    finding_count: int = 0


class WaiverResponse(StrictModel):
    id: str
    project_id: str
    cve_id: str | None = None
    finding_id: str | None = None
    asset_id: str | None = None
    component_name: str | None = None
    component_version: str | None = None
    service: str | None = None
    owner: str
    reason: str
    expires_on: str
    review_on: str | None = None
    approval_ref: str | None = None
    ticket_url: str | None = None
    status: str
    days_remaining: int | None = None
    matched_findings: int = 0
    created_at: str
    updated_at: str


class ApiTokenCreateResponse(StrictModel):
    id: str
    name: str
    token: str
    created_at: str


class ProviderUpdateJobResponse(StrictModel):
    id: str
    status: str
    requested_sources: list[str] = Field(default_factory=list)
    started_at: str
    finished_at: str | None = None
    error_message: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


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


class DetectionControlResponse(StrictModel):
    id: str
    project_id: str
    control_id: str | None = None
    name: str
    technique_id: str
    technique_name: str | None = None
    source_type: str | None = None
    coverage_level: str
    environment: str | None = None
    owner: str | None = None
    evidence_ref: str | None = None
    notes: str | None = None
    last_verified_at: str | None = None


class DetectionControlImportResponse(StrictModel):
    imported: int
    items: list[DetectionControlResponse] = Field(default_factory=list)


class CoverageGapItem(StrictModel):
    technique_id: str
    name: str | None = None
    tactic_ids: list[str] = Field(default_factory=list)
    finding_count: int = 0
    critical_finding_count: int = 0
    kev_finding_count: int = 0
    coverage_level: str
    control_count: int = 0
    owner: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    recommended_action: str


class CoverageGapResponse(StrictModel):
    items: list[CoverageGapItem] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)


class TechniqueDetailResponse(StrictModel):
    technique_id: str
    name: str | None = None
    deprecated: bool = False
    revoked: bool = False
    tactics: list[str] = Field(default_factory=list)
    findings: list[FindingResponse] = Field(default_factory=list)
    controls: list[DetectionControlResponse] = Field(default_factory=list)
    coverage: CoverageGapItem | None = None


class GitHubIssuePreviewItem(StrictModel):
    title: str
    body: str
    labels: list[str] = Field(default_factory=list)
    milestone: str | None = None
    duplicate_key: str


class GitHubIssuePreviewResponse(StrictModel):
    dry_run: bool = True
    items: list[GitHubIssuePreviewItem] = Field(default_factory=list)


class GitHubIssueExportItem(GitHubIssuePreviewItem):
    status: Literal["preview", "created", "skipped_duplicate"]
    issue_url: str | None = None
    issue_number: int | None = None


class GitHubIssueExportResponse(StrictModel):
    dry_run: bool
    created_count: int = 0
    skipped_count: int = 0
    items: list[GitHubIssueExportItem] = Field(default_factory=list)


class ProjectConfigResponse(StrictModel):
    id: str
    project_id: str
    source: str
    config: dict[str, Any]
    created_at: str


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
