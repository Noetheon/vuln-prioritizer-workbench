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


class WorkbenchJobCreateRequest(StrictModel):
    kind: Literal["provider_update", "import_findings", "create_report", "create_evidence_bundle"]
    project_id: str | None = None
    target_type: str | None = None
    target_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = None
    priority: int = Field(default=100, ge=0, le=1000)
    max_attempts: int = Field(default=3, ge=1, le=10)


class ArtifactRetentionRequest(StrictModel):
    report_retention_days: int | None = Field(default=None, ge=1, le=3650)
    evidence_retention_days: int | None = Field(default=None, ge=1, le=3650)
    max_disk_usage_mb: int | None = Field(default=None, ge=1, le=1_000_000)


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


class FindingStatusUpdateRequest(StrictModel):
    status: Literal["open", "in_review", "remediating", "fixed", "accepted", "suppressed"]
    reason: str | None = None
    actor: str | None = None


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


class TicketSyncPreviewRequest(StrictModel):
    provider: Literal["jira", "servicenow"]
    limit: int = Field(default=20, ge=1, le=100)
    priority: str | None = None
    idempotency_prefix: str = "vuln-prioritizer"
    jira_project_key: str | None = None
    servicenow_table: str = "incident"


class TicketSyncExportRequest(TicketSyncPreviewRequest):
    base_url: str | None = None
    token_env: str | None = None
    dry_run: bool = True


class ProjectConfigRequest(StrictModel):
    config: dict[str, Any]


class DetectionControlRequest(StrictModel):
    control_id: str | None = None
    name: str
    technique_id: str
    technique_name: str | None = None
    source_type: str | None = None
    coverage_level: Literal["covered", "partial", "not_covered", "unknown", "not_applicable"] = (
        "unknown"
    )
    environment: str | None = None
    owner: str | None = None
    evidence_ref: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    review_status: Literal["unreviewed", "needs_review", "reviewed", "rejected", "stale"] = (
        "unreviewed"
    )
    notes: str | None = None
    last_verified_at: str | None = None


class DetectionControlPatchRequest(StrictModel):
    control_id: str | None = None
    name: str | None = None
    technique_id: str | None = None
    technique_name: str | None = None
    source_type: str | None = None
    coverage_level: (
        Literal["covered", "partial", "not_covered", "unknown", "not_applicable"] | None
    ) = None
    environment: str | None = None
    owner: str | None = None
    evidence_ref: str | None = None
    evidence_refs: list[str] | None = None
    review_status: Literal["unreviewed", "needs_review", "reviewed", "rejected", "stale"] | None = (
        None
    )
    notes: str | None = None
    last_verified_at: str | None = None


class AttackReviewUpdateRequest(StrictModel):
    review_status: Literal[
        "unreviewed",
        "needs_review",
        "source_reviewed",
        "reviewed",
        "rejected",
        "not_applicable",
    ]
    actor: str | None = None
    reason: str | None = None


class ErrorDetails(StrictModel):
    code: str
    message: str
    details: Any | None = None


class ErrorResponse(StrictModel):
    detail: Any
    error: ErrorDetails


class HealthResponse(StrictModel):
    status: str
    database: str
    projects: int | None = None
    upload_dir: str | None = None
    report_dir: str | None = None


class VersionResponse(StrictModel):
    version: str
    app: str


class ProjectResponse(StrictModel):
    id: str
    name: str
    description: str | None = None
    created_at: str


class ProjectsListResponse(StrictModel):
    items: list[ProjectResponse] = Field(default_factory=list)


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


class AssetsListResponse(StrictModel):
    items: list[AssetResponse] = Field(default_factory=list)


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


class WaiversListResponse(StrictModel):
    items: list[WaiverResponse] = Field(default_factory=list)


class DeleteResponse(StrictModel):
    deleted: bool


class ApiTokenCreateResponse(StrictModel):
    id: str
    name: str
    token: str
    created_at: str


class ApiTokenResponse(StrictModel):
    id: str
    name: str
    created_at: str
    last_used_at: str | None = None
    revoked_at: str | None = None
    active: bool


class ApiTokensListResponse(StrictModel):
    items: list[ApiTokenResponse] = Field(default_factory=list)
    active_count: int = 0
    requires_token_for_mutations: bool = False


class ApiTokenDeleteResponse(StrictModel):
    id: str
    deleted: bool
    revoked: bool
    revoked_at: str


class FindingStatusHistoryResponse(StrictModel):
    id: str
    finding_id: str
    previous_status: str | None = None
    new_status: str
    actor: str | None = None
    reason: str | None = None
    created_at: str


class AuditEventResponse(StrictModel):
    id: str
    project_id: str | None = None
    event_type: str
    target_type: str | None = None
    target_id: str | None = None
    actor: str | None = None
    message: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str


class ProviderUpdateJobResponse(StrictModel):
    id: str
    status: str
    requested_sources: list[str] = Field(default_factory=list)
    started_at: str
    finished_at: str | None = None
    error_message: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProviderUpdateJobsListResponse(StrictModel):
    items: list[ProviderUpdateJobResponse] = Field(default_factory=list)


class WorkbenchJobResponse(StrictModel):
    id: str
    project_id: str | None = None
    kind: str
    status: str
    target_type: str | None = None
    target_id: str | None = None
    progress: int
    attempts: int
    max_attempts: int
    priority: int
    idempotency_key: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    logs: list[dict[str, Any]] = Field(default_factory=list)
    error_message: str | None = None
    created_at: str
    queued_at: str | None = None
    started_at: str | None = None
    heartbeat_at: str | None = None
    finished_at: str | None = None


class WorkbenchJobListResponse(StrictModel):
    items: list[WorkbenchJobResponse] = Field(default_factory=list)


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
    defensive_context_sources: list[str] = Field(default_factory=list)
    defensive_context_hits: int = 0


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
    job_id: str | None = None
    summary: AnalysisRunSummary


class AnalysisRunsListResponse(StrictModel):
    items: list[AnalysisRunResponse] = Field(default_factory=list)


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
    defensive_contexts: list[dict[str, Any]] = Field(default_factory=list)
    finding: dict[str, Any] | None = None
    occurrences: list[dict[str, Any]] | None = None
    status_history: list[FindingStatusHistoryResponse] | None = None


class FindingsListResponse(StrictModel):
    items: list[FindingResponse] = Field(default_factory=list)
    total: int
    limit: int
    offset: int


class FindingExplainResponse(StrictModel):
    finding_id: str
    cve_id: str
    priority: str
    rationale: str | None = None
    recommended_action: str | None = None
    explanation: dict[str, Any] | None = None


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


class ArtifactResponse(StrictModel):
    id: str
    project_id: str
    analysis_run_id: str
    type: Literal["report", "evidence_bundle"]
    kind: str
    format: str | None = None
    sha256: str
    created_at: str
    download_url: str
    verify_url: str | None = None


class ArtifactsListResponse(StrictModel):
    items: list[ArtifactResponse] = Field(default_factory=list)
    total: int
    limit: int
    offset: int


class ImportArtifactOptionResponse(StrictModel):
    filename: str
    kind: Literal["provider_snapshot", "attack_artifact"]
    source: Literal["provider_snapshot_dir", "provider_cache_dir", "attack_artifact_dir"]
    size_bytes: int
    modified_at: str


class WorkbenchArtifactsResponse(StrictModel):
    items: list[ImportArtifactOptionResponse] = Field(default_factory=list)
    provider_snapshots: list[ImportArtifactOptionResponse] = Field(default_factory=list)
    attack_artifacts: list[ImportArtifactOptionResponse] = Field(default_factory=list)
    total: int


class AnalysisRunArtifactsResponse(StrictModel):
    run: AnalysisRunResponse
    reports: list[ReportResponse] = Field(default_factory=list)
    evidence_bundles: list[EvidenceBundleResponse] = Field(default_factory=list)
    items: list[ArtifactResponse] = Field(default_factory=list)


class NavigatorLayerResponse(StrictModel):
    version: str
    name: str
    domain: str
    description: str | None = None
    gradient: dict[str, Any] | None = None
    legendItems: list[dict[str, Any]] = Field(default_factory=list)
    showTacticRowBackground: bool | None = None
    selectTechniquesAcrossTactics: bool | None = None
    techniques: list[dict[str, Any]] = Field(default_factory=list)


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


class DashboardServiceSummary(StrictModel):
    service: str
    finding_count: int


class ProjectDashboardResponse(StrictModel):
    project: ProjectResponse
    counts: dict[str, int] = Field(default_factory=dict)
    top_findings: list[FindingResponse] = Field(default_factory=list)
    recent_runs: list[AnalysisRunResponse] = Field(default_factory=list)
    top_services: list[DashboardServiceSummary] = Field(default_factory=list)
    top_techniques: list[AttackTechniqueSummary] = Field(default_factory=list)
    attack_mapped_count: int = 0
    provider_status: ProviderStatusResponse


class TokenAuthStatus(StrictModel):
    active_count: int = 0
    requires_token_for_mutations: bool = False


class WorkbenchBootstrapResponse(StrictModel):
    app: str
    version: str
    projects: list[ProjectResponse] = Field(default_factory=list)
    latest_project_id: str | None = None
    provider_status: ProviderStatusResponse
    token_auth: TokenAuthStatus
    supported_input_formats: list[str] = Field(default_factory=list)
    supported_report_formats: list[str] = Field(default_factory=list)
    supported_attack_sources: list[str] = Field(default_factory=list)
    limits: dict[str, int] = Field(default_factory=dict)


class VulnerabilityDetailResponse(StrictModel):
    project: ProjectResponse
    cve_id: str
    source_id: str | None = None
    title: str | None = None
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    cwe: str | None = None
    published_at: str | None = None
    modified_at: str | None = None
    provider: dict[str, Any] = Field(default_factory=dict)
    findings: list[FindingResponse] = Field(default_factory=list)


class AttackReviewQueueItem(StrictModel):
    finding_id: str
    cve_id: str
    priority: str
    finding_status: str
    mapped: bool
    source: str
    source_version: str | None = None
    source_hash: str | None = None
    source_path: str | None = None
    metadata_hash: str | None = None
    metadata_path: str | None = None
    attack_relevance: str
    threat_context_rank: int
    review_status: str
    rationale: str | None = None
    technique_ids: list[str] = Field(default_factory=list)
    tactic_names: list[str] = Field(default_factory=list)
    mapping_count: int = 0
    mapping_sources: list[str] = Field(default_factory=list)
    created_at: str


class AttackReviewQueueResponse(StrictModel):
    items: list[AttackReviewQueueItem] = Field(default_factory=list)


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
    evidence_refs: list[str] = Field(default_factory=list)
    review_status: str = "unreviewed"
    history_count: int = 0
    attachment_count: int = 0
    notes: str | None = None
    last_verified_at: str | None = None


class DetectionControlsListResponse(StrictModel):
    items: list[DetectionControlResponse] = Field(default_factory=list)


class DetectionControlHistoryResponse(StrictModel):
    id: str
    project_id: str
    control_id: str
    event_type: str
    actor: str | None = None
    reason: str | None = None
    previous: dict[str, Any] = Field(default_factory=dict)
    current: dict[str, Any] = Field(default_factory=dict)
    created_at: str


class DetectionControlAttachmentResponse(StrictModel):
    id: str
    project_id: str
    control_id: str
    filename: str
    content_type: str | None = None
    sha256: str
    size_bytes: int
    created_at: str
    download_url: str


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


class TicketSyncItem(StrictModel):
    provider: Literal["jira", "servicenow"]
    finding_id: str | None = None
    title: str
    body: str
    duplicate_key: str
    idempotency_key: str
    labels: list[str] = Field(default_factory=list)
    status: Literal["preview", "created", "skipped_duplicate"]
    ticket_url: str | None = None
    external_id: str | None = None


class TicketSyncResponse(StrictModel):
    dry_run: bool
    created_count: int = 0
    skipped_count: int = 0
    items: list[TicketSyncItem] = Field(default_factory=list)


class ProjectConfigResponse(StrictModel):
    id: str
    project_id: str
    source: str
    config: dict[str, Any]
    created_at: str


class ProjectConfigItemResponse(StrictModel):
    item: ProjectConfigResponse | None = None


class ArtifactRetentionResponse(StrictModel):
    project_id: str
    report_retention_days: int | None = None
    evidence_retention_days: int | None = None
    max_disk_usage_mb: int | None = None
    updated_at: str | None = None


class ArtifactCleanupResponse(StrictModel):
    deleted_files: list[str] = Field(default_factory=list)
    orphan_files: list[str] = Field(default_factory=list)
    expired_reports: int = 0
    expired_evidence_bundles: int = 0
    bytes_removed: int = 0
    dry_run: bool = True


class ProjectConfigDiffResponse(StrictModel):
    base_id: str | None = None
    target_id: str
    added: dict[str, Any] = Field(default_factory=dict)
    removed: dict[str, Any] = Field(default_factory=dict)
    changed: dict[str, dict[str, Any]] = Field(default_factory=dict)


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
