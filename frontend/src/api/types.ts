export interface Project {
  id: string;
  name: string;
  description?: string | null;
  created_at: string;
}

export interface ListResponse<T> {
  items: T[];
}

export interface WorkbenchBootstrapResponse {
  app: string;
  version: string;
  projects: Project[];
  latest_project_id?: string | null;
  provider_status: ProviderStatusResponse;
  token_auth: {
    active_count: number;
    requires_token_for_mutations: boolean;
  };
  supported_input_formats: string[];
  supported_report_formats: string[];
  supported_attack_sources: string[];
  limits: Record<string, number>;
}

export interface FindingsListResponse extends ListResponse<Finding> {
  total: number;
  limit: number;
  offset: number;
}

export interface FindingExplainResponse {
  finding_id: string;
  cve_id: string;
  priority: string;
  rationale?: string | null;
  recommended_action?: string | null;
  explanation?: Record<string, unknown> | null;
}

export interface AnalysisRunSummary {
  findings_count: number;
  kev_hits: number;
  counts_by_priority: Record<string, number>;
  provider_snapshot_id?: string | null;
  provider_snapshot_missing: boolean;
  attack_enabled: boolean;
  attack_mapped_cves: number;
  attack_source: string;
  attack_version?: string | null;
  attack_domain?: string | null;
  attack_mapping_file_sha256?: string | null;
  attack_technique_metadata_file_sha256?: string | null;
  attack_metadata_format?: string | null;
  attack_stix_spec_version?: string | null;
}

export interface AnalysisRun {
  id: string;
  project_id: string;
  input_type: string;
  input_filename?: string | null;
  status: string;
  started_at: string;
  finished_at?: string | null;
  error_message?: string | null;
  provider_snapshot_id?: string | null;
  summary: AnalysisRunSummary;
}

export interface Asset {
  id: string;
  project_id: string;
  asset_id: string;
  target_ref?: string | null;
  owner?: string | null;
  business_service?: string | null;
  environment?: string | null;
  exposure?: string | null;
  criticality?: string | null;
  finding_count: number;
}

export interface Waiver {
  id: string;
  project_id: string;
  cve_id?: string | null;
  finding_id?: string | null;
  asset_id?: string | null;
  component_name?: string | null;
  component_version?: string | null;
  service?: string | null;
  owner: string;
  reason: string;
  expires_on: string;
  review_on?: string | null;
  approval_ref?: string | null;
  ticket_url?: string | null;
  status: string;
  days_remaining?: number | null;
  matched_findings: number;
  created_at: string;
  updated_at: string;
}

export interface Finding {
  id: string;
  project_id: string;
  analysis_run_id?: string | null;
  cve_id: string;
  priority: string;
  priority_rank: number;
  operational_rank: number;
  status: string;
  in_kev: boolean;
  epss?: number | null;
  cvss_base_score?: number | null;
  component?: string | null;
  component_version?: string | null;
  asset?: string | null;
  owner?: string | null;
  service?: string | null;
  attack_mapped: boolean;
  threat_context_rank?: number | null;
  suppressed_by_vex: boolean;
  under_investigation: boolean;
  vex_statuses: Record<string, number>;
  waived: boolean;
  waiver_status?: string | null;
  waiver_reason?: string | null;
  waiver_owner?: string | null;
  waiver_expires_on?: string | null;
  waiver_review_on?: string | null;
  waiver_days_remaining?: number | null;
  waiver_scope?: string | null;
  waiver_id?: string | null;
  waiver_matched_scope?: string | null;
  waiver_approval_ref?: string | null;
  waiver_ticket_url?: string | null;
  rationale?: string | null;
  recommended_action?: string | null;
  finding?: Record<string, unknown> | null;
  occurrences?: Array<Record<string, unknown>> | null;
}

export interface ProviderSourceStatus {
  name: string;
  selected: boolean;
  available: boolean;
  stale: boolean;
  value?: string | null;
  detail?: string | null;
}

export interface ProviderSnapshotStatus {
  id?: string | null;
  content_hash?: string | null;
  generated_at?: string | null;
  selected_sources: string[];
  requested_cves: number;
  source_path?: string | null;
  locked_provider_data: boolean;
  missing: boolean;
}

export interface ProviderStatusResponse {
  status: string;
  snapshot: ProviderSnapshotStatus;
  sources: ProviderSourceStatus[];
  cache_dir: string;
  snapshot_dir: string;
  warnings: string[];
}

export interface ProviderUpdateJob {
  id: string;
  status: string;
  requested_sources: string[];
  started_at: string;
  finished_at?: string | null;
  error_message?: string | null;
  metadata: Record<string, unknown>;
}

export interface ArtifactOption {
  filename: string;
  kind: string;
  source: string;
  size_bytes: number;
  modified_at: string;
}

export interface WorkbenchArtifactOptionsResponse {
  provider_snapshots: ArtifactOption[];
  attack_artifacts: ArtifactOption[];
}

export interface ReportArtifact {
  id: string;
  analysis_run_id: string;
  format: string;
  kind: string;
  sha256: string;
  download_url: string;
}

export interface EvidenceBundle {
  id: string;
  analysis_run_id: string;
  sha256: string;
  download_url: string;
  verify_url: string;
}

export interface Artifact {
  id: string;
  project_id: string;
  analysis_run_id: string;
  type: "report" | "evidence_bundle";
  kind: string;
  format?: string | null;
  sha256: string;
  created_at: string;
  download_url: string;
  verify_url?: string | null;
}

export interface ArtifactsListResponse extends ListResponse<Artifact> {
  total: number;
  limit: number;
  offset: number;
}

export interface AnalysisRunArtifactsResponse {
  run: AnalysisRun;
  reports: ReportArtifact[];
  evidence_bundles: EvidenceBundle[];
  items: Artifact[];
}

export interface DetectionControl {
  id: string;
  project_id: string;
  control_id?: string | null;
  name: string;
  technique_id: string;
  technique_name?: string | null;
  source_type?: string | null;
  coverage_level: string;
  environment?: string | null;
  owner?: string | null;
  evidence_ref?: string | null;
  notes?: string | null;
  last_verified_at?: string | null;
}

export interface CoverageGapItem {
  technique_id: string;
  name?: string | null;
  tactic_ids: string[];
  finding_count: number;
  critical_finding_count: number;
  kev_finding_count: number;
  coverage_level: string;
  control_count: number;
  owner?: string | null;
  evidence_refs: string[];
  recommended_action: string;
}

export interface CoverageGapResponse {
  items: CoverageGapItem[];
  summary: Record<string, number>;
}

export interface TechniqueDetailResponse {
  technique_id: string;
  name?: string | null;
  deprecated: boolean;
  revoked: boolean;
  tactics: string[];
  findings: Finding[];
  controls: DetectionControl[];
  coverage?: CoverageGapItem | null;
}

export interface VulnerabilityDetailResponse {
  project: Project;
  cve_id: string;
  source_id?: string | null;
  title?: string | null;
  description?: string | null;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  severity?: string | null;
  cwe?: string | null;
  published_at?: string | null;
  modified_at?: string | null;
  provider: Record<string, unknown>;
  findings: Finding[];
}

export interface ApiTokenMetadata {
  id: string;
  name: string;
  created_at: string;
  last_used_at?: string | null;
  revoked_at?: string | null;
  active: boolean;
}

export interface ApiTokensListResponse {
  items: ApiTokenMetadata[];
  active_count: number;
  requires_token_for_mutations: boolean;
}

export interface ApiTokenCreateResponse {
  id: string;
  name: string;
  token: string;
  created_at: string;
}

export interface ProjectConfigSnapshot {
  id: string;
  project_id: string;
  source: string;
  config: Record<string, unknown>;
  created_at: string;
}

export interface ProjectConfigItemResponse {
  item?: ProjectConfigSnapshot | null;
}

export interface GitHubIssuePreviewRequest {
  limit: number;
  priority?: string | null;
  label_prefix: string;
  milestone?: string | null;
}

export interface GitHubIssueExportRequest extends GitHubIssuePreviewRequest {
  repository: string;
  token_env: string;
  dry_run: boolean;
}

export interface GitHubIssuePreviewItem {
  title: string;
  body: string;
  labels: string[];
  milestone?: string | null;
  duplicate_key: string;
}

export interface GitHubIssuePreviewResponse {
  dry_run: boolean;
  items: GitHubIssuePreviewItem[];
}

export interface GitHubIssueExportItem extends GitHubIssuePreviewItem {
  status: "preview" | "created" | "skipped_duplicate";
  issue_url?: string | null;
  issue_number?: number | null;
}

export interface GitHubIssueExportResponse {
  dry_run: boolean;
  created_count: number;
  skipped_count: number;
  items: GitHubIssueExportItem[];
}

export interface EvidenceBundleVerificationResponse {
  metadata: Record<string, unknown>;
  summary: Record<string, unknown>;
  items: Array<Record<string, unknown>>;
}

export interface AttackTechniqueSummary {
  technique_id: string;
  name: string;
  tactics: string[];
  url?: string | null;
  count: number;
  cves: string[];
}

export interface TopTechniquesResponse {
  items: AttackTechniqueSummary[];
}

export interface DashboardServiceSummary {
  service: string;
  finding_count: number;
}

export interface ProjectDashboardResponse {
  project: Project;
  counts: Record<string, number>;
  top_findings: Finding[];
  recent_runs: AnalysisRun[];
  top_services: DashboardServiceSummary[];
  top_techniques: AttackTechniqueSummary[];
  attack_mapped_count: number;
  provider_status: ProviderStatusResponse;
}

export interface FindingAttackContextResponse {
  finding_id: string;
  cve_id: string;
  mapped: boolean;
  source: string;
  source_version?: string | null;
  source_hash?: string | null;
  source_path?: string | null;
  attack_version?: string | null;
  domain?: string | null;
  metadata_hash?: string | null;
  metadata_path?: string | null;
  attack_relevance: string;
  threat_context_rank: number;
  rationale?: string | null;
  review_status: string;
  techniques: Array<Record<string, unknown>>;
  tactics: string[];
  mappings: Array<Record<string, unknown>>;
}

export interface GovernanceRollupItem {
  label: string;
  dimension: string;
  finding_count: number;
  actionable_count: number;
  critical_count: number;
  high_count: number;
  kev_count: number;
  attack_mapped_count: number;
  waived_count: number;
  waiver_review_due_count: number;
  expired_waiver_count: number;
  suppressed_by_vex_count: number;
  under_investigation_count: number;
  highest_priority: string;
  top_cves: string[];
  priority_counts: Record<string, number>;
  status_counts: Record<string, number>;
}

export interface GovernanceWaiverSummary {
  total_findings: number;
  waived_count: number;
  active_count: number;
  review_due_count: number;
  expired_count: number;
  unwaived_count: number;
  unknown_status_count: number;
  by_status: Record<string, number>;
  waiver_owner_counts: Record<string, number>;
}

export interface GovernanceVexSummary {
  total_findings: number;
  suppressed_findings: number;
  unsuppressed_findings: number;
  under_investigation_findings: number;
  findings_with_vex_status: number;
  status_counts: Record<string, number>;
}

export interface GovernanceRollupsResponse {
  total_findings: number;
  owners: GovernanceRollupItem[];
  services: GovernanceRollupItem[];
  waiver_summary: GovernanceWaiverSummary;
  vex_summary: GovernanceVexSummary;
}

export interface ApiErrorDetails {
  status: number;
  message: string;
  details?: unknown;
}
