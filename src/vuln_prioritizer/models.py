"""Pydantic models for the CLI."""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator

import vuln_prioritizer.models_artifacts as _models_artifacts
import vuln_prioritizer.models_attack as _models_attack
import vuln_prioritizer.models_input as _models_input
import vuln_prioritizer.models_provider as _models_provider
import vuln_prioritizer.models_remediation as _models_remediation
import vuln_prioritizer.models_state as _models_state
import vuln_prioritizer.models_waivers as _models_waivers
from vuln_prioritizer.model_base import StrictModel

AttackData = _models_attack.AttackData
AttackMapping = _models_attack.AttackMapping
AttackSummary = _models_attack.AttackSummary
AttackTechnique = _models_attack.AttackTechnique
AssetContextRecord = _models_input.AssetContextRecord
ContextPolicyProfile = _models_input.ContextPolicyProfile
DoctorCheck = _models_artifacts.DoctorCheck
DoctorReport = _models_artifacts.DoctorReport
DoctorSummary = _models_artifacts.DoctorSummary
EvidenceBundleFile = _models_artifacts.EvidenceBundleFile
EvidenceBundleInputHash = _models_artifacts.EvidenceBundleInputHash
EvidenceBundleManifest = _models_artifacts.EvidenceBundleManifest
EvidenceBundleVerificationItem = _models_artifacts.EvidenceBundleVerificationItem
EvidenceBundleVerificationMetadata = _models_artifacts.EvidenceBundleVerificationMetadata
EvidenceBundleVerificationSummary = _models_artifacts.EvidenceBundleVerificationSummary
DefensiveContext = _models_provider.DefensiveContext
EpssData = _models_provider.EpssData
FindingProvenance = _models_input.FindingProvenance
InputItem = _models_input.InputItem
InputOccurrence = _models_input.InputOccurrence
InputSourceSummary = _models_input.InputSourceSummary
KevData = _models_provider.KevData
NvdData = _models_provider.NvdData
ParsedInput = _models_input.ParsedInput
ProviderEvidence = _models_provider.ProviderEvidence
ProviderLookupDiagnostics = _models_provider.ProviderLookupDiagnostics
RemediationComponent = _models_remediation.RemediationComponent
RemediationPlan = _models_remediation.RemediationPlan

StateHistoryEntry = _models_state.StateHistoryEntry
StateHistoryMetadata = _models_state.StateHistoryMetadata
StateHistoryReport = _models_state.StateHistoryReport
StateImportMetadata = _models_state.StateImportMetadata
StateImportReport = _models_state.StateImportReport
StateImportSummary = _models_state.StateImportSummary
StateInitMetadata = _models_state.StateInitMetadata
StateInitReport = _models_state.StateInitReport
StateInitSummary = _models_state.StateInitSummary
StateServiceHistoryEntry = _models_state.StateServiceHistoryEntry
StateServiceHistoryMetadata = _models_state.StateServiceHistoryMetadata
StateServiceHistoryReport = _models_state.StateServiceHistoryReport
StateTopServiceEntry = _models_state.StateTopServiceEntry
StateTopServicesMetadata = _models_state.StateTopServicesMetadata
StateTopServicesReport = _models_state.StateTopServicesReport
StateTrendEntry = _models_state.StateTrendEntry
StateTrendsMetadata = _models_state.StateTrendsMetadata
StateTrendsReport = _models_state.StateTrendsReport
StateWaiverEntry = _models_state.StateWaiverEntry
StateWaiverMetadata = _models_state.StateWaiverMetadata
StateWaiverReport = _models_state.StateWaiverReport
VexStatement = _models_input.VexStatement
WaiverHealthSummary = _models_waivers.WaiverHealthSummary
WaiverRule = _models_waivers.WaiverRule


class PriorityPolicy(StrictModel):
    critical_epss_threshold: float = 0.70
    critical_cvss_threshold: float = 7.0
    high_epss_threshold: float = 0.40
    high_cvss_threshold: float = 9.0
    medium_epss_threshold: float = 0.10
    medium_cvss_threshold: float = 7.0

    @model_validator(mode="after")
    def validate_thresholds(self) -> PriorityPolicy:
        for field_name in (
            "critical_epss_threshold",
            "high_epss_threshold",
            "medium_epss_threshold",
        ):
            value = getattr(self, field_name)
            if value < 0.0 or value > 1.0:
                raise ValueError(f"{field_name} must stay between 0.0 and 1.0.")

        for field_name in (
            "critical_cvss_threshold",
            "high_cvss_threshold",
            "medium_cvss_threshold",
        ):
            value = getattr(self, field_name)
            if value < 0.0 or value > 10.0:
                raise ValueError(f"{field_name} must stay between 0.0 and 10.0.")

        if not (
            self.critical_epss_threshold >= self.high_epss_threshold >= self.medium_epss_threshold
        ):
            raise ValueError("EPSS thresholds must descend from critical to high to medium.")

        if self.high_cvss_threshold < self.medium_cvss_threshold:
            raise ValueError(
                "high_cvss_threshold must be greater than or equal to medium_cvss_threshold."
            )

        return self

    def methodology_lines(self) -> list[str]:
        return [
            (
                "Critical: KEV or "
                f"(EPSS >= {self.critical_epss_threshold:.2f} and "
                f"CVSS >= {self.critical_cvss_threshold:.1f})"
            ),
            (
                f"High: EPSS >= {self.high_epss_threshold:.2f} or "
                f"CVSS >= {self.high_cvss_threshold:.1f}"
            ),
            (
                f"Medium: CVSS >= {self.medium_cvss_threshold:.1f} or "
                f"EPSS >= {self.medium_epss_threshold:.2f}"
            ),
            "Low: all remaining CVEs",
        ]

    def override_descriptions(self) -> list[str]:
        default_policy = PriorityPolicy()
        if self == default_policy:
            return []

        labels = {
            "critical_epss_threshold": "critical-epss",
            "critical_cvss_threshold": "critical-cvss",
            "high_epss_threshold": "high-epss",
            "high_cvss_threshold": "high-cvss",
            "medium_epss_threshold": "medium-epss",
            "medium_cvss_threshold": "medium-cvss",
        }
        descriptions: list[str] = []

        for field_name, label in labels.items():
            current_value = getattr(self, field_name)
            default_value = getattr(default_policy, field_name)
            if current_value == default_value:
                continue

            if "epss" in field_name:
                descriptions.append(f"{label}={current_value:.3f}")
            else:
                descriptions.append(f"{label}={current_value:.1f}")

        return descriptions


class PrioritizedFinding(StrictModel):
    cve_id: str
    description: str | None = None
    cvss_base_score: float | None = None
    cvss_severity: str | None = None
    cvss_version: str | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    in_kev: bool = False
    attack_mapped: bool = False
    attack_relevance: str = "Unmapped"
    attack_rationale: str | None = None
    attack_techniques: list[str] = Field(default_factory=list)
    attack_tactics: list[str] = Field(default_factory=list)
    attack_note: str | None = None
    attack_mappings: list[AttackMapping] = Field(default_factory=list)
    attack_technique_details: list[AttackTechnique] = Field(default_factory=list)
    provenance: FindingProvenance = Field(default_factory=FindingProvenance)
    context_summary: str | None = None
    context_recommendation: str | None = None
    highest_asset_criticality: str | None = None
    asset_count: int = 0
    suppressed_by_vex: bool = False
    under_investigation: bool = False
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
    operational_rank: int = 0
    context_rank_reasons: list[str] = Field(default_factory=list)
    priority_label: str
    priority_rank: int
    priority_drivers: list[str] = Field(default_factory=list)
    rationale: str
    provider_evidence: ProviderEvidence | None = None
    defensive_contexts: list[DefensiveContext] = Field(default_factory=list)
    remediation: RemediationPlan = Field(default_factory=RemediationPlan)
    recommended_action: str


class ComparisonFinding(StrictModel):
    cve_id: str
    description: str | None = None
    cvss_base_score: float | None = None
    cvss_severity: str | None = None
    cvss_version: str | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    in_kev: bool = False
    cvss_only_label: str
    cvss_only_rank: int
    enriched_label: str
    enriched_rank: int
    attack_mapped: bool = False
    attack_relevance: str = "Unmapped"
    mapped_technique_count: int = 0
    mapped_tactics: list[str] = Field(default_factory=list)
    provenance: FindingProvenance = Field(default_factory=FindingProvenance)
    context_summary: str | None = None
    suppressed_by_vex: bool = False
    under_investigation: bool = False
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
    operational_rank: int = 0
    context_rank_reasons: list[str] = Field(default_factory=list)
    defensive_contexts: list[DefensiveContext] = Field(default_factory=list)
    changed: bool
    delta_rank: int
    change_reason: str


class EnrichmentResult(BaseModel):
    nvd: dict[str, NvdData] = Field(default_factory=dict)
    epss: dict[str, EpssData] = Field(default_factory=dict)
    kev: dict[str, KevData] = Field(default_factory=dict)
    attack: dict[str, AttackData] = Field(default_factory=dict)
    defensive_contexts: dict[str, list[DefensiveContext]] = Field(default_factory=dict)
    defensive_context_file: str | None = None
    defensive_context_sources: list[str] = Field(default_factory=list)
    attack_source: str = "none"
    attack_mapping_file: str | None = None
    attack_technique_metadata_file: str | None = None
    attack_source_version: str | None = None
    attack_version: str | None = None
    attack_domain: str | None = None
    mapping_framework: str | None = None
    mapping_framework_version: str | None = None
    attack_mapping_file_sha256: str | None = None
    attack_technique_metadata_file_sha256: str | None = None
    attack_metadata_format: str | None = None
    attack_metadata_source: str | None = None
    attack_stix_spec_version: str | None = None
    attack_mapping_created_at: str | None = None
    attack_mapping_updated_at: str | None = None
    attack_mapping_organization: str | None = None
    attack_mapping_author: str | None = None
    attack_mapping_contact: str | None = None
    parsed_input: ParsedInput = Field(default_factory=ParsedInput)
    warnings: list[str] = Field(default_factory=list)
    nvd_diagnostics: ProviderLookupDiagnostics = Field(default_factory=ProviderLookupDiagnostics)
    epss_diagnostics: ProviderLookupDiagnostics = Field(default_factory=ProviderLookupDiagnostics)
    kev_diagnostics: ProviderLookupDiagnostics = Field(default_factory=ProviderLookupDiagnostics)
    provider_snapshot_sources: list[str] = Field(default_factory=list)
    provider_cache_timestamps: dict[str, str | None] = Field(default_factory=dict)


class AnalysisContext(BaseModel):
    schema_version: str = "1.0.0"
    input_path: str
    output_path: str | None = None
    output_format: str
    generated_at: str
    input_format: str = "cve-list"
    input_paths: list[str] = Field(default_factory=list)
    input_sources: list[InputSourceSummary] = Field(default_factory=list)
    merged_input_count: int = 1
    duplicate_cve_count: int = 0
    provider_snapshot_file: str | None = None
    locked_provider_data: bool = False
    provider_snapshot_sources: list[str] = Field(default_factory=list)
    defensive_context_file: str | None = None
    defensive_context_sources: list[str] = Field(default_factory=list)
    defensive_context_hits: int = 0
    attack_enabled: bool = False
    attack_source: str = "none"
    attack_mapping_file: str | None = None
    attack_technique_metadata_file: str | None = None
    attack_source_version: str | None = None
    attack_version: str | None = None
    attack_domain: str | None = None
    mapping_framework: str | None = None
    mapping_framework_version: str | None = None
    attack_mapping_file_sha256: str | None = None
    attack_technique_metadata_file_sha256: str | None = None
    attack_metadata_format: str | None = None
    attack_metadata_source: str | None = None
    attack_stix_spec_version: str | None = None
    attack_mapping_created_at: str | None = None
    attack_mapping_updated_at: str | None = None
    attack_mapping_organization: str | None = None
    attack_mapping_author: str | None = None
    attack_mapping_contact: str | None = None
    warnings: list[str] = Field(default_factory=list)
    total_input: int = 0
    valid_input: int = 0
    occurrences_count: int = 0
    findings_count: int = 0
    filtered_out_count: int = 0
    nvd_hits: int = 0
    nvd_diagnostics: ProviderLookupDiagnostics = Field(default_factory=ProviderLookupDiagnostics)
    epss_diagnostics: ProviderLookupDiagnostics = Field(default_factory=ProviderLookupDiagnostics)
    kev_diagnostics: ProviderLookupDiagnostics = Field(default_factory=ProviderLookupDiagnostics)
    provider_degraded: bool = False
    provider_diagnostics: dict[str, ProviderLookupDiagnostics] = Field(default_factory=dict)
    provider_freshness: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    max_provider_age_hours: int | None = None
    provider_stale: bool = False
    provider_stale_sources: list[str] = Field(default_factory=list)
    epss_hits: int = 0
    kev_hits: int = 0
    attack_hits: int = 0
    suppressed_by_vex: int = 0
    under_investigation_count: int = 0
    asset_match_conflict_count: int = 0
    vex_conflict_count: int = 0
    waived_count: int = 0
    waiver_review_due_count: int = 0
    expired_waiver_count: int = 0
    attack_summary: AttackSummary = Field(default_factory=AttackSummary)
    active_filters: list[str] = Field(default_factory=list)
    policy_overrides: list[str] = Field(default_factory=list)
    priority_policy: PriorityPolicy = Field(default_factory=PriorityPolicy)
    policy_profile: str = "default"
    policy_file: str | None = None
    waiver_file: str | None = None
    counts_by_priority: dict[str, int] = Field(default_factory=dict)
    source_stats: dict[str, int] = Field(default_factory=dict)
    included_occurrence_count: int = 0
    included_unique_cves: int = 0
    data_sources: list[str] = Field(default_factory=list)
    cache_enabled: bool = False
    cache_dir: str | None = None


class SnapshotMetadata(AnalysisContext):
    schema_version: str = "1.1.0"
    snapshot_kind: str = "snapshot"
    config_file: str | None = None


class ProviderSnapshotMetadata(StrictModel):
    schema_version: str = "1.2.0"
    artifact_kind: str = "provider-snapshot"
    generated_at: str
    input_path: str | None = None
    input_paths: list[str] = Field(default_factory=list)
    input_format: str = "cve-list"
    selected_sources: list[str] = Field(default_factory=list)
    requested_cves: int = 0
    output_path: str | None = None
    cache_enabled: bool = False
    cache_only: bool = False
    cache_dir: str | None = None
    offline_kev_file: str | None = None
    nvd_api_key_env: str | None = None


class ProviderSnapshotItem(StrictModel):
    cve_id: str
    nvd: NvdData | None = None
    epss: EpssData | None = None
    kev: KevData | None = None
    defensive_contexts: list[DefensiveContext] = Field(default_factory=list)


class ProviderSnapshotReport(StrictModel):
    metadata: ProviderSnapshotMetadata
    items: list[ProviderSnapshotItem] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class SnapshotDiffMetadata(StrictModel):
    schema_version: str = "1.1.0"
    generated_at: str
    before_path: str
    after_path: str
    include_unchanged: bool = False


class SnapshotDiffSummary(StrictModel):
    added: int = 0
    removed: int = 0
    priority_up: int = 0
    priority_down: int = 0
    context_changed: int = 0
    unchanged: int = 0


class SnapshotDiffItem(StrictModel):
    cve_id: str
    category: str
    before_priority: str | None = None
    after_priority: str | None = None
    before_rank: int | None = None
    after_rank: int | None = None
    before_targets: list[str] = Field(default_factory=list)
    after_targets: list[str] = Field(default_factory=list)
    before_asset_ids: list[str] = Field(default_factory=list)
    after_asset_ids: list[str] = Field(default_factory=list)
    before_services: list[str] = Field(default_factory=list)
    after_services: list[str] = Field(default_factory=list)
    context_change_fields: list[str] = Field(default_factory=list)


class RollupMetadata(StrictModel):
    schema_version: str = "1.2.0"
    generated_at: str
    input_path: str
    input_kind: str
    dimension: str
    bucket_count: int = 0
    top: int = 5


class RollupCandidate(StrictModel):
    cve_id: str
    priority_label: str
    waived: bool = False
    waiver_status: str | None = None
    in_kev: bool = False
    highest_asset_criticality: str | None = None
    highest_asset_exposure: str | None = None
    asset_ids: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    owners: list[str] = Field(default_factory=list)
    remediation: RemediationPlan = Field(default_factory=RemediationPlan)
    recommended_action: str
    rank_reason: str


class RollupBucket(StrictModel):
    bucket: str
    dimension: str
    remediation_rank: int = 0
    finding_count: int = 0
    actionable_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    kev_count: int = 0
    attack_mapped_count: int = 0
    waived_count: int = 0
    waiver_review_due_count: int = 0
    expired_waiver_count: int = 0
    internet_facing_count: int = 0
    production_count: int = 0
    highest_priority: str = "Low"
    rank_reason: str | None = None
    context_hints: list[str] = Field(default_factory=list)
    top_cves: list[str] = Field(default_factory=list)
    owners: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    top_candidates: list[RollupCandidate] = Field(default_factory=list)
