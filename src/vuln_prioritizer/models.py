"""Pydantic models for the CLI."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    """Base model with frozen instances and forbidden extra fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class InputItem(StrictModel):
    cve_id: str
    source_format: str = "cve-list"


class InputOccurrence(StrictModel):
    cve_id: str
    source_format: str = "cve-list"
    component_name: str | None = None
    component_version: str | None = None
    purl: str | None = None
    package_type: str | None = None
    file_path: str | None = None
    dependency_path: str | None = None
    fix_versions: list[str] = Field(default_factory=list)
    source_record_id: str | None = None
    raw_severity: str | None = None
    target_kind: str = "generic"
    target_ref: str | None = None
    asset_id: str | None = None
    asset_criticality: str | None = None
    asset_exposure: str | None = None
    asset_environment: str | None = None
    asset_owner: str | None = None
    asset_business_service: str | None = None
    vex_status: str | None = None
    vex_justification: str | None = None
    vex_action_statement: str | None = None


class ParsedInput(BaseModel):
    input_format: str = "cve-list"
    total_rows: int = 0
    occurrences: list[InputOccurrence] = Field(default_factory=list)
    unique_cves: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    source_stats: dict[str, int] = Field(default_factory=dict)


class FindingProvenance(StrictModel):
    occurrence_count: int = 0
    active_occurrence_count: int = 0
    suppressed_occurrence_count: int = 0
    source_formats: list[str] = Field(default_factory=list)
    components: list[str] = Field(default_factory=list)
    affected_paths: list[str] = Field(default_factory=list)
    fix_versions: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    asset_ids: list[str] = Field(default_factory=list)
    highest_asset_criticality: str | None = None
    highest_asset_exposure: str | None = None
    asset_count: int = 0
    vex_statuses: dict[str, int] = Field(default_factory=dict)
    occurrences: list[InputOccurrence] = Field(default_factory=list)


class AssetContextRecord(StrictModel):
    target_kind: str
    target_ref: str
    asset_id: str
    criticality: str | None = None
    exposure: str | None = None
    environment: str | None = None
    owner: str | None = None
    business_service: str | None = None


class ContextPolicyProfile(StrictModel):
    name: str = "default"
    narrative_only: bool = True
    enterprise_escalation: bool = False
    internet_facing_boost: bool = False
    prod_asset_boost: bool = False

    def describe(self, provenance: FindingProvenance) -> tuple[str | None, str | None]:
        if provenance.occurrence_count == 0:
            return None, None

        summary_parts: list[str] = [
            f"Seen in {provenance.occurrence_count} occurrence(s)",
        ]
        if provenance.asset_count:
            summary_parts.append(f"across {provenance.asset_count} mapped asset(s)")
        if provenance.highest_asset_criticality:
            summary_parts.append(
                f"highest asset criticality {provenance.highest_asset_criticality}"
            )
        if provenance.highest_asset_exposure:
            summary_parts.append(f"highest exposure {provenance.highest_asset_exposure}")
        summary = ", ".join(summary_parts) + "."

        if self.narrative_only and not self.enterprise_escalation:
            return summary, (
                "Review the affected components and assets in context before final remediation "
                "scheduling."
            )

        escalation_reasons: list[str] = []
        if (
            self.internet_facing_boost
            and provenance.highest_asset_exposure
            and provenance.highest_asset_exposure.lower() == "internet-facing"
        ):
            escalation_reasons.append("internet-facing exposure")
        if self.prod_asset_boost and any(
            occurrence.asset_environment and occurrence.asset_environment.lower() == "prod"
            for occurrence in provenance.occurrences
        ):
            escalation_reasons.append("production environment")

        if not escalation_reasons:
            return summary, (
                "Context does not raise the default response, but affected components and owners "
                "should still be reviewed."
            )

        return summary, (
            "Escalate validation and remediation because context indicates "
            + ", ".join(escalation_reasons)
            + "."
        )


class VexStatement(StrictModel):
    source_format: str
    cve_id: str
    status: str
    component_name: str | None = None
    component_version: str | None = None
    purl: str | None = None
    target_kind: str | None = None
    target_ref: str | None = None
    justification: str | None = None
    action_statement: str | None = None
    source_record_id: str | None = None


class NvdData(StrictModel):
    cve_id: str
    description: str | None = None
    cvss_base_score: float | None = None
    cvss_severity: str | None = None
    cvss_version: str | None = None
    published: str | None = None
    last_modified: str | None = None
    cwes: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class EpssData(StrictModel):
    cve_id: str
    epss: float | None = None
    percentile: float | None = None
    date: str | None = None


class KevData(StrictModel):
    cve_id: str
    in_kev: bool = False
    vendor_project: str | None = None
    product: str | None = None
    date_added: str | None = None
    required_action: str | None = None
    due_date: str | None = None


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
    priority_label: str
    priority_rank: int
    rationale: str
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
    waived: bool = False
    waiver_status: str | None = None
    waiver_reason: str | None = None
    waiver_owner: str | None = None
    waiver_expires_on: str | None = None
    waiver_review_on: str | None = None
    waiver_days_remaining: int | None = None
    changed: bool
    delta_rank: int
    change_reason: str


class EnrichmentResult(BaseModel):
    nvd: dict[str, NvdData] = Field(default_factory=dict)
    epss: dict[str, EpssData] = Field(default_factory=dict)
    kev: dict[str, KevData] = Field(default_factory=dict)
    attack: dict[str, AttackData] = Field(default_factory=dict)
    attack_source: str = "none"
    attack_mapping_file: str | None = None
    attack_technique_metadata_file: str | None = None
    attack_source_version: str | None = None
    attack_version: str | None = None
    attack_domain: str | None = None
    mapping_framework: str | None = None
    mapping_framework_version: str | None = None
    parsed_input: ParsedInput = Field(default_factory=ParsedInput)
    warnings: list[str] = Field(default_factory=list)


class AnalysisContext(BaseModel):
    schema_version: str = "1.0.0"
    input_path: str
    output_path: str | None = None
    output_format: str
    generated_at: str
    input_format: str = "cve-list"
    attack_enabled: bool = False
    attack_source: str = "none"
    attack_mapping_file: str | None = None
    attack_technique_metadata_file: str | None = None
    attack_source_version: str | None = None
    attack_version: str | None = None
    attack_domain: str | None = None
    mapping_framework: str | None = None
    mapping_framework_version: str | None = None
    warnings: list[str] = Field(default_factory=list)
    total_input: int = 0
    valid_input: int = 0
    occurrences_count: int = 0
    findings_count: int = 0
    filtered_out_count: int = 0
    nvd_hits: int = 0
    epss_hits: int = 0
    kev_hits: int = 0
    attack_hits: int = 0
    suppressed_by_vex: int = 0
    under_investigation_count: int = 0
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
    data_sources: list[str] = Field(default_factory=list)
    cache_enabled: bool = False
    cache_dir: str | None = None


class SnapshotMetadata(AnalysisContext):
    schema_version: str = "1.1.0"
    snapshot_kind: str = "snapshot"
    config_file: str | None = None


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


class DoctorCheck(StrictModel):
    name: str
    status: str
    detail: str


class DoctorReport(StrictModel):
    schema_version: str = "1.1.0"
    generated_at: str
    live: bool = False
    config_file: str | None = None
    checks: list[DoctorCheck] = Field(default_factory=list)


class EvidenceBundleFile(StrictModel):
    path: str
    kind: str
    size_bytes: int
    sha256: str


class EvidenceBundleManifest(StrictModel):
    schema_version: str = "1.1.0"
    bundle_kind: str = "evidence-bundle"
    generated_at: str
    source_analysis_path: str
    source_input_path: str | None = None
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


class WaiverRule(StrictModel):
    id: str | None = None
    cve_id: str
    owner: str
    reason: str
    expires_on: str
    review_on: str | None = None
    asset_ids: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)


class WaiverHealthSummary(StrictModel):
    total_rules: int = 0
    active_count: int = 0
    review_due_count: int = 0
    expired_count: int = 0
    review_window_days: int = 14
