"""Strict Decision/Evidence Kernel v2 contracts for Workbench runs."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ANALYSIS_EVIDENCE_SCHEMA_VERSION: Literal["analysis-evidence.v2"] = "analysis-evidence.v2"
FINDING_DECISION_EVIDENCE_SCHEMA_VERSION: Literal["finding-decision-evidence.v2"] = (
    "finding-decision-evidence.v2"
)
RUN_DIAGNOSTICS_SCHEMA_VERSION: Literal["run-diagnostics.v2"] = "run-diagnostics.v2"
ANALYSIS_RESULT_SCHEMA_V2: Literal["analysis-result.v2"] = "analysis-result.v2"
ANALYSIS_RESULT_SCHEMA_VERSION_V2 = "2.0.0"

RawEvidenceObject = dict[str, Any]
JsonObject = RawEvidenceObject


class EvidenceContractModel(BaseModel):
    """Base class for strict evidence contracts."""

    model_config = ConfigDict(extra="forbid")

    def to_jsonable(self) -> dict[str, Any]:
        """Return the JSON-ready representation used for database payloads."""
        return self.model_dump(mode="json", exclude_none=True)


class EvidenceUploadRef(EvidenceContractModel):
    """Managed upload metadata without local filesystem paths."""

    input_type: str | None = None
    original_filename: str | None = None
    stored_filename: str | None = None
    content_type: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    path: str | None = None
    storage_ref: str | None = None


class AnalysisEvidenceUploadsV2(EvidenceContractModel):
    """Run upload refs that contributed to the evidence graph."""

    input: EvidenceUploadRef | None = None
    asset_context: EvidenceUploadRef | None = None
    vex: EvidenceUploadRef | None = None


class RunCountsV2(EvidenceContractModel):
    """Stable run/finding counters used by API and reports."""

    created_findings: int = 0
    updated_findings: int = 0
    ignored_lines: int = 0
    rows_read: int = 0
    occurrence_count: int = 0
    finding_count: int = 0
    counts_by_priority: dict[str, int] = Field(default_factory=dict)
    kev_hits: int = 0
    epss_hits: int = 0
    nvd_hits: int = 0
    suppressed_by_vex: int = 0
    under_investigation_count: int = 0
    vex_conflict_count: int = 0
    attack_mapped_cves: int = 0


class AnalysisServiceEvidenceV2(EvidenceContractModel):
    """Stable producer metadata for a decision run."""

    pipeline: str
    engine: str
    kernel: str


class AnalysisSemanticsV2(EvidenceContractModel):
    """Typed explanation of how run-wide decisions were scoped."""

    analysis_decision_scope: str
    persistence_scope: str
    occurrence_overlay_fields: list[str] = Field(default_factory=list)
    finding_dedup_key_version: str
    decision_graph_schema_version: str | None = None
    normalized_input_sha256: str | None = None
    policy_sha256: str | None = None
    shared_facts_sha256: str | None = None
    replay_sha256: str | None = None
    cve_count: int = 0
    occurrence_count: int = 0
    finding_count: int = 0
    same_cve_can_create_distinct_asset_findings: bool = True


class DedupKeyPartsV2(EvidenceContractModel):
    """Dedup key material used to form one finding identity."""

    project_id: str | None = None
    cve_id: str | None = None
    source_id: str | None = None
    component_identity: str | None = None
    target_kind: str | None = None
    target_ref: str | None = None


class DedupDecisionV2(EvidenceContractModel):
    """Sampled dedup decision retained for audit and report summaries."""

    action: str
    dedup_key: str
    finding_id: str
    cve_id: str
    source_id: str | None = None
    component_identity: str | None = None
    target_kind: str | None = None
    target_ref: str | None = None


class DedupSummaryV2(EvidenceContractModel):
    """Run-level finding deduplication summary."""

    key_version: str
    created_findings: int = 0
    updated_findings: int = 0
    reused_findings: int = 0
    decision_count: int = 0
    decisions: list[DedupDecisionV2] = Field(default_factory=list)
    decision_sample_limit: int = 0
    omitted_decisions: int = 0


class ProviderDataQualityFlagEvidenceV2(EvidenceContractModel):
    """Provider quality flag preserved in the decision evidence contract."""

    source: str
    code: str
    message: str
    severity: Literal["info", "warning", "error"] = "warning"
    cve_id: str | None = None
    asset_id: str | None = None
    changed_fields: list[str] = Field(default_factory=list)
    changed_at: str | None = None


class PriorityExplanationReasonV2(EvidenceContractModel):
    """One reason in a priority explanation."""

    code: str | None = None
    source: str | None = None
    signal: str | None = None
    value: str | None = None
    threshold: str | None = None
    matched: bool = True
    message: str | None = None


class PriorityExplanationNoteV2(EvidenceContractModel):
    """One note in a priority explanation."""

    code: str | None = None
    source: str | None = None
    severity: str = "info"
    message: str | None = None


class PriorityExplanationV2(EvidenceContractModel):
    """Structured priority explanation projected from the analysis engine."""

    cve_id: str | None = None
    priority_label: str | None = None
    priority_state: str | None = None
    operational_score: float | None = None
    data_quality_confidence: str | None = None
    summary: str | None = None
    human_readable: str | None = None
    reason_codes: list[str] = Field(default_factory=list)
    reasons: list[PriorityExplanationReasonV2] = Field(default_factory=list)
    notes: list[PriorityExplanationNoteV2] = Field(default_factory=list)
    recommended_action: str | None = None


class OccurrenceScopeV2(EvidenceContractModel):
    """Typed scope overlay for one finding occurrence."""

    source: str | None = None
    source_id: str | None = None
    source_record_id: str | None = None
    component_name: str | None = None
    component_version: str | None = None
    purl: str | None = None
    package_type: str | None = None
    target_kind: str | None = None
    target_ref: str | None = None
    asset_id: str | None = None
    asset_owner: str | None = None
    asset_business_service: str | None = None
    asset_exposure: str | None = None
    asset_environment: str | None = None
    asset_criticality: str | None = None
    vex_status: str | None = None
    vex_match_type: str | None = None
    vex_source_path: str | None = None


class OccurrenceDedupEvidenceV2(EvidenceContractModel):
    """Typed dedup evidence attached to a persisted occurrence."""

    key: str | None = None
    key_version: str | None = None
    observation_key: str | None = None
    observation_key_version: str | None = None
    action: str | None = None
    parts: DedupKeyPartsV2 | None = None


class WorkflowArtifactRefV2(EvidenceContractModel):
    """Compact workflow artifact reference."""

    kind: str
    id: str | None = None
    report_id: str | None = None
    path: str | None = None
    name: str | None = None


class WorkflowResultRefV2(EvidenceContractModel):
    """Terminal workflow result reference for successful import runs."""

    schema_version: Literal["workflow-result-ref.v2"] = "workflow-result-ref.v2"
    analysis_evidence_id: str
    artifact_refs: list[WorkflowArtifactRefV2] = Field(default_factory=list)


class ProviderEvidenceV2(EvidenceContractModel):
    """Provider snapshot and provider-quality evidence for a run or finding."""

    provider_snapshot_id: str | None = None
    provider_snapshot_hash: str | None = None
    provider_snapshot_file: str | None = None
    locked_provider_data: bool = False
    provider_degraded: bool = False
    provider_data_quality_flags: dict[str, list[ProviderDataQualityFlagEvidenceV2]] = Field(
        default_factory=dict
    )
    provider_evidence: RawEvidenceObject = Field(default_factory=dict)
    nvd_hits: int = 0
    epss_hits: int = 0
    kev_hits: int = 0


class PriorityEvidenceV2(EvidenceContractModel):
    """Priority and scoring explanation for one finding decision."""

    priority_label: str
    priority_rank: int
    priority_state: str | None = None
    operational_score: float | None = None
    operational_score_reasons: list[str] = Field(default_factory=list)
    explanation: PriorityExplanationV2 = Field(default_factory=PriorityExplanationV2)
    rationale: str | None = None
    data_quality_confidence: str | None = None
    data_quality_flags: list[ProviderDataQualityFlagEvidenceV2] = Field(default_factory=list)
    raw: RawEvidenceObject = Field(default_factory=dict)


class GovernanceEvidenceV2(EvidenceContractModel):
    """Governance signals from VEX, waivers, and accepted-risk state."""

    suppressed_by_vex: bool = False
    under_investigation: bool = False
    waived: bool = False
    vex_statuses: dict[str, int] = Field(default_factory=dict)
    waiver: RawEvidenceObject = Field(default_factory=dict)
    data_quality: RawEvidenceObject = Field(default_factory=dict)


class AttackEvidenceV2(EvidenceContractModel):
    """Finding ATT&CK evidence used by details, reports, and Navigator export."""

    mapped: bool = False
    source: str = "none"
    review_status: str = "unreviewed"
    defensive_note: str | None = None
    rationale: str | None = None
    confidence: str | None = None
    technique_ids: list[str] = Field(default_factory=list)
    tactic_ids: list[str] = Field(default_factory=list)
    mappings: list[RawEvidenceObject] = Field(default_factory=list)


class RemediationEvidenceV2(EvidenceContractModel):
    """Decision guidance used for worklist and report remediation views."""

    recommended_action: str | None = None
    decision_statement: str | None = None
    recommendation: str | None = None
    recommendation_label: str | None = None
    business_impact: str | None = None
    sla: RawEvidenceObject = Field(default_factory=dict)
    raw: RawEvidenceObject = Field(default_factory=dict)


class OccurrenceEvidenceV2(EvidenceContractModel):
    """One source/scanner occurrence that contributed to a finding decision."""

    occurrence_id: str | None = None
    analysis_run_id: str
    source: str | None = None
    scanner: str | None = None
    raw_reference: str | None = None
    fix_version: str | None = None
    source_format: str | None = None
    source_id: str | None = None
    source_record_id: str | None = None
    component_name: str | None = None
    component_version: str | None = None
    purl: str | None = None
    package_type: str | None = None
    fix_versions: list[str] | None = None
    target_kind: str | None = None
    target_ref: str | None = None
    asset_id: str | None = None
    asset_owner: str | None = None
    asset_business_service: str | None = None
    asset_exposure: str | None = None
    asset_environment: str | None = None
    asset_criticality: str | None = None
    raw_severity: str | None = None
    vex_status: str | None = None
    vex_justification: str | None = None
    vex_action_statement: str | None = None
    vex_match_type: str | None = None
    vex_source_format: str | None = None
    vex_source_record_id: str | None = None
    vex_source_path: str | None = None
    vex_candidate_count: int = 0
    import_evidence: RawEvidenceObject = Field(default_factory=dict)
    dedup: OccurrenceDedupEvidenceV2 = Field(default_factory=OccurrenceDedupEvidenceV2)


class FindingDecisionEvidenceV2(EvidenceContractModel):
    """Current decision and evidence graph for one finding in one run."""

    schema_version: Literal["finding-decision-evidence.v2"] = (
        FINDING_DECISION_EVIDENCE_SCHEMA_VERSION
    )
    finding_id: str
    analysis_run_id: str
    project_id: str
    cve_id: str
    dedup_key: str
    status: str
    priority: str
    priority_rank: int
    risk_score: float | None = None
    operational_rank: int = 0
    in_kev: bool = False
    epss: float | None = None
    cvss_base_score: float | None = None
    attack_mapped: bool = False
    suppressed_by_vex: bool = False
    under_investigation: bool = False
    waived: bool = False
    rationale: str | None = None
    recommended_action: str | None = None
    occurrence_scope: OccurrenceScopeV2 = Field(default_factory=OccurrenceScopeV2)
    priority_evidence: PriorityEvidenceV2
    provider: ProviderEvidenceV2 = Field(default_factory=ProviderEvidenceV2)
    governance: GovernanceEvidenceV2 = Field(default_factory=GovernanceEvidenceV2)
    attack: AttackEvidenceV2 = Field(default_factory=AttackEvidenceV2)
    remediation: RemediationEvidenceV2 = Field(default_factory=RemediationEvidenceV2)
    occurrences: list[OccurrenceEvidenceV2] = Field(default_factory=list)


class RunParseErrorV2(EvidenceContractModel):
    """Stable parser diagnostic item."""

    input_type: str
    filename: str | None = None
    message: str
    error_type: str
    line: int | None = None
    field: str | None = None
    value: str | None = None


class RunFailureV2(EvidenceContractModel):
    """Structured workflow failure metadata."""

    message: str
    stage: str
    error_type: str | None = None
    filename: str | None = None


class RunDiagnosticsV2(EvidenceContractModel):
    """Typed terminal diagnostics for failed or degraded runs."""

    schema_version: Literal["run-diagnostics.v2"] = RUN_DIAGNOSTICS_SCHEMA_VERSION
    stage: str | None = None
    message: str | None = None
    error_type: str | None = None
    parse_errors: list[RunParseErrorV2] = Field(default_factory=list)
    analysis_error: RunFailureV2 | None = None
    asset_context_error: RunFailureV2 | None = None
    vex_error: RunFailureV2 | None = None
    warnings: list[str] = Field(default_factory=list)


class AnalysisEvidenceV2(EvidenceContractModel):
    """Run-wide source of truth for Workbench decisions and report generation."""

    schema_version: Literal["analysis-evidence.v2"] = ANALYSIS_EVIDENCE_SCHEMA_VERSION
    analysis_evidence_id: str | None = None
    analysis_run_id: str
    project_id: str
    input_type: str
    filename: str | None = None
    status: str
    input_sha256: str | None = None
    counts: RunCountsV2 = Field(default_factory=RunCountsV2)
    uploads: AnalysisEvidenceUploadsV2 = Field(default_factory=AnalysisEvidenceUploadsV2)
    provider: ProviderEvidenceV2 = Field(default_factory=ProviderEvidenceV2)
    warnings: list[str] = Field(default_factory=list)
    parse_errors: list[RunParseErrorV2] = Field(default_factory=list)
    analysis_service: AnalysisServiceEvidenceV2
    analysis_semantics: AnalysisSemanticsV2
    asset_context: RawEvidenceObject | None = None
    vex: RawEvidenceObject | None = None
    dedup_summary: DedupSummaryV2 | None = None
    attack: AttackEvidenceV2 = Field(default_factory=AttackEvidenceV2)
    diagnostics: RunDiagnosticsV2 | None = None
