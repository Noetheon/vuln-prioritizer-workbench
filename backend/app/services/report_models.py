"""Report payload models and report service errors."""

from __future__ import annotations

from datetime import datetime
from typing import Any, TypeAlias

from pydantic import Field

from vuln_prioritizer.model_base import StrictModel

JsonObject: TypeAlias = dict[str, Any]


class ReportGenerationError(RuntimeError):
    """Raised when a report cannot be generated from the stored run."""


class ReportVerificationError(RuntimeError):
    """Raised when an evidence bundle cannot be verified."""


class ReportProviderSnapshot(StrictModel):
    """Provider snapshot context shown in generated reports."""

    id: str | None
    content_hash: str | None
    nvd_last_sync: str | None
    epss_date: str | None
    kev_catalog_version: str | None
    created_at: str | None = None
    source_hashes: JsonObject = Field(default_factory=dict)
    source_metadata: JsonObject = Field(default_factory=dict)


class ReportVulnerability(StrictModel):
    """Typed vulnerability details carried by report findings."""

    id: str | None = None
    source_id: str | None = None
    title: str | None = None
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    cwe: str | None = None
    published_at: datetime | str | None = None
    modified_at: datetime | str | None = None
    provider: JsonObject = Field(default_factory=dict)
    references: tuple[Any, ...] = Field(default_factory=tuple)
    reference_urls: tuple[Any, ...] = Field(default_factory=tuple)
    urls: tuple[Any, ...] = Field(default_factory=tuple)
    url: str | None = None
    href: str | None = None
    link: str | None = None


class ReportOccurrence(StrictModel):
    """Typed occurrence details carried by report findings."""

    id: str | None = None
    analysis_run_id: str | None = None
    source: str | None = None
    scanner: str | None = None
    raw_reference: str | None = None
    fix_version: str | None = None
    evidence: JsonObject = Field(default_factory=dict)
    path: str | None = None
    file: str | None = None
    artifact_uri: str | None = None
    purl: str | None = None
    target_kind: str | None = None
    target_ref: str | None = None


class ReportFinding(StrictModel):
    """Finding context shown in generated reports."""

    operational_rank: int
    cve_id: str
    priority: str
    status: str
    risk_score: float | None
    epss: float | None
    cvss_base_score: float | None
    in_kev: bool
    asset: str | None
    component: str | None
    rationale: str | None
    recommended_action: str | None
    data_quality_confidence: str | None
    id: str | None = None
    dedup_key: str | None = None
    priority_rank: int | None = None
    asset_key: str | None = None
    owner: str | None = None
    business_service: str | None = None
    environment: str | None = None
    exposure: str | None = None
    criticality: str | None = None
    component_purl: str | None = None
    attack_mapped: bool = False
    suppressed_by_vex: bool = False
    under_investigation: bool = False
    waived: bool = False
    decision_statement: str | None = None
    business_impact: str | None = None
    decision_sla: str | None = None
    data_quality_flags: tuple[str, ...] = Field(default_factory=tuple)
    vulnerability: ReportVulnerability | None = None
    explanation: JsonObject = Field(default_factory=dict)
    data_quality: JsonObject = Field(default_factory=dict)
    evidence: JsonObject = Field(default_factory=dict)
    occurrences: tuple[ReportOccurrence, ...] = Field(default_factory=tuple)
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class ReportPayload(StrictModel):
    """Pure rendering payload for deterministic snapshot tests."""

    generated_at: datetime
    project_id: str
    project_name: str
    run_id: str
    run_status: str
    input_type: str
    filename: str | None
    summary: JsonObject
    findings: tuple[ReportFinding, ...]
    provider_snapshot: ReportProviderSnapshot | None
    governance_rollups: JsonObject = Field(default_factory=dict)
    detection_coverage: JsonObject = Field(default_factory=dict)
    project_description: str | None = None
    project_created_at: datetime | None = None
    project_updated_at: datetime | None = None
    run_started_at: datetime | None = None
    run_finished_at: datetime | None = None
    run_error: str | None = None
    run_errors: JsonObject = Field(default_factory=dict)
    input_file_hash: str | None = None


class EvidencePackageArtifact(StrictModel):
    """Prepared evidence package artifact row for executive report rendering."""

    artifact: str
    purpose: str
    status: str
    sha256: str | None = None
    size_bytes: int | None = None
    kind: str | None = None
    note: str | None = None


class EvidencePackageContext(StrictModel):
    """Evidence package context for standalone HTML or generated bundle HTML."""

    mode: str = "standalone"
    manifest_path: str = "manifest.json"
    artifacts: tuple[EvidencePackageArtifact, ...] = Field(default_factory=tuple)


class RemediationCampaign(StrictModel):
    """Typed remediation campaign row used by executive report renderers."""

    rank: int = 0
    sort_rank: int
    cve_id: str
    group_key: str
    project_name: str | None = None
    alias: str = ""
    campaign_name: str
    findings: tuple[ReportFinding, ...]
    actionable_findings: tuple[ReportFinding, ...]
    assets: tuple[str, ...] = Field(default_factory=tuple)
    services: tuple[str, ...] = Field(default_factory=tuple)
    owners: tuple[str, ...] = Field(default_factory=tuple)
    environments: tuple[str, ...] = Field(default_factory=tuple)
    exposures: tuple[str, ...] = Field(default_factory=tuple)
    actions: tuple[str, ...] = Field(default_factory=tuple)
    slas: tuple[str, ...] = Field(default_factory=tuple)
    max_cvss: float | None = None
    max_epss: float | None = None
    in_kev: bool = False
    attack_techniques: tuple[str, ...] = Field(default_factory=tuple)
    attack_mappings: tuple[JsonObject, ...] = Field(default_factory=tuple)
    total_occurrences: int = 0
    total_assets: int = 0
    affected_assets: tuple[str, ...] = Field(default_factory=tuple)
    business_services: tuple[str, ...] = Field(default_factory=tuple)
    internet_facing_exposure: bool = False
    actionable_count: int = 0
    actionable_occurrences: int = 0
    accepted_count: int = 0
    waived_count: int = 0
    vex_count: int = 0
    fixed_count: int = 0
    open_actionable_count: int = 0
    priority_label: str = ""
    decision_statement: str = ""
    evidence_signals: str = ""


class ReportIdentity(StrictModel):
    """Executive report identity block."""

    report_type: str
    project_id: str
    project_name: str
    analysis_run_id: str
    generated_at: datetime
    run_status: str
    input_type: str
    input_file: str | None
    provider_snapshot_id: str | None


class DecisionBrief(StrictModel):
    """Decision brief block for the executive report."""

    decision_needed: str
    executive_summary: str
    management_approval_items: tuple[str, ...]
    caution_items: tuple[str, ...]
    validation_items: tuple[str, ...]


class RiskPosture(StrictModel):
    """Risk posture metrics for the executive report."""

    total_findings: int
    open_actionable_findings: int
    kev_backed_findings: int
    emergency_sla_count: int
    accepted_risk_findings: int
    vex_suppressed_findings: int
    fixed_evidence_findings: int
    review_due_or_expiring_count: int
    internet_facing_prod_count: int
    unique_cves_count: int
    provider_freshness_verdict: str
    evidence_bundle_status: str


class ActionPlanRow(StrictModel):
    """Typed action plan row."""

    time_window: str
    action: str
    scope: str
    owner: str
    evidence_basis: str


class BusinessServiceRiskRow(StrictModel):
    """Typed business service risk row."""

    service: str
    open_actionable_count: int
    open_actionable_campaigns: int
    emergency_campaigns: int
    governed_risk: str
    environment: str
    exposure: str
    owner: str
    decision_needed: str
    validation_evidence: str


class GovernanceExceptions(StrictModel):
    """Governance exception rollup for executive reports."""

    waiver_rows: tuple[JsonObject, ...] = Field(default_factory=tuple)
    waivers: int
    expired: int
    review_due: int
    expiring_soon: int
    accepted_findings: int
    vex_suppressed: int
    fixed_findings: int
    under_investigation: int


class EvidenceConfidence(StrictModel):
    """Evidence confidence block for executive reports."""

    provider_freshness_verdict: str
    provider_rows: tuple[JsonObject, ...] = Field(default_factory=tuple)
    snapshot_replay_status: str
    source_hashes: JsonObject = Field(default_factory=dict)
    static_html_safety_status: str


class EvidencePackageRow(StrictModel):
    """Typed evidence package row."""

    artifact: str
    purpose: str
    status: str
    sha256: str | None = None
    size_bytes: int | None = None
    kind: str | None = None
    note: str | None = None


class RecommendationRow(StrictModel):
    """Typed recommendation row."""

    campaign_name: str
    scope: str
    action: str
    sla: str
    owners: tuple[str, ...] = Field(default_factory=tuple)
    evidence_basis: str


class AttackContextView(StrictModel):
    """Reviewed ATT&CK context block for executive reports."""

    mapped_techniques: tuple[JsonObject, ...] = Field(default_factory=tuple)
    mapping_source: tuple[str, ...] = Field(default_factory=tuple)
    navigator_layer_status: str
    unmapped_handling_note: str
    no_llm_inference_note: str


class TechnicalAppendix(StrictModel):
    """Technical appendix block for executive reports."""

    note: str


class ExecutiveReportViewModel(StrictModel):
    """Prepared decision-brief model for the executive HTML renderer."""

    report_identity: ReportIdentity
    decision_brief: DecisionBrief
    risk_posture: RiskPosture
    action_plan: tuple[ActionPlanRow, ...]
    remediation_campaigns: tuple[RemediationCampaign, ...]
    business_services: tuple[BusinessServiceRiskRow, ...]
    governance_exceptions: GovernanceExceptions
    evidence_confidence: EvidenceConfidence
    evidence_package: tuple[EvidencePackageRow, ...]
    recommendations: tuple[RecommendationRow, ...]
    attack_context: AttackContextView
    technical_appendix: TechnicalAppendix


class AnalysisResultV1(StrictModel):
    """Stable machine-readable analysis-result.v1 export model."""

    schema_: str = Field(alias="schema", serialization_alias="schema")
    schema_version: str
    generated_at: str
    project: JsonObject
    analysis_run: JsonObject
    provider_snapshot: JsonObject | None
    findings: tuple[JsonObject, ...]
    explanations: JsonObject
    governance_rollups: JsonObject | None = None
    detection_coverage: JsonObject | None = None


MarkdownProviderSnapshot: TypeAlias = ReportProviderSnapshot
MarkdownReportFinding: TypeAlias = ReportFinding
MarkdownReportPayload: TypeAlias = ReportPayload


__all__ = [
    "ActionPlanRow",
    "AnalysisResultV1",
    "AttackContextView",
    "BusinessServiceRiskRow",
    "DecisionBrief",
    "EvidenceConfidence",
    "EvidencePackageArtifact",
    "EvidencePackageContext",
    "EvidencePackageRow",
    "ExecutiveReportViewModel",
    "GovernanceExceptions",
    "MarkdownProviderSnapshot",
    "MarkdownReportFinding",
    "MarkdownReportPayload",
    "RecommendationRow",
    "RemediationCampaign",
    "ReportFinding",
    "ReportGenerationError",
    "ReportIdentity",
    "ReportOccurrence",
    "ReportPayload",
    "ReportProviderSnapshot",
    "ReportVerificationError",
    "ReportVulnerability",
    "RiskPosture",
    "TechnicalAppendix",
]
