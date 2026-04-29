"""Input normalization, provenance, asset context, and VEX models."""

from __future__ import annotations

from pydantic import BaseModel, Field

from vuln_prioritizer.model_base import StrictModel


class InputItem(StrictModel):
    cve_id: str
    source_format: str = "cve-list"


class InputOccurrence(StrictModel):
    cve_id: str
    source_format: str = "cve-list"
    source_id: str | None = Field(default=None, exclude_if=lambda value: value is None)
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
    asset_match_rule_id: str | None = None
    asset_match_row: int | None = None
    asset_match_mode: str | None = None
    asset_match_pattern: str | None = None
    asset_match_precedence: int | None = None
    asset_match_candidate_count: int = 0
    vex_status: str | None = None
    vex_justification: str | None = None
    vex_action_statement: str | None = None
    vex_match_type: str | None = None
    vex_source_format: str | None = None
    vex_source_record_id: str | None = None
    vex_source_path: str | None = None
    vex_candidate_count: int = 0


class InputSourceSummary(StrictModel):
    input_path: str
    input_format: str
    total_rows: int = 0
    occurrence_count: int = 0
    unique_cves: int = 0
    included_occurrence_count: int | None = None
    included_unique_cves: int | None = None
    warning_count: int = 0


class ParsedInput(BaseModel):
    input_format: str = "cve-list"
    total_rows: int = 0
    occurrences: list[InputOccurrence] = Field(default_factory=list)
    unique_cves: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    source_stats: dict[str, int] = Field(default_factory=dict)
    input_paths: list[str] = Field(default_factory=list)
    source_summaries: list[InputSourceSummary] = Field(default_factory=list)
    merged_input_count: int = 1
    duplicate_cve_count: int = 0
    included_occurrence_count: int = 0
    included_unique_cves: int = 0
    asset_match_conflict_count: int = 0
    vex_conflict_count: int = 0


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
    rule_id: str | None = None
    match_mode: str = "exact"
    precedence: int = 0
    row_number: int | None = None
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
    source_path: str | None = None
    source_file_order: int | None = None
    statement_order: int | None = None
