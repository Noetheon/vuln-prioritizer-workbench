"""Combine enrichment data into prioritized findings."""

from __future__ import annotations

from collections import Counter
from typing import Literal

from vuln_prioritizer.models import (
    AttackData,
    ComparisonFinding,
    ContextPolicyProfile,
    EpssData,
    FindingProvenance,
    KevData,
    NvdData,
    PrioritizedFinding,
    PriorityPolicy,
)
from vuln_prioritizer.scoring import (
    build_comparison_reason,
    build_rationale,
    determine_cvss_only_priority,
    determine_priority,
    recommended_action,
)
from vuln_prioritizer.services.contextualization import is_suppressed_by_vex, is_under_investigation

SortField = Literal["priority", "epss", "cvss", "cve"]


class PrioritizationService:
    """Create final prioritized findings from enrichment data."""

    def __init__(self, policy: PriorityPolicy | None = None) -> None:
        self.policy = policy or PriorityPolicy()

    def prioritize(
        self,
        cve_ids: list[str],
        *,
        nvd_data: dict[str, NvdData],
        epss_data: dict[str, EpssData],
        kev_data: dict[str, KevData],
        attack_data: dict[str, AttackData],
        provenance_by_cve: dict[str, FindingProvenance] | None = None,
        context_profile: ContextPolicyProfile | None = None,
    ) -> tuple[list[PrioritizedFinding], dict[str, int]]:
        findings: list[PrioritizedFinding] = []
        active_context_profile = context_profile or ContextPolicyProfile()
        provenance_map = provenance_by_cve or {}

        for cve_id in cve_ids:
            nvd = nvd_data.get(cve_id, NvdData(cve_id=cve_id))
            epss = epss_data.get(cve_id, EpssData(cve_id=cve_id))
            kev = kev_data.get(cve_id, KevData(cve_id=cve_id, in_kev=False))
            attack = attack_data.get(cve_id, AttackData(cve_id=cve_id))
            provenance = provenance_map.get(cve_id, FindingProvenance())
            context_summary, context_recommendation = active_context_profile.describe(provenance)
            suppressed_by_vex = is_suppressed_by_vex(provenance)
            under_investigation = is_under_investigation(provenance)

            priority_label, priority_rank = determine_priority(nvd, epss, kev, self.policy)
            findings.append(
                PrioritizedFinding(
                    cve_id=cve_id,
                    description=nvd.description,
                    cvss_base_score=nvd.cvss_base_score,
                    cvss_severity=nvd.cvss_severity,
                    cvss_version=nvd.cvss_version,
                    epss=epss.epss,
                    epss_percentile=epss.percentile,
                    in_kev=kev.in_kev,
                    attack_mapped=attack.mapped,
                    attack_relevance=attack.attack_relevance,
                    attack_rationale=attack.attack_rationale,
                    attack_techniques=attack.attack_techniques,
                    attack_tactics=attack.attack_tactics,
                    attack_note=attack.attack_note,
                    attack_mappings=attack.mappings,
                    attack_technique_details=attack.techniques,
                    provenance=provenance,
                    context_summary=context_summary,
                    context_recommendation=context_recommendation,
                    highest_asset_criticality=provenance.highest_asset_criticality,
                    asset_count=provenance.asset_count,
                    suppressed_by_vex=suppressed_by_vex,
                    under_investigation=under_investigation,
                    priority_label=priority_label,
                    priority_rank=priority_rank,
                    rationale=build_rationale(
                        nvd,
                        epss,
                        kev,
                        attack,
                        provenance,
                        context_summary=context_summary,
                        suppressed_by_vex=suppressed_by_vex,
                        under_investigation=under_investigation,
                    ),
                    recommended_action=recommended_action(priority_label),
                )
            )

        sorted_findings = self.sort_findings(findings, sort_by="priority")
        return sorted_findings, self.count_by_priority(sorted_findings)

    def filter_findings(
        self,
        findings: list[PrioritizedFinding],
        *,
        priorities: set[str] | None = None,
        kev_only: bool = False,
        min_cvss: float | None = None,
        min_epss: float | None = None,
        show_suppressed: bool = False,
        hide_waived: bool = False,
    ) -> list[PrioritizedFinding]:
        """Filter findings after enrichment and scoring."""
        filtered: list[PrioritizedFinding] = []
        allowed_priorities = priorities or set()

        for finding in findings:
            if not show_suppressed and finding.suppressed_by_vex:
                continue
            if hide_waived and finding.waived:
                continue
            if allowed_priorities and finding.priority_label not in allowed_priorities:
                continue
            if kev_only and not finding.in_kev:
                continue
            if min_cvss is not None and (
                finding.cvss_base_score is None or finding.cvss_base_score < min_cvss
            ):
                continue
            if min_epss is not None and (finding.epss is None or finding.epss < min_epss):
                continue
            filtered.append(finding)

        return filtered

    def sort_findings(
        self,
        findings: list[PrioritizedFinding],
        *,
        sort_by: SortField = "priority",
    ) -> list[PrioritizedFinding]:
        """Sort findings for terminal and report output."""
        return sorted(findings, key=lambda finding: _finding_sort_key(finding, sort_by))

    def build_comparison(
        self,
        findings: list[PrioritizedFinding],
        *,
        sort_by: SortField = "priority",
    ) -> list[ComparisonFinding]:
        """Create `CVSS-only vs enriched` comparison rows from prioritized findings."""
        comparisons: list[ComparisonFinding] = []

        for finding in findings:
            cvss_only_label, cvss_only_rank = determine_cvss_only_priority(finding.cvss_base_score)
            comparisons.append(
                ComparisonFinding(
                    cve_id=finding.cve_id,
                    description=finding.description,
                    cvss_base_score=finding.cvss_base_score,
                    cvss_severity=finding.cvss_severity,
                    cvss_version=finding.cvss_version,
                    epss=finding.epss,
                    epss_percentile=finding.epss_percentile,
                    in_kev=finding.in_kev,
                    cvss_only_label=cvss_only_label,
                    cvss_only_rank=cvss_only_rank,
                    enriched_label=finding.priority_label,
                    enriched_rank=finding.priority_rank,
                    attack_mapped=finding.attack_mapped,
                    attack_relevance=finding.attack_relevance,
                    mapped_technique_count=len(finding.attack_technique_details),
                    mapped_tactics=finding.attack_tactics,
                    provenance=finding.provenance,
                    context_summary=finding.context_summary,
                    suppressed_by_vex=finding.suppressed_by_vex,
                    waived=finding.waived,
                    waiver_reason=finding.waiver_reason,
                    waiver_owner=finding.waiver_owner,
                    waiver_expires_on=finding.waiver_expires_on,
                    changed=cvss_only_rank != finding.priority_rank,
                    delta_rank=cvss_only_rank - finding.priority_rank,
                    change_reason=build_comparison_reason(
                        finding,
                        cvss_only_label=cvss_only_label,
                        cvss_only_rank=cvss_only_rank,
                    ),
                )
            )

        return sorted(comparisons, key=lambda row: _comparison_sort_key(row, sort_by))

    @staticmethod
    def count_by_priority(findings: list[PrioritizedFinding]) -> dict[str, int]:
        """Count findings by enriched priority label."""
        counts = Counter(finding.priority_label for finding in findings)
        return dict(counts)


def _finding_sort_key(finding: PrioritizedFinding, sort_by: SortField) -> tuple:
    if sort_by == "epss":
        return (
            _descending_numeric(finding.epss),
            finding.priority_rank,
            0 if finding.in_kev else 1,
            _descending_numeric(finding.cvss_base_score),
            finding.cve_id,
        )
    if sort_by == "cvss":
        return (
            _descending_numeric(finding.cvss_base_score),
            finding.priority_rank,
            0 if finding.in_kev else 1,
            _descending_numeric(finding.epss),
            finding.cve_id,
        )
    if sort_by == "cve":
        return (finding.cve_id,)

    return (
        finding.priority_rank,
        0 if finding.in_kev else 1,
        _descending_numeric(finding.epss),
        _descending_numeric(finding.cvss_base_score),
        finding.cve_id,
    )


def _comparison_sort_key(row: ComparisonFinding, sort_by: SortField) -> tuple:
    if sort_by == "epss":
        return (
            _descending_numeric(row.epss),
            row.enriched_rank,
            0 if row.in_kev else 1,
            _descending_numeric(row.cvss_base_score),
            row.cve_id,
        )
    if sort_by == "cvss":
        return (
            _descending_numeric(row.cvss_base_score),
            row.enriched_rank,
            0 if row.in_kev else 1,
            _descending_numeric(row.epss),
            row.cve_id,
        )
    if sort_by == "cve":
        return (row.cve_id,)

    return (
        row.enriched_rank,
        0 if row.in_kev else 1,
        _descending_numeric(row.epss),
        _descending_numeric(row.cvss_base_score),
        row.cve_id,
    )


def _descending_numeric(value: float | None) -> tuple[int, float]:
    if value is None:
        return 1, 0.0
    return 0, -value
