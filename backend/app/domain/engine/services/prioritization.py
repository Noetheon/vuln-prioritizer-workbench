"""Combine enrichment data into prioritized findings."""

from __future__ import annotations

from collections import Counter

from app.domain.engine.models import (
    AttackData,
    ComparisonFinding,
    ContextPolicyProfile,
    EpssData,
    FindingProvenance,
    KevData,
    NvdData,
    PrioritizedFinding,
    PriorityPolicy,
    ProviderEvidence,
)
from app.domain.engine.scoring import (
    build_comparison_reason,
    build_priority_drivers,
    build_rationale,
    determine_cvss_only_priority,
    determine_priority,
)
from app.domain.engine.services.contextualization import (
    is_suppressed_by_vex,
    is_under_investigation,
)
from app.domain.engine.services.prioritization_attack import (
    build_attack_context_summary as _attack_context_summary,
)
from app.domain.engine.services.prioritization_ranking import (
    assign_operational_ranks as _assign_operational_ranks,
)
from app.domain.engine.services.prioritization_sorting import (
    SortField,
    sort_comparison_findings,
    sort_prioritized_findings,
)
from app.domain.engine.services.remediation import RemediationService


class PrioritizationService:
    """Create final prioritized findings from enrichment data."""

    def __init__(self, policy: PriorityPolicy | None = None) -> None:
        """Initialize a new instance of PrioritizationService."""
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
        """Prioritize method for PrioritizationService."""
        findings: list[PrioritizedFinding] = []
        active_context_profile = context_profile or ContextPolicyProfile()
        provenance_map = provenance_by_cve or {}
        remediation_service = RemediationService()

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
            remediation, recommended_action = remediation_service.build_action(
                provenance,
                priority_label=priority_label,
                kev=kev,
            )
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
                    attack_context=_attack_context_summary(cve_id, attack),
                    provenance=provenance,
                    context_summary=context_summary,
                    context_recommendation=context_recommendation,
                    highest_asset_criticality=provenance.highest_asset_criticality,
                    asset_count=provenance.asset_count,
                    suppressed_by_vex=suppressed_by_vex,
                    under_investigation=under_investigation,
                    priority_label=priority_label.value,
                    priority_rank=priority_rank,
                    priority_drivers=build_priority_drivers(nvd, epss, kev, self.policy),
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
                    provider_evidence=ProviderEvidence(
                        nvd=nvd,
                        epss=epss,
                        kev=kev,
                    ),
                    remediation=remediation,
                    recommended_action=recommended_action,
                )
            )

        ranked_findings = self.assign_operational_ranks(findings)
        sorted_findings = self.sort_findings(ranked_findings, sort_by="priority")
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
        """Sort findings for Workbench and report output."""
        return sort_prioritized_findings(findings, sort_by=sort_by)

    def assign_operational_ranks(
        self,
        findings: list[PrioritizedFinding],
    ) -> list[PrioritizedFinding]:
        """Attach deterministic operational work-queue ranks without changing base priority."""
        return _assign_operational_ranks(findings, self.policy)

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
                    under_investigation=finding.under_investigation,
                    waived=finding.waived,
                    waiver_status=finding.waiver_status,
                    waiver_reason=finding.waiver_reason,
                    waiver_owner=finding.waiver_owner,
                    waiver_expires_on=finding.waiver_expires_on,
                    waiver_review_on=finding.waiver_review_on,
                    waiver_days_remaining=finding.waiver_days_remaining,
                    waiver_scope=finding.waiver_scope,
                    waiver_id=finding.waiver_id,
                    waiver_matched_scope=finding.waiver_matched_scope,
                    waiver_approval_ref=finding.waiver_approval_ref,
                    waiver_ticket_url=finding.waiver_ticket_url,
                    operational_rank=finding.operational_rank,
                    context_rank_reasons=finding.context_rank_reasons,
                    priority_state=finding.priority_state,
                    operational_score=finding.operational_score,
                    operational_score_reasons=finding.operational_score_reasons,
                    defensive_contexts=finding.defensive_contexts,
                    data_quality_flags=finding.data_quality_flags,
                    data_quality_confidence=finding.data_quality_confidence,
                    changed=cvss_only_rank != finding.priority_rank,
                    delta_rank=cvss_only_rank - finding.priority_rank,
                    change_reason=build_comparison_reason(
                        finding,
                        cvss_only_label=cvss_only_label,
                        cvss_only_rank=cvss_only_rank,
                    ),
                )
            )

        return sort_comparison_findings(comparisons, sort_by=sort_by)

    @staticmethod
    def count_by_priority(findings: list[PrioritizedFinding]) -> dict[str, int]:
        """Count findings by enriched priority label."""
        counts = Counter(finding.priority_label for finding in findings)
        return dict(counts)
