"""Recommendation, SLA, and decision statement generation."""

from __future__ import annotations

from typing import Literal

from app.domain.engine.models import (
    BusinessImpactBlock,
    FindingDecisionGuidance,
    PrioritizedFinding,
    SlaTarget,
)
from app.domain.engine.models_decision import DecisionRecommendation

SLA_BY_PRIORITY: dict[str, SlaTarget] = {
    "Critical": SlaTarget(
        priority="Critical",
        label="Emergency",
        target_hours=24,
        target_days=1,
        guidance="Validate scope and begin remediation or approved mitigation within 24 hours.",
    ),
    "High": SlaTarget(
        priority="High",
        label="High",
        target_hours=168,
        target_days=7,
        guidance="Validate scope and schedule remediation or mitigation within 7 days.",
    ),
    "Medium": SlaTarget(
        priority="Medium",
        label="Standard",
        target_hours=720,
        target_days=30,
        guidance="Plan remediation in the regular risk-reduction cycle within 30 days.",
    ),
    "Low": SlaTarget(
        priority="Low",
        label="Monitor",
        target_hours=2160,
        target_days=90,
        guidance="Track in the normal maintenance cycle and re-evaluate if exposure changes.",
    ),
}

GOVERNANCE_SLA_BY_STATE: dict[str, SlaTarget] = {
    "Accepted": SlaTarget(
        priority="Accepted",
        label="Governance Review",
        guidance="Keep waiver ownership, review date, and expiry evidence visible for review.",
    ),
    "Suppressed": SlaTarget(
        priority="Suppressed",
        label="Evidence Review",
        guidance="Keep suppression evidence visible and re-open if source context changes.",
    ),
    "Fixed": SlaTarget(
        priority="Fixed",
        label="Verification",
        guidance="Keep fixed evidence visible and verify future scanner runs stay clean.",
    ),
}

RECOMMENDATION_LABELS = {
    "patch": "Patch",
    "mitigate": "Mitigate",
    "monitor": "Monitor",
    "review": "Review",
    "waiver": "Waiver",
}

BusinessImpactLevel = Literal["critical", "high", "medium", "low", "governance"]


class DecisionGuidanceService:
    """Build deterministic management-readable guidance from finding evidence."""

    def build(self, finding: PrioritizedFinding) -> FindingDecisionGuidance:
        """Build method for DecisionGuidanceService."""
        recommendation, recommendation_reasons = _select_recommendation(finding)
        sla = _sla_for_finding(finding)
        business_impact = _business_impact(finding)
        visibility = _visibility_statement(finding)
        decision_statement = _decision_statement(
            finding,
            recommendation=recommendation,
            sla=sla,
            business_impact=business_impact,
        )
        reason_codes = [
            f"recommendation.{recommendation}",
            f"sla.{sla.priority.lower().replace(' ', '_')}.{sla.label.lower().replace(' ', '_')}",
            f"impact.{business_impact.level}",
            *recommendation_reasons,
            *_impact_reason_codes(business_impact.drivers),
        ]
        return FindingDecisionGuidance(
            recommendation=recommendation,
            recommendation_label=RECOMMENDATION_LABELS[recommendation],
            sla=sla,
            business_impact=business_impact,
            decision_statement=decision_statement,
            visibility=visibility,
            reason_codes=_unique(reason_codes),
        )


def build_decision_guidance(finding: PrioritizedFinding) -> FindingDecisionGuidance:
    """Convenience wrapper around :class:`DecisionGuidanceService`."""
    return DecisionGuidanceService().build(finding)


def _select_recommendation(finding: PrioritizedFinding) -> tuple[DecisionRecommendation, list[str]]:
    """Select recommendation function."""
    state = finding.priority_state or finding.priority_label
    if state in {"Suppressed", "Fixed"} or finding.suppressed_by_vex:
        return "monitor", [f"recommendation.monitor.{state.lower()}_evidence_visible"]
    if state == "Accepted" or finding.waived:
        return "waiver", ["recommendation.waiver.accepted_risk_visible"]
    if _has_fixed_version_evidence(finding):
        return "patch", ["recommendation.patch.fixed_version_evidence"]
    if finding.in_kev or finding.priority_label in {"Critical", "High"}:
        return "mitigate", ["recommendation.mitigate.urgent_without_fix_evidence"]
    if _needs_review(finding):
        return "review", ["recommendation.review.incomplete_context"]
    return "monitor", ["recommendation.monitor.normal_cycle"]


def _sla_for_finding(finding: PrioritizedFinding) -> SlaTarget:
    """Sla for finding function."""
    state = finding.priority_state or finding.priority_label
    if state in GOVERNANCE_SLA_BY_STATE:
        return GOVERNANCE_SLA_BY_STATE[state]
    if finding.suppressed_by_vex:
        return GOVERNANCE_SLA_BY_STATE["Suppressed"]
    if finding.waived:
        return GOVERNANCE_SLA_BY_STATE["Accepted"]
    return SLA_BY_PRIORITY.get(finding.priority_label, SLA_BY_PRIORITY["Low"])


def _business_impact(finding: PrioritizedFinding) -> BusinessImpactBlock:
    """Business impact function."""
    drivers = _business_impact_drivers(finding)
    level: BusinessImpactLevel
    if finding.priority_state in {"Accepted", "Suppressed", "Fixed"} or (
        finding.waived or finding.suppressed_by_vex
    ):
        level = "governance"
    elif finding.in_kev or finding.priority_label == "Critical":
        level = "critical"
    elif finding.priority_label == "High" or (finding.highest_asset_criticality or "").lower() in {
        "critical",
        "high",
    }:
        level = "high"
    elif finding.priority_label == "Medium":
        level = "medium"
    else:
        level = "low"
    return BusinessImpactBlock(
        level=level,
        text=_business_impact_text(level, drivers),
        drivers=drivers,
    )


def _business_impact_drivers(finding: PrioritizedFinding) -> list[str]:
    """Business impact drivers function."""
    drivers: list[str] = []
    if finding.in_kev:
        drivers.append("CISA KEV known-exploited listing")
    if finding.epss is not None and finding.epss >= 0.7:
        drivers.append(f"EPSS {finding.epss:.3f}")
    if finding.cvss_base_score is not None and finding.cvss_base_score >= 9.0:
        drivers.append(f"CVSS {finding.cvss_base_score:.1f}")
    if finding.provenance.highest_asset_exposure:
        drivers.append(f"{finding.provenance.highest_asset_exposure} exposure")
    environments = _asset_environments(finding)
    if environments:
        drivers.append("environment " + _summarize_values(environments))
    criticality = finding.highest_asset_criticality or finding.provenance.highest_asset_criticality
    if criticality:
        drivers.append(f"{criticality} asset criticality")
    services = _asset_business_services(finding)
    if services:
        drivers.append("business service " + _summarize_values(services))
    owners = _asset_owners(finding)
    if owners:
        drivers.append("owner " + _summarize_values(owners))
    if finding.provenance.active_occurrence_count > 1:
        drivers.append(f"{finding.provenance.active_occurrence_count} active occurrences")
    if _asset_context_unknown(finding):
        drivers.append("unknown asset context")
    if finding.waived:
        drivers.append("accepted-risk waiver")
    if finding.suppressed_by_vex:
        drivers.append("VEX suppression evidence")
    return drivers or ["base priority decision"]


def _business_impact_text(level: str, drivers: list[str]) -> str:
    """Business impact text function."""
    driver_limit = 8
    driver_text = "; ".join(drivers[:driver_limit])
    if len(drivers) > driver_limit:
        driver_text += f"; +{len(drivers) - driver_limit} more"
    if level == "critical":
        return (
            "Executive attention is warranted because the finding combines urgent security "
            f"signals with business routing context: {driver_text}."
        )
    if level == "high":
        return (
            "Business owners should schedule near-term remediation because the finding has "
            f"elevated security or asset-context signals: {driver_text}."
        )
    if level == "medium":
        return (
            "The finding should stay in the planned remediation queue with owner validation: "
            f"{driver_text}."
        )
    if level == "governance":
        return (
            "The finding is governed by accepted, suppressed, or fixed evidence and remains "
            f"visible for audit review: {driver_text}."
        )
    return (
        "Business impact is currently limited by available signals, but context should be "
        f"monitored for change: {driver_text}."
    )


def _visibility_statement(finding: PrioritizedFinding) -> str:
    """Visibility statement function."""
    state = finding.priority_state or finding.priority_label
    if state == "Fixed":
        return (
            "Fixed evidence remains visible for audit until follow-up scans confirm the "
            "occurrence no longer appears."
        )
    if state == "Suppressed" or finding.suppressed_by_vex:
        return (
            "Suppressed evidence remains visible when included and must be reopened if VEX or "
            "asset context changes."
        )
    if state == "Accepted" or finding.waived:
        return (
            "Accepted risk remains visible in reports until the waiver is reviewed, renewed, "
            "or converted back to remediation work."
        )
    return "Open remediation work remains visible until validation evidence supports closure."


def _decision_statement(
    finding: PrioritizedFinding,
    *,
    recommendation: DecisionRecommendation,
    sla: SlaTarget,
    business_impact: BusinessImpactBlock,
) -> str:
    """Decision statement function."""
    rank_prefix = ""
    if 0 < finding.operational_rank <= 5:
        rank_prefix = f"Top finding #{finding.operational_rank}: "
    cve = finding.cve_id
    if recommendation == "patch":
        action = (
            f"patch {cve} by applying validated vendor fixes or package upgrades, then confirm "
            "the affected assets are clean."
        )
    elif recommendation == "mitigate":
        action = (
            f"mitigate {cve} with approved compensating controls while the owner confirms "
            "patch availability and affected scope."
        )
    elif recommendation == "waiver":
        action = (
            f"keep {cve} under accepted-risk governance with owner, review date, and expiry "
            "evidence visible."
        )
    elif recommendation == "review":
        action = (
            f"review {cve} with the asset owner because evidence is incomplete or context "
            "needs validation before scheduling."
        )
    else:
        action = (
            f"monitor {cve} and re-evaluate if provider, VEX, waiver, or asset context changes."
        )
    label = RECOMMENDATION_LABELS[recommendation]
    return (
        f"{rank_prefix}{label} decision: {action} SLA: {sla.label} - {sla.guidance} "
        f"Business impact: {business_impact.text}"
    )


def _has_fixed_version_evidence(finding: PrioritizedFinding) -> bool:
    """Has fixed version evidence function."""
    return any(component.fixed_versions for component in finding.remediation.components)


def _needs_review(finding: PrioritizedFinding) -> bool:
    """Needs review function."""
    return (
        finding.data_quality_confidence == "low"
        or finding.cvss_base_score is None
        or finding.epss is None
        or _asset_context_unknown(finding)
        or finding.under_investigation
    )


def _asset_environments(finding: PrioritizedFinding) -> list[str]:
    """Asset environments function."""
    if finding.provenance.asset_environments:
        return finding.provenance.asset_environments
    return sorted(
        {
            occurrence.asset_environment
            for occurrence in finding.provenance.occurrences
            if occurrence.asset_environment
        }
    )


def _asset_business_services(finding: PrioritizedFinding) -> list[str]:
    """Asset business services function."""
    if finding.provenance.asset_business_services:
        return finding.provenance.asset_business_services
    return sorted(
        {
            occurrence.asset_business_service
            for occurrence in finding.provenance.occurrences
            if occurrence.asset_business_service
        }
    )


def _asset_owners(finding: PrioritizedFinding) -> list[str]:
    """Asset owners function."""
    if finding.provenance.asset_owners:
        return finding.provenance.asset_owners
    return sorted(
        {
            occurrence.asset_owner
            for occurrence in finding.provenance.occurrences
            if occurrence.asset_owner
        }
    )


def _asset_context_unknown(finding: PrioritizedFinding) -> bool:
    """Asset context unknown function."""
    provenance = finding.provenance
    if provenance.occurrence_count == 0 and not provenance.occurrences:
        return False
    if (
        provenance.asset_ids
        or provenance.highest_asset_criticality
        or provenance.highest_asset_exposure
        or provenance.asset_environments
        or provenance.asset_owners
        or provenance.asset_business_services
        or finding.highest_asset_criticality
    ):
        return False
    return not any(
        occurrence.asset_id
        or occurrence.asset_criticality
        or occurrence.asset_exposure
        or occurrence.asset_environment
        or occurrence.asset_owner
        or occurrence.asset_business_service
        for occurrence in provenance.occurrences
    )


def _summarize_values(values: list[str], *, limit: int = 3) -> str:
    """Summarize values function."""
    if len(values) <= limit:
        return ", ".join(values)
    shown = ", ".join(values[:limit])
    return f"{shown}, +{len(values) - limit} more"


def _impact_reason_codes(drivers: list[str]) -> list[str]:
    """Impact reason codes function."""
    codes: list[str] = []
    for driver in drivers:
        cleaned = (
            driver.lower().replace(" ", "_").replace("-", "_").replace(".", "_").replace(";", "")
        )
        codes.append(f"impact.{cleaned}")
    return codes


def _unique(values: list[str]) -> list[str]:
    """Unique function."""
    seen: set[str] = set()
    unique_values: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique_values.append(value)
    return unique_values
