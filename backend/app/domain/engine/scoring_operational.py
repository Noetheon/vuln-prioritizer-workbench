"""Operational scoring rules for prioritized findings."""

from __future__ import annotations

from app.domain.engine.models import (
    FindingProvenance,
    PrioritizedFinding,
    PriorityLabel,
    PriorityPolicy,
)

OPERATIONAL_SCORE_MIN = 0
OPERATIONAL_SCORE_MAX = 100
OPERATIONAL_BASE_SCORES = {
    PriorityLabel.CRITICAL: 70,
    PriorityLabel.HIGH: 50,
    PriorityLabel.MEDIUM: 30,
    PriorityLabel.LOW: 10,
    PriorityLabel.ACCEPTED: 25,
}


def determine_priority_state(finding: PrioritizedFinding) -> PriorityLabel:
    """Return the effective priority enum including governance terminal states."""
    if finding.suppressed_by_vex:
        statuses = {status.lower() for status in finding.provenance.vex_statuses}
        if statuses and statuses <= {"fixed"}:
            return PriorityLabel.FIXED
        return PriorityLabel.SUPPRESSED
    if finding.waived and finding.waiver_status in {"active", "review_due"}:
        return PriorityLabel.ACCEPTED
    try:
        return PriorityLabel(finding.priority_label)
    except ValueError:
        return PriorityLabel.LOW


def build_operational_score(
    finding: PrioritizedFinding,
    policy: PriorityPolicy | None = None,
) -> tuple[int, list[str]]:
    """Build an explainable 0-100 operational risk score from explicit rules."""
    priority_state = determine_priority_state(finding)
    if terminal_score := _terminal_vex_operational_score(priority_state):
        return terminal_score

    active_policy = policy or PriorityPolicy()
    score, reasons = _base_priority_adjustment(priority_state)

    for points, reason in _signal_score_adjustments(finding, active_policy):
        score += points
        reasons.append(reason)

    context_score, context_reasons = _asset_context_adjustments(finding)
    score += context_score
    reasons.extend(context_reasons)

    occurrence_points, occurrence_reason = _occurrence_adjustment(finding)
    if occurrence_reason is not None:
        score += occurrence_points
        reasons.append(occurrence_reason)

    accepted_points, accepted_reason = _accepted_risk_adjustment(finding, priority_state)
    if accepted_reason is not None:
        score += accepted_points
        reasons.append(accepted_reason)

    clamped_score = clamp_operational_score(score)
    if clamped_score != score:
        reasons.append(f"clamped to {clamped_score}")
    return clamped_score, reasons


def clamp_operational_score(score: int) -> int:
    """Clamp operational score function."""
    return max(OPERATIONAL_SCORE_MIN, min(OPERATIONAL_SCORE_MAX, score))


def _terminal_vex_operational_score(
    priority_state: PriorityLabel,
) -> tuple[int, list[str]] | None:
    """Terminal vex operational score function."""
    if priority_state == PriorityLabel.FIXED:
        return OPERATIONAL_SCORE_MIN, ["fixed VEX state clamps operational score to 0"]
    if priority_state == PriorityLabel.SUPPRESSED:
        return OPERATIONAL_SCORE_MIN, ["suppressed VEX state clamps operational score to 0"]
    return None


def _base_priority_adjustment(priority_state: PriorityLabel) -> tuple[int, list[str]]:
    """Base priority adjustment function."""
    base_score = OPERATIONAL_BASE_SCORES.get(
        priority_state,
        OPERATIONAL_BASE_SCORES[PriorityLabel.LOW],
    )
    return base_score, [f"base {priority_state.value} priority: +{base_score}"]


def _signal_score_adjustments(
    finding: PrioritizedFinding,
    policy: PriorityPolicy,
) -> list[tuple[int, str]]:
    """Signal score adjustments function."""
    adjustments: list[tuple[int, str]] = []
    if finding.in_kev:
        adjustments.append((15, "CISA KEV-listed: +15"))
    if epss_adjustment := _epss_score_adjustment(finding, policy):
        adjustments.append(epss_adjustment)
    if cvss_adjustment := _cvss_score_adjustment(finding, policy):
        adjustments.append(cvss_adjustment)
    return adjustments


def _epss_score_adjustment(
    finding: PrioritizedFinding,
    policy: PriorityPolicy,
) -> tuple[int, str] | None:
    """Epss score adjustment function."""
    if (
        finding.epss is not None
        and finding.epss >= policy.critical_epss_threshold
        and finding.cvss_base_score is not None
        and finding.cvss_base_score >= policy.critical_cvss_threshold
    ):
        return 8, "critical EPSS/CVSS threshold: +8"
    if finding.epss is not None and finding.epss >= policy.high_epss_threshold:
        return 5, "high EPSS threshold: +5"
    if finding.epss is not None and finding.epss >= policy.medium_epss_threshold:
        return 2, "medium EPSS threshold: +2"
    return None


def _cvss_score_adjustment(
    finding: PrioritizedFinding,
    policy: PriorityPolicy,
) -> tuple[int, str] | None:
    """Cvss score adjustment function."""
    if (
        finding.cvss_base_score is not None
        and finding.cvss_base_score >= policy.high_cvss_threshold
    ):
        return 5, "high CVSS threshold: +5"
    if (
        finding.cvss_base_score is not None
        and finding.cvss_base_score >= policy.medium_cvss_threshold
    ):
        return 2, "medium CVSS threshold: +2"
    return None


def _asset_context_adjustments(finding: PrioritizedFinding) -> tuple[int, list[str]]:
    """Asset context adjustments function."""
    score = 0
    reasons: list[str] = []
    if _is_internet_facing(finding.provenance):
        score += 8
        reasons.append("internet-facing asset context: +8")
    if _is_production(finding.provenance):
        score += 5
        reasons.append("production asset context: +5")

    criticality_points = _asset_criticality_points(finding)
    if criticality_points:
        score += criticality_points
        reasons.append(
            f"{finding.highest_asset_criticality} asset criticality: +{criticality_points}"
        )

    reasons.extend(_routing_context_reasons(finding))
    return score, reasons


def _asset_criticality_points(finding: PrioritizedFinding) -> int:
    """Asset criticality points function."""
    return {
        "critical": 7,
        "high": 4,
        "medium": 2,
    }.get((finding.highest_asset_criticality or "").lower(), 0)


def _routing_context_reasons(finding: PrioritizedFinding) -> list[str]:
    """Routing context reasons function."""
    reasons = [
        f"business service {service} routing context: +0"
        for service in _asset_business_services(finding)[:3]
    ]
    reasons.extend(f"owner {owner} routing context: +0" for owner in _asset_owners(finding)[:3])
    if _asset_context_unknown(finding):
        reasons.append("asset context unknown: +0, not treated as safe")
    return reasons


def _occurrence_adjustment(finding: PrioritizedFinding) -> tuple[int, str | None]:
    """Occurrence adjustment function."""
    extra_occurrences = max(finding.provenance.active_occurrence_count - 1, 0)
    if not extra_occurrences:
        return 0, None
    occurrence_points = min(extra_occurrences, 5)
    return (
        occurrence_points,
        f"{finding.provenance.active_occurrence_count} active occurrences: +{occurrence_points}",
    )


def _accepted_risk_adjustment(
    finding: PrioritizedFinding,
    priority_state: PriorityLabel,
) -> tuple[int, str | None]:
    """Accepted risk adjustment function."""
    if priority_state != PriorityLabel.ACCEPTED:
        return 0, None
    if finding.waiver_status == "review_due":
        return -5, "accepted risk review due: -5"
    return -20, "active accepted-risk waiver: -20"


def _is_internet_facing(provenance: FindingProvenance) -> bool:
    """Is internet facing function."""
    highest_exposure = provenance.highest_asset_exposure
    if highest_exposure and highest_exposure.lower() == "internet-facing":
        return True
    return any(
        occurrence.asset_exposure and occurrence.asset_exposure.lower() == "internet-facing"
        for occurrence in provenance.occurrences
    )


def _is_production(provenance: FindingProvenance) -> bool:
    """Is production function."""
    if any(
        environment.lower() in {"prod", "production"}
        for environment in provenance.asset_environments
    ):
        return True
    return any(
        occurrence.asset_environment
        and occurrence.asset_environment.lower() in {"prod", "production"}
        for occurrence in provenance.occurrences
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
