"""Operational rank and context-reason helpers for prioritization."""

from __future__ import annotations

from datetime import UTC, date, datetime

from vuln_prioritizer.explanations import build_priority_explanation
from vuln_prioritizer.models import PrioritizedFinding, PriorityPolicy
from vuln_prioritizer.scoring import build_operational_score, determine_priority_state
from vuln_prioritizer.services.decision_guidance import DecisionGuidanceService
from vuln_prioritizer.services.prioritization_sorting import descending_numeric
from vuln_prioritizer.utils import iso_utc_now


def assign_operational_ranks(
    findings: list[PrioritizedFinding],
    policy: PriorityPolicy,
) -> list[PrioritizedFinding]:
    """Attach deterministic operational ranks, reasons, and decision guidance."""
    scored_findings = [_with_operational_score(finding, policy) for finding in findings]
    ordered = sorted(scored_findings, key=_operational_sort_key)
    rank_by_cve = {finding.cve_id: index for index, finding in enumerate(ordered, start=1)}
    decision_guidance_service = DecisionGuidanceService()
    ranked_findings: list[PrioritizedFinding] = []
    for finding in scored_findings:
        ranked = finding.model_copy(
            update={
                "operational_rank": rank_by_cve[finding.cve_id],
                "context_rank_reasons": _context_rank_reasons(finding),
            }
        )
        ranked_findings.append(
            ranked.model_copy(
                update={
                    "decision_guidance": decision_guidance_service.build(ranked),
                }
            )
        )
    return ranked_findings


def _with_operational_score(
    finding: PrioritizedFinding,
    policy: PriorityPolicy,
) -> PrioritizedFinding:
    score, reasons = build_operational_score(finding, policy)
    scored = finding.model_copy(
        update={
            "priority_state": determine_priority_state(finding).value,
            "operational_score": score,
            "operational_score_reasons": reasons,
        }
    )
    return scored.model_copy(update={"explanation": build_priority_explanation(scored, policy)})


def _operational_sort_key(finding: PrioritizedFinding) -> tuple:
    return (
        finding.priority_rank,
        -finding.operational_score,
        _waiver_work_queue_bucket(finding),
        _kev_due_sort_key(finding),
        0 if _is_internet_facing(finding) else 1,
        0 if _is_production(finding) else 1,
        _asset_criticality_sort_key(finding.highest_asset_criticality),
        -finding.provenance.active_occurrence_count,
        _attack_relevance_sort_key(finding.attack_relevance),
        descending_numeric(finding.epss),
        descending_numeric(finding.cvss_base_score),
        finding.cve_id,
    )


def _waiver_work_queue_bucket(finding: PrioritizedFinding) -> int:
    if finding.waiver_status == "review_due":
        return 1
    if finding.waived:
        return 2
    return 0


def _kev_due_sort_key(finding: PrioritizedFinding) -> tuple[int, int]:
    if not finding.in_kev or finding.provider_evidence is None:
        return 2, 99999999
    due_date = _parse_date(finding.provider_evidence.kev.due_date)
    if due_date is None:
        return 1, 99999999
    today = _parse_date(iso_utc_now()) or datetime.now(UTC).date()
    return (0 if due_date <= today else 1), due_date.toordinal()


def _parse_date(value: str | None) -> date | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return None


def _is_internet_facing(finding: PrioritizedFinding) -> bool:
    highest_exposure = finding.provenance.highest_asset_exposure
    if highest_exposure and highest_exposure.lower() == "internet-facing":
        return True
    return any(
        occurrence.asset_exposure and occurrence.asset_exposure.lower() == "internet-facing"
        for occurrence in finding.provenance.occurrences
    )


def _is_production(finding: PrioritizedFinding) -> bool:
    if any(
        environment.lower() in {"prod", "production"}
        for environment in finding.provenance.asset_environments
    ):
        return True
    return any(
        occurrence.asset_environment
        and occurrence.asset_environment.lower() in {"prod", "production"}
        for occurrence in finding.provenance.occurrences
    )


def _asset_criticality_sort_key(value: str | None) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get((value or "").lower(), 4)


def _attack_relevance_sort_key(value: str) -> int:
    return {"High": 0, "Medium": 1, "Low": 2, "Unmapped": 3}.get(value, 4)


def _context_rank_reasons(finding: PrioritizedFinding) -> list[str]:
    reasons: list[str] = []
    if finding.waiver_status == "expired":
        reasons.append("expired waiver requires reassessment")
    elif finding.waiver_status == "review_due":
        reasons.append("waiver review due")
    elif finding.waived:
        reasons.append("active waiver lowers work-queue urgency")
    if finding.in_kev:
        due_date = (
            None if finding.provider_evidence is None else finding.provider_evidence.kev.due_date
        )
        if due_date:
            reasons.append(f"KEV due date {due_date}")
        else:
            reasons.append("KEV-listed")
    if _is_internet_facing(finding):
        reasons.append("internet-facing exposure")
    if _is_production(finding):
        reasons.append("production environment")
    if finding.highest_asset_criticality:
        reasons.append(f"{finding.highest_asset_criticality} asset criticality")
    for service in _asset_business_services(finding)[:3]:
        reasons.append(f"business service {service}")
    for owner in _asset_owners(finding)[:3]:
        reasons.append(f"owner {owner}")
    if _asset_context_unknown(finding):
        reasons.append("asset context unknown; validate before scheduling")
    if finding.provenance.active_occurrence_count > 1:
        reasons.append(f"{finding.provenance.active_occurrence_count} active occurrences")
    if finding.attack_relevance in {"High", "Medium"}:
        reasons.append(f"ATT&CK {finding.attack_relevance}")
    return reasons


def _asset_business_services(finding: PrioritizedFinding) -> list[str]:
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
