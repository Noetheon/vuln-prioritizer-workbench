"""Dashboard risk-reduction opportunity helpers."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from typing import Any

from app.decision_core.readmodels import (
    DecisionFindingView,
    decision_views_for_findings,
)
from app.models import (
    AnalysisRun,
    Finding,
    ProjectRiskReductionPublic,
    ResidualRiskStepPublic,
    RiskContributionPublic,
    RiskIndexHistoryPointPublic,
    RiskReductionOpportunityPublic,
)
from app.models.enums import AnalysisRunStatus, FindingStatus

ACTIONABLE_STATUSES = {
    FindingStatus.OPEN.value,
    FindingStatus.IN_REVIEW.value,
    FindingStatus.REMEDIATING.value,
}

RISK_INDEX_HISTORY_LIMIT = 12


def build_project_risk_reduction_payload(
    findings: Sequence[Finding | DecisionFindingView],
    *,
    runs: Sequence[AnalysisRun] = (),
    opportunity_limit: int = 5,
) -> ProjectRiskReductionPublic:
    """Build dashboard risk-reduction opportunities from evidence-backed findings."""
    finding_views = _decision_views(findings)
    actionable = [finding for finding in finding_views if _is_actionable(finding)]
    governance_debt = [finding for finding in finding_views if _is_governance_debt(finding)]
    current_risk = _round_score(sum(_risk_score(finding) for finding in actionable))
    all_opportunities = _risk_reduction_opportunities(
        actionable,
        current_risk=current_risk,
    )
    top_opportunities = all_opportunities[: max(1, min(opportunity_limit, 20))]
    return ProjectRiskReductionPublic(
        current_actionable_risk=current_risk,
        actionable_finding_count=len(actionable),
        largest_driver=_largest_driver(actionable),
        top_opportunities=top_opportunities,
        residual_steps=_residual_steps(current_risk, top_opportunities),
        history=risk_index_history(runs),
        governance_debt_risk=_round_score(sum(_risk_score(finding) for finding in governance_debt)),
    )


def risk_index_history(
    runs: Sequence[AnalysisRun],
    *,
    limit: int = RISK_INDEX_HISTORY_LIMIT,
) -> list[RiskIndexHistoryPointPublic]:
    """Return persisted run risk indexes ordered oldest to newest."""
    points = [
        RiskIndexHistoryPointPublic(
            run_id=run.id,
            finished_at=run.finished_at,
            risk_index=_round_score(float(run.risk_index)),
        )
        for run in runs
        if run.risk_index is not None
        and run.finished_at is not None
        and run.status == AnalysisRunStatus.SUCCEEDED
    ]
    points.sort(key=lambda point: point.finished_at)
    return points[-max(1, limit) :]


def project_risk_index(findings: Sequence[Finding | DecisionFindingView]) -> float:
    """Average actionable risk score (0-100) persisted as one run's risk index."""
    finding_views = _decision_views(findings)
    actionable = [finding for finding in finding_views if _is_actionable(finding)]
    if not actionable:
        return 0.0
    average = sum(_risk_score(finding) for finding in actionable) / len(actionable)
    return _round_score(min(average, 100.0))


def _decision_views(
    findings: Sequence[Finding | DecisionFindingView],
) -> list[DecisionFindingView]:
    if not findings:
        return []
    first = findings[0]
    if isinstance(first, DecisionFindingView):
        return [finding for finding in findings if isinstance(finding, DecisionFindingView)]
    return decision_views_for_findings(
        [finding for finding in findings if isinstance(finding, Finding)]
    )


def _is_actionable(finding: DecisionFindingView) -> bool:
    status = str(finding.status)
    return (
        status in ACTIONABLE_STATUSES
        and not bool(finding.suppressed_by_vex)
        and not bool(finding.waived)
    )


def _is_governance_debt(finding: DecisionFindingView) -> bool:
    status = str(finding.status)
    return (
        (status == FindingStatus.ACCEPTED.value or bool(finding.waived))
        and status not in {FindingStatus.FIXED.value, FindingStatus.SUPPRESSED.value}
        and not bool(finding.suppressed_by_vex)
    )


def _risk_reduction_opportunities(
    findings: Sequence[DecisionFindingView],
    *,
    current_risk: float,
) -> list[RiskReductionOpportunityPublic]:
    grouped: dict[tuple[str, str, str], list[DecisionFindingView]] = {}
    for finding in findings:
        grouped.setdefault(_opportunity_key(finding), []).append(finding)

    opportunities = [
        _opportunity_for_findings(
            key=key,
            findings=items,
            current_risk=current_risk,
        )
        for key, items in grouped.items()
    ]
    opportunities.sort(
        key=lambda item: (
            -item.expected_reduction,
            0 if item.in_kev else 1,
            -float(item.max_epss or 0.0),
            -float(item.max_cvss or 0.0),
            item.cve_id.casefold(),
            (item.component or "").casefold(),
            item.recommended_action.casefold(),
        )
    )
    return opportunities


def _opportunity_for_findings(
    *,
    key: tuple[str, str, str],
    findings: Sequence[DecisionFindingView],
    current_risk: float,
) -> RiskReductionOpportunityPublic:
    cve_id, component_key, action_key = key
    component = _first_present(_component_label(finding) for finding in findings)
    action = _first_present(finding.recommended_action for finding in findings)
    recommended_action = action or "Review with asset owner and record remediation path."
    expected_reduction = _round_score(sum(_risk_score(finding) for finding in findings))
    label = _opportunity_label(cve_id, component, recommended_action)
    return RiskReductionOpportunityPublic(
        id="|".join((cve_id, component_key, action_key)),
        label=label,
        cve_id=cve_id,
        component=component,
        recommended_action=recommended_action,
        expected_reduction=expected_reduction,
        residual_after=_round_score(max(current_risk - expected_reduction, 0.0)),
        finding_count=len(findings),
        affected_assets=_unique_labels(_asset_label(finding) for finding in findings),
        business_services=_unique_labels(_service_label(finding) for finding in findings),
        owners=_unique_labels(_owner_label(finding) for finding in findings),
        max_epss=_max_optional(finding.epss for finding in findings),
        max_cvss=_max_optional(finding.cvss_base_score for finding in findings),
        in_kev=any(bool(finding.in_kev) for finding in findings),
        search_query=cve_id or component or recommended_action,
    )


def _opportunity_key(finding: DecisionFindingView) -> tuple[str, str, str]:
    return (
        finding.cve_id,
        _normalized_component_key(finding),
        _normalized_action_key(finding.recommended_action),
    )


def _largest_driver(
    findings: Sequence[DecisionFindingView],
) -> RiskContributionPublic | None:
    driver_candidates: list[RiskContributionPublic] = []
    for dimension, labels in (
        ("service", [_service_label(finding) for finding in findings]),
        ("asset", [_asset_label(finding) for finding in findings]),
        ("owner", [_owner_label(finding) for finding in findings]),
        ("cve", [finding.cve_id for finding in findings]),
    ):
        grouped: dict[str, list[DecisionFindingView]] = {}
        for finding, label in zip(findings, labels, strict=False):
            grouped.setdefault(label or "Unassigned", []).append(finding)
        driver_candidates.extend(
            _contribution_for_findings(
                dimension=dimension,
                label=label,
                findings=items,
            )
            for label, items in grouped.items()
        )

    if not driver_candidates:
        return None
    return sorted(
        driver_candidates,
        key=lambda item: (
            -item.risk_score_total,
            -item.critical_count,
            -item.high_count,
            -item.kev_count,
            _dimension_rank(item.dimension),
            item.label.casefold(),
        ),
    )[0]


def _contribution_for_findings(
    *,
    dimension: str,
    label: str,
    findings: Sequence[DecisionFindingView],
) -> RiskContributionPublic:
    priority_counts = Counter(_priority_label(finding) for finding in findings)
    return RiskContributionPublic(
        dimension=dimension,
        label=label,
        risk_score_total=_round_score(sum(_risk_score(finding) for finding in findings)),
        finding_count=len(findings),
        critical_count=priority_counts.get("Critical", 0),
        high_count=priority_counts.get("High", 0),
        kev_count=sum(1 for finding in findings if finding.in_kev),
    )


def _residual_steps(
    current_risk: float,
    opportunities: Sequence[RiskReductionOpportunityPublic],
) -> list[ResidualRiskStepPublic]:
    top_one_reduction = _reduction_for_first(opportunities, 1)
    top_three_reduction = _reduction_for_first(opportunities, 3)
    displayed_reduction = _reduction_for_first(opportunities, len(opportunities))
    return [
        ResidualRiskStepPublic(label="Current", risk_score=current_risk, reduction=0.0),
        ResidualRiskStepPublic(
            label="After top 1",
            risk_score=_round_score(max(current_risk - top_one_reduction, 0.0)),
            reduction=_round_score(top_one_reduction),
        ),
        ResidualRiskStepPublic(
            label="After top 3",
            risk_score=_round_score(max(current_risk - top_three_reduction, 0.0)),
            reduction=_round_score(top_three_reduction),
        ),
        ResidualRiskStepPublic(
            label="Remaining",
            risk_score=_round_score(max(current_risk - displayed_reduction, 0.0)),
            reduction=_round_score(displayed_reduction),
        ),
    ]


def _reduction_for_first(
    opportunities: Sequence[RiskReductionOpportunityPublic],
    count: int,
) -> float:
    return sum(opportunity.expected_reduction for opportunity in opportunities[:count])


def _normalized_component_key(finding: DecisionFindingView) -> str:
    component_label = _component_label(finding)
    if component_label:
        return _slug(component_label)
    component = getattr(finding.finding, "component", None)
    purl = getattr(component, "purl", None)
    if purl:
        return _slug(str(purl))
    return _slug("unknown-component")


def _normalized_action_key(value: str | None) -> str:
    return _slug(value or "review-and-remediate")


def _opportunity_label(cve_id: str, component: str | None, action: str) -> str:
    if component:
        return f"{cve_id} on {component}"
    compact_action = action.split(".", maxsplit=1)[0].strip()
    return f"{cve_id}: {compact_action[:64]}"


def _component_label(finding: DecisionFindingView) -> str | None:
    component = getattr(finding.finding, "component", None)
    if component is None:
        return None
    name = getattr(component, "name", None)
    if not name:
        return None
    version = getattr(component, "version", None)
    return f"{name} {version}" if version else str(name)


def _asset_label(finding: DecisionFindingView) -> str | None:
    asset = getattr(finding.finding, "asset", None)
    if asset is None:
        return None
    return _clean_label(
        getattr(asset, "name", None)
        or getattr(asset, "asset_key", None)
        or getattr(asset, "target_ref", None)
    )


def _service_label(finding: DecisionFindingView) -> str | None:
    asset = getattr(finding.finding, "asset", None)
    if asset is None:
        return None
    return _clean_label(getattr(asset, "business_service", None))


def _owner_label(finding: DecisionFindingView) -> str | None:
    asset = getattr(finding.finding, "asset", None)
    if asset is None:
        return None
    return _clean_label(getattr(asset, "owner", None))


def _priority_label(finding: DecisionFindingView) -> str:
    raw = getattr(finding, "priority_label", None)
    if raw:
        return str(raw)
    priority = str(getattr(finding, "priority", "Low")).split(".", maxsplit=1)[-1].lower()
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }.get(priority, "Low")


def _risk_score(finding: DecisionFindingView) -> float:
    value = finding.risk_score
    if value is None:
        return 0.0
    return max(float(value), 0.0)


def _round_score(value: float) -> float:
    return round(float(value), 3)


def _dimension_rank(value: str) -> int:
    return {"service": 0, "asset": 1, "owner": 2, "cve": 3}.get(value, 99)


def _unique_labels(values: Sequence[str | None] | Any) -> list[str]:
    return sorted({value for value in values if value})


def _first_present(values: Sequence[str | None] | Any) -> str | None:
    for value in values:
        cleaned = _clean_label(value)
        if cleaned:
            return cleaned
    return None


def _max_optional(values: Sequence[float | None] | Any) -> float | None:
    numbers = [float(value) for value in values if value is not None]
    return _round_score(max(numbers)) if numbers else None


def _clean_label(value: object | None) -> str | None:
    text = str(value or "").strip()
    return text or None


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    return slug[:96] or "unknown"
