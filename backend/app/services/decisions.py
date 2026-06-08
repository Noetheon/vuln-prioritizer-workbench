"""Decision API helpers for persisted Workbench findings."""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Sequence
from typing import Any

from pydantic import ValidationError

from app.decision_core.contracts import FindingDecisionEvidenceV2
from app.decision_core.readmodels import (
    DecisionFindingView,
    decision_run_view,
    decision_views_for_findings,
    latest_finding_decision_view,
)
from app.domain.engine.models import PrioritizedFinding
from app.domain.engine.services.baseline_comparison import (
    build_cvss_baseline_comparison_payload,
)
from app.models import (
    AnalysisRun,
    Finding,
    FindingExplanationPublic,
    FindingStatus,
    ProjectCvssOnlyComparisonPublic,
    ProjectDecisionSummaryPublic,
)

PRIORITY_LABELS = ("Critical", "High", "Medium", "Low")
STATUS_LABELS = tuple(status.value for status in FindingStatus)
OPEN_WORK_STATUSES = {
    FindingStatus.OPEN.value,
    FindingStatus.IN_REVIEW.value,
    FindingStatus.REMEDIATING.value,
}


class DecisionDataUnavailableError(RuntimeError):
    """Raised when a persisted finding does not contain decision explanation data."""


def build_finding_explanation_payload(finding: Finding) -> FindingExplanationPublic:
    """Build the public explanation payload for one stored finding."""
    view = latest_finding_decision_view(finding)
    evidence = _required_finding_evidence(view)
    explanation_json = evidence.priority_evidence.raw
    decision_explanation: dict[str, Any] | None = (
        evidence.priority_evidence.explanation.to_jsonable()
    )
    if not decision_explanation:
        decision_explanation = _dict_or_none(explanation_json.get("explanation"))
    if decision_explanation is None:
        raise DecisionDataUnavailableError("Finding explanation is not available.")

    return FindingExplanationPublic(
        finding_id=finding.id,
        project_id=finding.project_id,
        cve_id=view.cve_id,
        priority=view.priority,
        priority_rank=view.priority_rank,
        priority_state=evidence.priority_evidence.priority_state
        or _string_or_none(explanation_json.get("priority_state"))
        or view.priority_label,
        risk_score=view.risk_score,
        operational_rank=view.operational_rank,
        rationale=view.rationale,
        recommended_action=view.recommended_action,
        decision_guidance=evidence.remediation.raw
        or _dict_or_none(explanation_json.get("decision_guidance")),
        decision_explanation=decision_explanation,
        provider_evidence=evidence.provider.provider_evidence or None,
        data_quality_flags=_data_quality_flags(evidence),
        data_quality_confidence=evidence.priority_evidence.data_quality_confidence or "high",
        explanation=explanation_json,
    )


def build_project_summary_payload(
    *,
    project_id: uuid.UUID,
    findings: Sequence[Finding | DecisionFindingView],
    runs: Sequence[AnalysisRun],
) -> ProjectDecisionSummaryPublic:
    """Build a dashboard summary from persisted findings and latest run metadata."""
    finding_views = _decision_views(findings)
    latest_run = runs[0] if runs else None
    latest_run_summary = _latest_run_summary(latest_run)
    return ProjectDecisionSummaryPublic(
        project_id=project_id,
        finding_count=len(finding_views),
        open_finding_count=sum(
            1 for finding in finding_views if str(finding.status) in OPEN_WORK_STATUSES
        ),
        counts_by_priority=_counts_by_priority(finding_views),
        counts_by_status=_counts_by_status(finding_views),
        kev_hits=sum(1 for finding in finding_views if finding.in_kev),
        epss_hits=sum(1 for finding in finding_views if finding.epss is not None),
        cvss_known_count=sum(1 for finding in finding_views if finding.cvss_base_score is not None),
        provider_degraded=bool(latest_run_summary.get("provider_degraded", False)),
        latest_run_id=latest_run.id if latest_run is not None else None,
        latest_run_status=latest_run.status if latest_run is not None else None,
        latest_run_summary=latest_run_summary,
    )


def build_project_summary_payload_from_counts(
    *,
    project_id: uuid.UUID,
    summary_counts: dict[str, Any],
    latest_run: AnalysisRun | None,
) -> ProjectDecisionSummaryPublic:
    """Build a dashboard summary from pre-aggregated database counts."""
    latest_run_summary = _latest_run_summary(latest_run)
    return ProjectDecisionSummaryPublic(
        project_id=project_id,
        finding_count=int(summary_counts.get("finding_count", 0)),
        open_finding_count=int(summary_counts.get("open_finding_count", 0)),
        counts_by_priority=_ordered_priority_counts(summary_counts.get("counts_by_priority")),
        counts_by_status=_ordered_status_counts(summary_counts.get("counts_by_status")),
        kev_hits=int(summary_counts.get("kev_hits", 0)),
        epss_hits=int(summary_counts.get("epss_hits", 0)),
        cvss_known_count=int(summary_counts.get("cvss_known_count", 0)),
        provider_degraded=bool(latest_run_summary.get("provider_degraded", False)),
        latest_run_id=latest_run.id if latest_run is not None else None,
        latest_run_status=latest_run.status if latest_run is not None else None,
        latest_run_summary=latest_run_summary,
    )


def _latest_run_summary(latest_run: AnalysisRun | None) -> dict[str, Any]:
    if latest_run is None:
        return {}
    evidence = decision_run_view(latest_run).evidence
    if evidence is None:
        return {}
    return {
        "provider_degraded": evidence.provider.provider_degraded,
        "counts": evidence.counts.to_jsonable(),
        "warnings": list(evidence.warnings),
    }


def build_cvss_only_comparison_payload(
    *,
    project_id: uuid.UUID,
    findings: Sequence[Finding],
    top_change_limit: int,
    include_comparisons: bool = True,
) -> ProjectCvssOnlyComparisonPublic:
    """Build a typed CVSS-only comparison response for Workbench API clients."""
    payload = build_cvss_baseline_comparison_payload(
        [prioritized_finding_from_workbench(finding) for finding in findings],
        project_id=str(project_id),
        top_change_limit=top_change_limit,
        include_comparisons=include_comparisons,
    )
    return ProjectCvssOnlyComparisonPublic.model_validate(payload)


def prioritized_finding_from_workbench(finding: Finding) -> PrioritizedFinding:
    """Convert a stored Workbench finding back to the core decision model."""
    view = latest_finding_decision_view(finding)
    evidence = view.evidence
    explanation_json = evidence.priority_evidence.raw if evidence is not None else {}
    if explanation_json.get("cve_id") == view.cve_id:
        try:
            return PrioritizedFinding.model_validate(explanation_json)
        except (TypeError, ValueError, ValidationError):
            pass

    return PrioritizedFinding(
        cve_id=view.cve_id,
        description=getattr(finding.vulnerability, "description", None),
        cvss_base_score=view.cvss_base_score,
        epss=view.epss,
        in_kev=view.in_kev,
        attack_mapped=view.attack_mapped,
        suppressed_by_vex=view.suppressed_by_vex,
        under_investigation=view.under_investigation,
        waived=view.waived,
        priority_label=view.priority_label,
        priority_rank=view.priority_rank,
        priority_state=view.priority_label,
        operational_rank=view.operational_rank,
        operational_score=int(view.risk_score or 0),
        rationale=view.rationale or "Stored Workbench finding without raw rationale payload.",
        recommended_action=view.recommended_action or "Review the finding with the asset owner.",
    )


def _counts_by_priority(findings: Sequence[DecisionFindingView]) -> dict[str, int]:
    counts = Counter(finding.priority_label for finding in findings)
    return {priority: counts.get(priority, 0) for priority in PRIORITY_LABELS}


def _counts_by_status(findings: Sequence[DecisionFindingView]) -> dict[str, int]:
    counts = Counter(str(finding.status) for finding in findings)
    return {status: counts.get(status, 0) for status in STATUS_LABELS}


def _ordered_priority_counts(value: Any) -> dict[str, int]:
    counts = Counter(
        {
            _priority_label(str(priority)): int(count)
            for priority, count in _dict_value(value).items()
        }
    )
    return {priority: counts.get(priority, 0) for priority in PRIORITY_LABELS}


def _ordered_status_counts(value: Any) -> dict[str, int]:
    counts = Counter(
        {
            str(status).split(".", maxsplit=1)[-1].strip().lower(): int(count)
            for status, count in _dict_value(value).items()
        }
    )
    return {status: int(counts.get(status, 0)) for status in STATUS_LABELS}


def _data_quality_flags(evidence: FindingDecisionEvidenceV2) -> list[dict[str, Any]]:
    flags = [
        flag.to_jsonable() for flag in evidence.priority_evidence.data_quality_flags
    ] + _flag_items(evidence.governance.data_quality.get("flags"))
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[tuple[str, str], ...]] = set()
    for flag in flags:
        key = tuple(sorted((str(name), str(value)) for name, value in flag.items()))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(flag)
    return deduped


def _required_finding_evidence(view: DecisionFindingView) -> FindingDecisionEvidenceV2:
    evidence = view.evidence
    if evidence is None:
        raise DecisionDataUnavailableError("Finding explanation is not available.")
    return evidence


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


def _flag_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _priority_label(value: str) -> str:
    normalized = value.split(".", maxsplit=1)[-1].strip().lower()
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }.get(normalized, "Low")


def _dict_value(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _dict_or_none(value: Any) -> dict[str, Any] | None:
    return dict(value) if isinstance(value, dict) else None


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None
