"""Decision API helpers for persisted Workbench findings."""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Sequence
from typing import Any

from pydantic import ValidationError

from app.models import (
    AnalysisRun,
    Finding,
    FindingExplanationPublic,
    FindingStatus,
    ProjectCvssOnlyComparisonPublic,
    ProjectDecisionSummaryPublic,
)
from vuln_prioritizer.models import PrioritizedFinding
from vuln_prioritizer.services.baseline_comparison import (
    build_cvss_baseline_comparison_payload,
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
    explanation_json = _dict_value(finding.explanation_json)
    decision_explanation = _dict_or_none(explanation_json.get("explanation"))
    if decision_explanation is None:
        raise DecisionDataUnavailableError("Finding explanation is not available.")

    return FindingExplanationPublic(
        finding_id=finding.id,
        project_id=finding.project_id,
        cve_id=finding.cve_id,
        priority=finding.priority,
        priority_rank=finding.priority_rank,
        priority_state=_string_or_none(explanation_json.get("priority_state"))
        or _string_or_none(
            _dict_value(_dict_value(finding.evidence_json).get("analysis")).get("priority_state")
        )
        or _priority_label(str(finding.priority)),
        risk_score=finding.risk_score,
        operational_rank=finding.operational_rank,
        rationale=finding.rationale,
        recommended_action=finding.recommended_action,
        decision_guidance=_dict_or_none(explanation_json.get("decision_guidance")),
        decision_explanation=decision_explanation,
        provider_evidence=_dict_or_none(explanation_json.get("provider_evidence")),
        data_quality_flags=_data_quality_flags(finding, explanation_json),
        data_quality_confidence=_string_or_none(explanation_json.get("data_quality_confidence"))
        or _string_or_none(_dict_value(finding.data_quality_json).get("confidence"))
        or "high",
        explanation=explanation_json,
    )


def build_project_summary_payload(
    *,
    project_id: uuid.UUID,
    findings: Sequence[Finding],
    runs: Sequence[AnalysisRun],
) -> ProjectDecisionSummaryPublic:
    """Build a dashboard summary from persisted findings and latest run metadata."""
    latest_run = runs[0] if runs else None
    latest_run_summary: dict[str, Any] = {}
    return ProjectDecisionSummaryPublic(
        project_id=project_id,
        finding_count=len(findings),
        open_finding_count=sum(
            1 for finding in findings if str(finding.status) in OPEN_WORK_STATUSES
        ),
        counts_by_priority=_counts_by_priority(findings),
        counts_by_status=_counts_by_status(findings),
        kev_hits=sum(1 for finding in findings if finding.in_kev),
        epss_hits=sum(1 for finding in findings if finding.epss is not None),
        cvss_known_count=sum(1 for finding in findings if finding.cvss_base_score is not None),
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
    latest_run_summary: dict[str, Any] = {}
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
    explanation_json = _dict_value(finding.explanation_json)
    if explanation_json.get("cve_id") == finding.cve_id:
        try:
            return PrioritizedFinding.model_validate(explanation_json)
        except (TypeError, ValueError, ValidationError):
            pass

    return PrioritizedFinding(
        cve_id=finding.cve_id,
        description=getattr(finding.vulnerability, "description", None),
        cvss_base_score=finding.cvss_base_score,
        epss=finding.epss,
        in_kev=finding.in_kev,
        attack_mapped=finding.attack_mapped,
        suppressed_by_vex=finding.suppressed_by_vex,
        under_investigation=finding.under_investigation,
        waived=finding.waived,
        priority_label=_priority_label(str(finding.priority)),
        priority_rank=finding.priority_rank,
        priority_state=_priority_label(str(finding.priority)),
        operational_rank=finding.operational_rank,
        operational_score=int(finding.risk_score or 0),
        rationale=finding.rationale or "Stored Workbench finding without raw rationale payload.",
        recommended_action=finding.recommended_action or "Review the finding with the asset owner.",
    )


def _counts_by_priority(findings: Sequence[Finding]) -> dict[str, int]:
    counts = Counter(_priority_label(str(finding.priority)) for finding in findings)
    return {priority: counts.get(priority, 0) for priority in PRIORITY_LABELS}


def _counts_by_status(findings: Sequence[Finding]) -> dict[str, int]:
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


def _data_quality_flags(
    finding: Finding,
    explanation_json: dict[str, Any],
) -> list[dict[str, Any]]:
    data_quality_json = _dict_value(finding.data_quality_json)
    return _flag_items(explanation_json.get("data_quality_flags")) + _flag_items(
        data_quality_json.get("flags")
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
