"""Cycle-free dashboard signal count helpers."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.decision_core.readmodels import (
    DecisionFindingView,
    decision_views_for_findings,
    finding_is_internet_facing_critical,
)
from app.models import (
    DashboardEpssBucketsPublic,
    DashboardSignalCountsPublic,
    Finding,
)


def dashboard_signal_counts(
    findings: Sequence[Finding | DecisionFindingView],
) -> DashboardSignalCountsPublic:
    """Compute dashboard signal counts without issuing extra findings queries."""
    finding_views = _decision_views(findings)
    return DashboardSignalCountsPublic(
        high_epss=sum(1 for finding in finding_views if _epss_in_range(finding, minimum=0.7)),
        internet_facing_criticals=sum(
            1 for finding in finding_views if finding_is_internet_facing_critical(finding)
        ),
        epss_buckets=DashboardEpssBucketsPublic(
            low=sum(
                1 for finding in finding_views if _epss_in_range(finding, minimum=0, maximum=0.25)
            ),
            medium=sum(
                1 for finding in finding_views if _epss_in_range(finding, minimum=0.25, maximum=0.5)
            ),
            high=sum(
                1 for finding in finding_views if _epss_in_range(finding, minimum=0.5, maximum=0.7)
            ),
            critical=sum(1 for finding in finding_views if _epss_in_range(finding, minimum=0.7)),
        ),
    )


def dashboard_signal_counts_from_counts(counts: dict[str, Any]) -> DashboardSignalCountsPublic:
    """Build dashboard signal counts from pre-aggregated repository values."""
    epss_buckets = dict(counts.get("epss_buckets") or {})
    return DashboardSignalCountsPublic(
        high_epss=int(counts.get("high_epss", 0)),
        internet_facing_criticals=int(counts.get("internet_facing_criticals", 0)),
        epss_buckets=DashboardEpssBucketsPublic(
            low=int(epss_buckets.get("low", 0)),
            medium=int(epss_buckets.get("medium", 0)),
            high=int(epss_buckets.get("high", 0)),
            critical=int(epss_buckets.get("critical", 0)),
        ),
    )


def _epss_in_range(
    finding: DecisionFindingView,
    *,
    minimum: float,
    maximum: float | None = None,
) -> bool:
    if finding.epss is None or finding.epss < minimum:
        return False
    return maximum is None or finding.epss <= maximum


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
