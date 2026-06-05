"""Project dashboard aggregate helpers."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from app.models import (
    AnalysisRun,
    AnalysisRunsPublic,
    DashboardEpssBucketsPublic,
    DashboardSignalCountsPublic,
    Finding,
    FindingPublic,
    FindingsPublic,
    ProjectDashboardFindingsPublic,
    ProjectDashboardPublic,
    Waiver,
)
from app.models.base import get_datetime_utc
from app.repositories.findings import FindingRepository
from app.repositories.runs import RunRepository
from app.repositories.waivers import WaiverRepository
from app.services.decision_projection import (
    DecisionFindingView,
    decision_views_for_findings,
    finding_is_internet_facing_critical,
    latest_finding_decision_view,
)
from app.services.decisions import (
    build_project_summary_payload,
)
from app.services.governance import (
    build_project_governance_rollups_payload,
)
from app.services.run_workflow_projection import analysis_run_public


def build_project_dashboard_payload(
    *,
    project_id: uuid.UUID,
    findings: Sequence[Finding],
    runs: Sequence[AnalysisRun],
    waivers: Sequence[Waiver],
    waiver_repository: WaiverRepository,
    remediation_limit: int = 5,
    rollup_limit: int = 5,
) -> ProjectDashboardPublic:
    """Build the one-call project dashboard aggregate from loaded domain rows."""
    bounded_remediation_limit = max(1, min(remediation_limit, 50))
    finding_views = decision_views_for_findings(list(findings))
    remediation_findings = list(finding_views[:bounded_remediation_limit])
    return ProjectDashboardPublic(
        project_id=project_id,
        generated_at=get_datetime_utc(),
        summary=build_project_summary_payload(
            project_id=project_id,
            findings=finding_views,
            runs=runs,
        ),
        governance=build_project_governance_rollups_payload(
            project_id=project_id,
            findings=finding_views,
            waivers=waivers,
            waiver_repository=waiver_repository,
            limit=rollup_limit,
        ),
        runs=AnalysisRunsPublic(
            data=[analysis_run_public(run) for run in runs],
            count=len(runs),
        ),
        findings=ProjectDashboardFindingsPublic(
            remediation_queue=FindingsPublic(
                data=[finding_public(finding) for finding in remediation_findings],
                count=len(finding_views),
            ),
            signal_counts=dashboard_signal_counts(finding_views),
        ),
    )


def build_project_dashboard_payload_from_repositories(
    *,
    project_id: uuid.UUID,
    finding_repository: FindingRepository,
    run_repository: RunRepository,
    waiver_repository: WaiverRepository,
    remediation_limit: int = 50,
    run_limit: int = 30,
    rollup_limit: int = 5,
) -> ProjectDashboardPublic:
    """Build the dashboard aggregate from bounded repository queries."""
    bounded_remediation_limit = max(1, min(remediation_limit, 50))
    bounded_run_limit = max(1, min(run_limit, 30))
    findings = finding_repository.list_project_findings(project_id)
    runs, run_count = run_repository.list_analysis_runs_page(
        project_id,
        limit=bounded_run_limit,
        offset=0,
    )
    dashboard = build_project_dashboard_payload(
        project_id=project_id,
        findings=findings,
        runs=runs,
        waivers=waiver_repository.list_project_waivers(project_id),
        waiver_repository=waiver_repository,
        remediation_limit=bounded_remediation_limit,
        rollup_limit=rollup_limit,
    )
    return dashboard.model_copy(
        update={
            "runs": AnalysisRunsPublic(
                data=[analysis_run_public(run, session=finding_repository.session) for run in runs],
                count=run_count,
            )
        }
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


def finding_public(finding: Finding | DecisionFindingView) -> FindingPublic:
    """Return a finding DTO with display context needed by dashboard tables."""
    view = (
        finding
        if isinstance(finding, DecisionFindingView)
        else latest_finding_decision_view(finding)
    )
    return FindingPublic.model_validate(view.finding).model_copy(update=view.public_update())


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
