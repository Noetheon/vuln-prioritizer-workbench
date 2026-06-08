"""Project dashboard aggregate helpers."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from app.decision_core.readmodels import (
    DecisionFindingView,
    decision_views_for_findings,
    latest_finding_decision_view,
)
from app.models import (
    AnalysisRun,
    AnalysisRunsPublic,
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
from app.services.dashboard_counts import (
    dashboard_signal_counts,
)
from app.services.decisions import (
    build_project_summary_payload,
)
from app.services.governance_rollups import (
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
    remediation_findings = sorted(finding_views, key=_remediation_queue_sort_key)[
        :bounded_remediation_limit
    ]
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


def finding_public(finding: Finding | DecisionFindingView) -> FindingPublic:
    """Return a finding DTO with display context needed by dashboard tables."""
    view = (
        finding
        if isinstance(finding, DecisionFindingView)
        else latest_finding_decision_view(finding)
    )
    return FindingPublic.model_validate(view.finding).model_copy(update=view.public_update())


def _remediation_queue_sort_key(view: DecisionFindingView) -> tuple[object, ...]:
    finding = view.finding
    asset = finding.asset
    component = finding.component
    return (
        view.operational_rank or 999_999,
        view.priority_rank,
        _none_last_desc_number(view.risk_score),
        _stable_text(view.cve_id),
        _stable_text(component.name if component is not None else None),
        _stable_text(asset.business_service if asset is not None else None),
        _stable_text(asset.owner if asset is not None else None),
        _stable_text(asset.asset_key if asset is not None else None),
        str(finding.id),
    )


def _none_last_desc_number(value: float | None) -> tuple[bool, float]:
    if value is None:
        return (True, 0.0)
    return (False, -float(value))


def _stable_text(value: object | None) -> str:
    return str(value or "").casefold()
