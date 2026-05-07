"""Project dashboard aggregate helpers."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from app.models import (
    AnalysisRun,
    AnalysisRunPublic,
    AnalysisRunsPublic,
    AssetExposure,
    DashboardEpssBucketsPublic,
    DashboardSignalCountsPublic,
    Finding,
    FindingPriority,
    FindingPublic,
    FindingsPublic,
    ProjectDashboardFindingsPublic,
    ProjectDashboardPublic,
    Waiver,
)
from app.models.base import get_datetime_utc
from app.repositories.waivers import WaiverRepository
from app.services.decisions import build_project_summary_payload
from app.services.governance import build_project_governance_rollups_payload
from vuln_prioritizer.security_redaction import redact_value


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
    remediation_findings = list(findings[:bounded_remediation_limit])
    return ProjectDashboardPublic(
        project_id=project_id,
        generated_at=get_datetime_utc(),
        summary=build_project_summary_payload(
            project_id=project_id,
            findings=findings,
            runs=runs,
        ),
        governance=build_project_governance_rollups_payload(
            project_id=project_id,
            findings=findings,
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
                count=len(findings),
            ),
            signal_counts=dashboard_signal_counts(findings),
        ),
    )


def dashboard_signal_counts(findings: Sequence[Finding]) -> DashboardSignalCountsPublic:
    """Compute dashboard signal counts without issuing extra findings queries."""
    return DashboardSignalCountsPublic(
        high_epss=sum(1 for finding in findings if _epss_in_range(finding, minimum=0.7)),
        internet_facing_criticals=sum(
            1
            for finding in findings
            if finding.priority == FindingPriority.CRITICAL
            and finding.asset is not None
            and finding.asset.exposure == AssetExposure.INTERNET_FACING
        ),
        epss_buckets=DashboardEpssBucketsPublic(
            low=sum(1 for finding in findings if _epss_in_range(finding, minimum=0, maximum=0.25)),
            medium=sum(
                1 for finding in findings if _epss_in_range(finding, minimum=0.25, maximum=0.5)
            ),
            high=sum(
                1 for finding in findings if _epss_in_range(finding, minimum=0.5, maximum=0.7)
            ),
            critical=sum(1 for finding in findings if _epss_in_range(finding, minimum=0.7)),
        ),
    )


def finding_public(finding: Finding) -> FindingPublic:
    """Return a finding DTO with display context needed by dashboard tables."""
    return FindingPublic.model_validate(finding).model_copy(
        update={
            "explanation_json": _redacted_json_payload(finding.explanation_json),
            "data_quality_json": _redacted_json_payload(finding.data_quality_json),
            "evidence_json": _redacted_json_payload(finding.evidence_json),
            "component_name": finding.component.name if finding.component else None,
            "component_version": finding.component.version if finding.component else None,
            "component_purl": finding.component.purl if finding.component else None,
            "asset_name": finding.asset.name if finding.asset else None,
            "asset_key": finding.asset.asset_key if finding.asset else None,
            "asset_target_ref": finding.asset.target_ref if finding.asset else None,
            "asset_environment": finding.asset.environment if finding.asset else None,
            "asset_criticality": finding.asset.criticality if finding.asset else None,
            "owner": finding.asset.owner if finding.asset else None,
            "business_service": finding.asset.business_service if finding.asset else None,
            "exposure": finding.asset.exposure if finding.asset else None,
        }
    )


def analysis_run_public(run: AnalysisRun) -> AnalysisRunPublic:
    """Return a redacted analysis-run DTO for dashboard aggregate payloads."""
    public = AnalysisRunPublic.model_validate(run)
    return public.model_copy(
        update={
            "summary_json": _redacted_json_payload(run.summary_json or {}),
            "error_json": _redacted_json_payload(run.error_json or {}),
            "error_message": _redacted_value(run.error_message),
        }
    )


def _epss_in_range(
    finding: Finding,
    *,
    minimum: float,
    maximum: float | None = None,
) -> bool:
    if finding.epss is None or finding.epss < minimum:
        return False
    return maximum is None or finding.epss <= maximum


def _redacted_json_payload(payload: dict[str, Any]) -> dict[str, Any]:
    redacted, _paths = redact_value(payload)
    return redacted if isinstance(redacted, dict) else {}


def _redacted_value(value: Any) -> Any:
    redacted, _paths = redact_value(value)
    return redacted
