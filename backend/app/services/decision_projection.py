"""Evidence-first read models for Workbench decision projections."""

# ruff: noqa: D102

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import object_session
from sqlmodel import Session

from app.contracts.decision_evidence import (
    AnalysisEvidenceV2,
    FindingDecisionEvidenceV2,
    OccurrenceEvidenceV2,
    RunDiagnosticsV2,
)
from app.models import (
    AnalysisRun,
    AnalysisRunCountsPublic,
    AnalysisRunProviderSnapshotRefPublic,
    AnalysisRunStatus,
    AnalysisRunUploadsPublic,
    AssetExposure,
    Finding,
    FindingPriority,
    FindingStatus,
    WorkflowRunKind,
)
from app.repositories import EvidenceRepository, WorkflowRepository
from app.services.decision_evidence_builder import build_run_diagnostics
from app.services.run_workflow_metadata import redact_public_payload

SUCCESSFUL_RUN_STATUSES = {
    AnalysisRunStatus.SUCCEEDED,
    AnalysisRunStatus.COMPLETED,
    AnalysisRunStatus.COMPLETED_WITH_ERRORS,
}

WORKFLOW_RESULT_REF_SCHEMA = "workflow-result-ref.v2"


class DecisionEvidenceInvariantError(RuntimeError):
    """Raised when a v2 successful decision read is missing persisted evidence."""


@dataclass(frozen=True, slots=True)
class DecisionRunView:
    """Evidence-backed read model for one analysis run."""

    run: AnalysisRun
    evidence: AnalysisEvidenceV2 | None
    diagnostics: RunDiagnosticsV2 | None
    failure_result: dict[str, Any] | None = None

    @property
    def counts(self) -> AnalysisRunCountsPublic:
        if self.evidence is None:
            return AnalysisRunCountsPublic()
        counts = self.evidence.counts
        return AnalysisRunCountsPublic(
            created_findings=counts.created_findings,
            updated_findings=counts.updated_findings,
            ignored_lines=counts.ignored_lines,
            rows_read=counts.rows_read,
            occurrence_count=counts.occurrence_count,
            finding_count=counts.finding_count,
            counts_by_priority=dict(counts.counts_by_priority),
            kev_hits=counts.kev_hits,
            suppressed_by_vex=counts.suppressed_by_vex,
            attack_mapped_cves=counts.attack_mapped_cves,
        )

    @property
    def uploads(self) -> AnalysisRunUploadsPublic:
        if self.evidence is None:
            failure_result = self.failure_result or {}
            return AnalysisRunUploadsPublic(
                input=_dict_or_none(failure_result.get("input_upload")),
                asset_context=_dict_or_none(failure_result.get("asset_context_upload")),
                vex=_dict_or_none(failure_result.get("vex_upload")),
            )
        return AnalysisRunUploadsPublic(
            input=self.evidence.uploads.input.to_jsonable()
            if self.evidence.uploads.input
            else None,
            asset_context=self.evidence.uploads.asset_context.to_jsonable()
            if self.evidence.uploads.asset_context
            else None,
            vex=self.evidence.uploads.vex.to_jsonable() if self.evidence.uploads.vex else None,
        )

    @property
    def provider_snapshot(self) -> AnalysisRunProviderSnapshotRefPublic | None:
        if self.evidence is None:
            failure_result = self.failure_result or {}
            if self.run.provider_snapshot_id is None and not any(
                failure_result.get(key)
                for key in (
                    "provider_snapshot_file",
                    "provider_snapshot_hash",
                    "locked_provider_data",
                )
            ):
                return None
            return AnalysisRunProviderSnapshotRefPublic(
                id=self.run.provider_snapshot_id,
                file=_str_value(failure_result.get("provider_snapshot_file")),
                hash=_str_value(failure_result.get("provider_snapshot_hash")),
                locked=_bool_value(failure_result.get("locked_provider_data")),
                degraded=_bool_value(failure_result.get("provider_degraded")),
            )
        provider = self.evidence.provider
        if self.run.provider_snapshot_id is None and provider.provider_snapshot_hash is None:
            return None
        return AnalysisRunProviderSnapshotRefPublic(
            id=self.run.provider_snapshot_id,
            file=provider.provider_snapshot_file,
            hash=provider.provider_snapshot_hash,
            locked=provider.locked_provider_data,
            degraded=provider.provider_degraded,
        )

    @property
    def warnings(self) -> list[str]:
        if self.evidence is not None:
            return list(self.evidence.warnings)
        if self.diagnostics is not None:
            return list(self.diagnostics.warnings)
        return []

    @property
    def parse_errors(self) -> list[Any]:
        if self.evidence is not None:
            return list(self.evidence.parse_errors)
        if self.diagnostics is not None:
            return list(self.diagnostics.parse_errors)
        return []

    @property
    def provider_degraded(self) -> bool:
        return bool(self.evidence and self.evidence.provider.provider_degraded)

    @property
    def analysis_decision_scope(self) -> str | None:
        if self.evidence is None:
            return None
        return _str_value(self.evidence.analysis_semantics.get("analysis_decision_scope"))

    @property
    def persistence_scope(self) -> str | None:
        if self.evidence is None:
            return None
        return _str_value(self.evidence.analysis_semantics.get("persistence_scope"))

    @property
    def summary_payload(self) -> dict[str, object]:
        if self.evidence is None:
            return {}
        payload = self.evidence.to_jsonable()
        provider = dict(payload.get("provider") or {})
        counts = dict(payload.get("counts") or {})
        uploads = dict(payload.get("uploads") or {})
        return {
            **counts,
            **provider,
            "input_upload": uploads.get("input"),
            "asset_context_upload": uploads.get("asset_context"),
            "vex_upload": uploads.get("vex"),
            "input_sha256": payload.get("input_sha256"),
            "warnings": payload.get("warnings") or [],
            "parse_errors": payload.get("parse_errors") or [],
            "analysis_service": payload.get("analysis_service") or {},
            "analysis_semantics": payload.get("analysis_semantics") or {},
            "asset_context": payload.get("asset_context"),
            "vex": payload.get("vex"),
            "dedup_summary": payload.get("dedup_summary"),
        }

    @property
    def input_file_hash(self) -> str | None:
        if self.evidence is None:
            return None
        payload = self.evidence.to_jsonable()
        if isinstance(payload.get("input_sha256"), str):
            return payload["input_sha256"]
        uploads = dict(payload.get("uploads") or {})
        input_upload = uploads.get("input")
        if isinstance(input_upload, dict) and isinstance(input_upload.get("sha256"), str):
            return input_upload["sha256"]
        return None


@dataclass(frozen=True, slots=True)
class DecisionOccurrenceView:
    """Evidence-backed occurrence read model."""

    evidence: OccurrenceEvidenceV2
    finding: Finding


@dataclass(frozen=True, slots=True)
class DecisionFindingView:
    """Evidence-backed read model for one finding decision."""

    finding: Finding
    evidence: FindingDecisionEvidenceV2 | None = None

    @property
    def finding_id(self) -> uuid.UUID:
        return self.finding.id

    @property
    def cve_id(self) -> str:
        return self.evidence.cve_id if self.evidence is not None else self.finding.cve_id

    @property
    def dedup_key(self) -> str:
        return self.evidence.dedup_key if self.evidence is not None else self.finding.dedup_key

    @property
    def status(self) -> FindingStatus:
        if self.evidence is None:
            return self.finding.status
        return _status_value(self.evidence.status)

    @property
    def priority(self) -> FindingPriority:
        if self.evidence is None:
            return self.finding.priority
        return _priority_value(self.evidence.priority)

    @property
    def priority_label(self) -> str:
        return _priority_label(self.priority)

    @property
    def priority_rank(self) -> int:
        return (
            self.evidence.priority_rank if self.evidence is not None else self.finding.priority_rank
        )

    @property
    def risk_score(self) -> float | None:
        return self.evidence.risk_score if self.evidence is not None else self.finding.risk_score

    @property
    def operational_rank(self) -> int:
        return (
            self.evidence.operational_rank
            if self.evidence is not None
            else self.finding.operational_rank
        )

    @property
    def in_kev(self) -> bool:
        return self.evidence.in_kev if self.evidence is not None else self.finding.in_kev

    @property
    def epss(self) -> float | None:
        return self.evidence.epss if self.evidence is not None else self.finding.epss

    @property
    def cvss_base_score(self) -> float | None:
        return (
            self.evidence.cvss_base_score
            if self.evidence is not None
            else self.finding.cvss_base_score
        )

    @property
    def attack_mapped(self) -> bool:
        return (
            self.evidence.attack_mapped if self.evidence is not None else self.finding.attack_mapped
        )

    @property
    def suppressed_by_vex(self) -> bool:
        return (
            self.evidence.suppressed_by_vex
            if self.evidence is not None
            else self.finding.suppressed_by_vex
        )

    @property
    def under_investigation(self) -> bool:
        return (
            self.evidence.under_investigation
            if self.evidence is not None
            else self.finding.under_investigation
        )

    @property
    def waived(self) -> bool:
        return self.evidence.waived if self.evidence is not None else self.finding.waived

    @property
    def rationale(self) -> str | None:
        return self.evidence.rationale if self.evidence is not None else self.finding.rationale

    @property
    def recommended_action(self) -> str | None:
        return (
            self.evidence.recommended_action
            if self.evidence is not None
            else self.finding.recommended_action
        )

    @property
    def occurrence_views(self) -> list[DecisionOccurrenceView]:
        if self.evidence is None:
            return []
        return [
            DecisionOccurrenceView(evidence=occurrence, finding=self.finding)
            for occurrence in self.evidence.occurrences
        ]

    @property
    def component_label(self) -> str | None:
        component = self.finding.component
        if component is None:
            return None
        if component.version:
            return f"{component.name} {component.version}"
        return component.name

    @property
    def asset_label(self) -> str | None:
        asset = self.finding.asset
        if asset is None:
            return None
        return asset.name or asset.asset_key

    @property
    def evidence_payload(self) -> dict[str, Any]:
        return self.evidence.to_jsonable() if self.evidence is not None else {}

    def public_update(self) -> dict[str, object]:
        update: dict[str, object] = {
            "evidence": self.evidence,
            "component_name": self.finding.component.name if self.finding.component else None,
            "component_version": self.finding.component.version if self.finding.component else None,
            "component_purl": self.finding.component.purl if self.finding.component else None,
            "asset_name": self.finding.asset.name if self.finding.asset else None,
            "asset_key": self.finding.asset.asset_key if self.finding.asset else None,
            "asset_target_ref": self.finding.asset.target_ref if self.finding.asset else None,
            "asset_environment": self.finding.asset.environment if self.finding.asset else None,
            "asset_criticality": self.finding.asset.criticality if self.finding.asset else None,
            "owner": self.finding.asset.owner if self.finding.asset else None,
            "business_service": self.finding.asset.business_service if self.finding.asset else None,
            "exposure": self.finding.asset.exposure if self.finding.asset else None,
        }
        if self.evidence is not None:
            update.update(
                {
                    "cve_id": self.cve_id,
                    "dedup_key": self.dedup_key,
                    "status": self.status,
                    "priority": self.priority,
                    "priority_rank": self.priority_rank,
                    "risk_score": self.risk_score,
                    "operational_rank": self.operational_rank,
                    "in_kev": self.in_kev,
                    "epss": self.epss,
                    "cvss_base_score": self.cvss_base_score,
                    "attack_mapped": self.attack_mapped,
                    "suppressed_by_vex": self.suppressed_by_vex,
                    "under_investigation": self.under_investigation,
                    "waived": self.waived,
                    "recommended_action": self.recommended_action,
                    "rationale": self.rationale,
                }
            )
        return update


def decision_run_view(
    run: AnalysisRun,
    *,
    session: Session | None = None,
) -> DecisionRunView:
    """Return the centralized evidence-first run read model."""
    active_session = session or object_session(run)
    if not isinstance(active_session, Session):
        return DecisionRunView(run=run, evidence=None, diagnostics=None)
    evidence_repo = EvidenceRepository(active_session)
    evidence = evidence_repo.get_analysis_evidence(run.id)
    diagnostics = evidence_repo.get_run_diagnostics(run.id)
    workflow = WorkflowRepository(active_session).get_latest_analysis_workflow(
        analysis_run_id=run.id,
        kind=WorkflowRunKind.IMPORT,
    )
    workflow_result = workflow.result_json if workflow is not None else None
    if evidence is None and _requires_success_evidence(run, workflow_result=workflow_result):
        raise DecisionEvidenceInvariantError(
            f"Successful v2 analysis run {run.id} is missing AnalysisEvidenceV2."
        )
    failure_result: dict[str, Any] | None = None
    if workflow is not None and run.status not in SUCCESSFUL_RUN_STATUSES:
        failure_result = _dict_value(redact_public_payload(workflow.result_json))
    if diagnostics is None and workflow is not None and workflow.diagnostics_json:
        diagnostics = build_run_diagnostics(redact_public_payload(workflow.diagnostics_json))
    return DecisionRunView(
        run=run,
        evidence=evidence,
        diagnostics=diagnostics,
        failure_result=failure_result,
    )


def decision_finding_view(
    finding: Finding,
    *,
    evidence: FindingDecisionEvidenceV2 | None = None,
) -> DecisionFindingView:
    """Return a finding read model from an already-loaded evidence item."""
    return DecisionFindingView(finding=finding, evidence=evidence)


def latest_finding_decision_view(
    finding: Finding,
    *,
    session: Session | None = None,
) -> DecisionFindingView:
    """Return a finding read model using the latest persisted decision evidence."""
    active_session = session or object_session(finding)
    evidence = None
    if isinstance(active_session, Session):
        evidence = EvidenceRepository(active_session).latest_finding_decision_evidence(finding.id)
    return DecisionFindingView(finding=finding, evidence=evidence)


def project_finding_decision_views(
    session: Session,
    findings: list[Finding],
) -> list[DecisionFindingView]:
    """Return latest decision views for a project finding list without N+1 lookups."""
    evidence_by_finding = EvidenceRepository(session).latest_finding_decision_evidence_for_findings(
        [finding.id for finding in findings]
    )
    return [
        DecisionFindingView(finding=finding, evidence=evidence_by_finding.get(finding.id))
        for finding in findings
    ]


def run_finding_decision_views(
    session: Session,
    *,
    run: AnalysisRun,
    findings: list[Finding],
) -> list[DecisionFindingView]:
    """Return evidence-required finding views for one successful run."""
    evidence_by_finding = EvidenceRepository(session).finding_decision_evidence_for_run(run.id)
    views = [
        DecisionFindingView(finding=finding, evidence=evidence_by_finding.get(finding.id))
        for finding in findings
    ]
    if run.status in SUCCESSFUL_RUN_STATUSES:
        missing = [view.finding.id for view in views if view.evidence is None]
        if missing:
            raise DecisionEvidenceInvariantError(
                f"Successful analysis run {run.id} is missing FindingDecisionEvidenceV2 "
                f"for {len(missing)} finding(s)."
            )
    return views


def decision_views_for_findings(findings: list[Finding]) -> list[DecisionFindingView]:
    """Return best-effort latest decision views for attached findings."""
    if not findings:
        return []
    session = object_session(findings[0])
    if isinstance(session, Session):
        return project_finding_decision_views(session, findings)
    return [DecisionFindingView(finding=finding) for finding in findings]


def evidence_priority_label(value: str | FindingPriority) -> str:
    """Return canonical display label for a priority value."""
    return _priority_label(_priority_value(str(value)))


def _requires_success_evidence(
    run: AnalysisRun,
    *,
    workflow_result: dict[str, Any] | None,
) -> bool:
    if run.status not in SUCCESSFUL_RUN_STATUSES:
        return False
    if workflow_result is None:
        return False
    return workflow_result.get("schema_version") == WORKFLOW_RESULT_REF_SCHEMA


def _status_value(value: str) -> FindingStatus:
    try:
        return FindingStatus(value)
    except ValueError as exc:
        raise DecisionEvidenceInvariantError(
            f"Invalid finding status in evidence: {value}"
        ) from exc


def _priority_value(value: str) -> FindingPriority:
    normalized = value.split(".", maxsplit=1)[-1].strip().lower()
    try:
        return FindingPriority(normalized)
    except ValueError as exc:
        raise DecisionEvidenceInvariantError(
            f"Invalid finding priority in evidence: {value}"
        ) from exc


def _priority_label(value: FindingPriority) -> str:
    return {
        FindingPriority.CRITICAL: "Critical",
        FindingPriority.HIGH: "High",
        FindingPriority.MEDIUM: "Medium",
        FindingPriority.LOW: "Low",
    }[value]


def _str_value(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _dict_value(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _dict_or_none(value: Any) -> dict[str, Any] | None:
    payload = _dict_value(value)
    return payload or None


def _bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return False


def finding_is_internet_facing_critical(view: DecisionFindingView) -> bool:
    """Return whether a finding is a critical internet-facing signal."""
    asset = view.finding.asset
    return (
        view.priority == FindingPriority.CRITICAL
        and asset is not None
        and asset.exposure == AssetExposure.INTERNET_FACING
    )


__all__ = [
    "DecisionEvidenceInvariantError",
    "DecisionFindingView",
    "DecisionOccurrenceView",
    "DecisionRunView",
    "SUCCESSFUL_RUN_STATUSES",
    "decision_finding_view",
    "decision_run_view",
    "decision_views_for_findings",
    "evidence_priority_label",
    "finding_is_internet_facing_critical",
    "latest_finding_decision_view",
    "project_finding_decision_views",
    "run_finding_decision_views",
]
