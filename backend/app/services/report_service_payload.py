"""Payload assembly helpers for Workbench report generation."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from datetime import datetime
from typing import Any

from sqlmodel import Session, col, select

from app.decision_core.contracts import FindingDecisionEvidenceV2
from app.decision_core.readmodels import DecisionFindingView, decision_run_view
from app.models import (
    AnalysisEvidence,
    AnalysisRun,
    AnalysisRunStatus,
    Finding,
    FindingDecisionEvidence,
    FindingOccurrence,
    Project,
)
from app.models.base import get_datetime_utc
from app.repositories.evidence_payloads import EvidencePayloadStore
from app.services.report_governance_projection import build_run_governance_rollups
from app.services.report_models import (
    MarkdownReportFinding,
    MarkdownReportPayload,
    ReportGenerationError,
)
from app.services.report_projection import (
    _finding_payload_from_decision_view,
    _provider_snapshot_payload,
)

REPORT_SUPPORTED_RUN_STATUSES = {
    AnalysisRunStatus.COMPLETED,
    AnalysisRunStatus.COMPLETED_WITH_ERRORS,
    AnalysisRunStatus.SUCCEEDED,
}


class ReportSource:
    """Validate one historical envelope and hydrate only one batch of its members."""

    batch_size = 25

    def __init__(self, session: Session, *, run: AnalysisRun, project: Project) -> None:
        generated_at = get_datetime_utc()
        run_view = decision_run_view(run, session=session)
        evidence = run_view.evidence
        if evidence is None:
            raise ReportGenerationError("Analysis evidence v2 is required before reporting.")
        if evidence.analysis_run_id != str(run.id):
            raise ReportGenerationError(
                "Analysis evidence run identity does not match the requested report run."
            )
        if evidence.project_id != str(project.id) or evidence.project_id != str(run.project_id):
            raise ReportGenerationError(
                "Analysis evidence project identity does not match the requested report project."
            )
        if evidence.status not in {str(status) for status in REPORT_SUPPORTED_RUN_STATUSES}:
            raise ReportGenerationError(
                "Analysis run must be completed before reporting; "
                f"evidence status is {evidence.status}."
            )

        # Sort compact scalar keys with the same Python ordering as report views.
        document = col(FindingDecisionEvidence.payload_json)
        keys = session.exec(
            select(
                Finding.id,
                document["operational_rank"].as_integer(),
                document["priority_rank"].as_integer(),
                FindingDecisionEvidence.cve_id,
            )
            .join(
                FindingDecisionEvidence, col(FindingDecisionEvidence.finding_id) == col(Finding.id)
            )
            .where(FindingDecisionEvidence.analysis_run_id == run.id)
        ).all()
        self.finding_ids = [
            key[0]
            for key in sorted(
                keys, key=lambda key: (key[1] or 999_999, key[2], key[3], str(key[0]))
            )
        ]
        if len(self.finding_ids) != evidence.counts.finding_count:
            raise ReportGenerationError(
                "Analysis evidence finding membership is inconsistent: "
                f"expected {evidence.counts.finding_count}, found {len(self.finding_ids)}."
            )
        summary = run_view.summary_payload
        payload = MarkdownReportPayload(
            generated_at=generated_at,
            project_id=evidence.project_id,
            project_name=project.name,
            run_id=evidence.analysis_run_id,
            run_status=evidence.status,
            input_type=evidence.input_type,
            filename=evidence.filename,
            summary=summary,
            findings=(),
            provider_snapshot=_provider_snapshot_payload(
                None,
                evidence=evidence.provider,
            ),
            governance_rollups={},
            project_description=project.description,
            project_created_at=project.created_at,
            project_updated_at=project.updated_at,
            project_context_source="current_project_projection_at_export",
            run_started_at=None,
            run_finished_at=None,
            run_error=None,
            run_errors=evidence.diagnostics.to_jsonable()
            if evidence.diagnostics is not None
            else {},
            input_file_hash=run_view.input_file_hash,
        )

        self.session = session
        self.run = run
        self.project = project
        self.evidence = evidence
        self.header = payload
        self.provider_dates: dict[str, Any] = {
            "scope": "selected_run_findings",
            "derivation": "immutable_finding_decision_evidence",
            "finding_evidence_count": 0,
            "nvd_last_modified_max": None,
            "latest_epss_date": None,
            "kev_date_added_max": None,
        }

    def findings(
        self, checkpoint: Callable[[], None] | None = None
    ) -> Iterator[tuple[MarkdownReportFinding, Finding]]:
        """Yield validated immutable report findings, without loading current projections."""
        for offset in range(0, len(self.finding_ids), self.batch_size):
            if checkpoint is not None:
                checkpoint()
            store = EvidencePayloadStore(self.session.connection())
            ids = self.finding_ids[offset : offset + self.batch_size]
            rows = self.session.exec(
                select(Finding, FindingDecisionEvidence)
                .join(
                    FindingDecisionEvidence,
                    col(FindingDecisionEvidence.finding_id) == col(Finding.id),
                )
                .where(
                    FindingDecisionEvidence.analysis_run_id == self.run.id, col(Finding.id).in_(ids)
                )
            ).all()
            if len(rows) != len(ids) or any(
                record.project_id != self.project.id or finding.project_id != self.project.id
                for finding, record in rows
            ):
                raise ReportGenerationError(
                    "Finding decision evidence identity does not match "
                    "the report evidence envelope."
                )
            payloads = store.load_records(record for _, record in rows)
            by_id = {finding.id: (finding, record) for finding, record in rows}
            for finding_id in ids:
                finding, record = by_id[finding_id]
                evidence = FindingDecisionEvidenceV2.model_validate(payloads[record.id])
                if (
                    evidence.analysis_run_id != self.evidence.analysis_run_id
                    or evidence.project_id != self.evidence.project_id
                    or evidence.finding_id != str(finding.id)
                ):
                    raise ReportGenerationError(
                        "Finding decision evidence identity does not match "
                        "the report evidence envelope."
                    )
                self.provider_dates["finding_evidence_count"] += 1
                facts = evidence.provider.provider_evidence
                for provider, field, key in (
                    ("nvd", "last_modified", "nvd_last_modified_max"),
                    ("epss", "date", "latest_epss_date"),
                    ("kev", "date_added", "kev_date_added_max"),
                ):
                    item = facts.get(provider)
                    value = item.get(field) if isinstance(item, dict) else None
                    if isinstance(value, str) and value.strip():
                        self.provider_dates[key] = max(
                            self.provider_dates[key] or "", value.strip()
                        )
                yield (
                    _finding_payload_from_decision_view(
                        DecisionFindingView(finding=finding, evidence=evidence), occurrences=[]
                    ),
                    finding,
                )

    def payload(self, findings: list[MarkdownReportFinding]) -> MarkdownReportPayload:
        """Complete small run-wide summaries after iterating historical findings."""
        provider = self.header.provider_snapshot
        if provider is not None:
            provider = provider.model_copy(
                update={
                    "source_metadata": {
                        **provider.source_metadata,
                        "run_subset_provider_evidence": dict(self.provider_dates),
                    }
                }
            )
        return self.header.model_copy(
            update={
                "provider_snapshot": provider,
                "findings": tuple(findings),
                "governance_rollups": build_run_governance_rollups(
                    project_id=self.project.id,
                    findings=findings,
                    generated_at=self.header.generated_at,
                    evaluated_at=self.header.generated_at,
                ),
            }
        )


def build_report_payload(
    session: Session,
    *,
    run: AnalysisRun,
    project: Project,
    max_input_bytes: int | None = None,
) -> tuple[MarkdownReportPayload, list[Finding], datetime]:
    """Build a bounded rendering payload for formats that need the whole run."""
    source = ReportSource(session, run=run, project=project)
    report_findings: list[MarkdownReportFinding] = []
    findings: list[Finding] = []
    input_bytes = 0
    for item, finding in source.findings():
        if max_input_bytes is not None:
            input_bytes += len(item.model_dump_json().encode("utf-8"))
            if input_bytes > max_input_bytes:
                raise ReportGenerationError(
                    "Report input exceeds configured report size limit for in-memory rendering. "
                    "Use the streaming JSON (gzip) or CSV export for large runs."
                )
        report_findings.append(item)
        findings.append(finding)
    return source.payload(report_findings), findings, source.header.generated_at


def run_findings(session: Session, run: AnalysisRun) -> list[Finding]:
    """Return immutable v2 run members, with occurrence lookup only for true legacy runs."""
    has_analysis_evidence = (
        session.exec(
            select(AnalysisEvidence.id).where(AnalysisEvidence.analysis_run_id == run.id).limit(1)
        ).first()
        is not None
    )
    if has_analysis_evidence:
        statement = (
            select(Finding)
            .join(
                FindingDecisionEvidence,
                col(FindingDecisionEvidence.finding_id) == col(Finding.id),
            )
            .where(FindingDecisionEvidence.analysis_run_id == run.id)
            .order_by(FindingDecisionEvidence.cve_id, col(Finding.id))
        )
    else:
        statement = (
            select(Finding)
            .join(FindingOccurrence)
            .where(FindingOccurrence.analysis_run_id == run.id)
            .order_by(Finding.cve_id, col(Finding.id))
        )
    findings: list[Finding] = []
    seen_ids: set[uuid.UUID] = set()
    for finding in session.exec(statement).all():
        if finding.id in seen_ids:
            continue
        findings.append(finding)
        seen_ids.add(finding.id)
    return findings


def run_occurrences_by_finding(
    session: Session,
    run: AnalysisRun,
) -> dict[uuid.UUID, list[FindingOccurrence]]:
    """Run occurrences by finding function."""
    statement = (
        select(FindingOccurrence)
        .where(FindingOccurrence.analysis_run_id == run.id)
        .order_by(col(FindingOccurrence.id))
    )
    occurrences: dict[uuid.UUID, list[FindingOccurrence]] = {}
    for occurrence in session.exec(statement).all():
        occurrences.setdefault(occurrence.finding_id, []).append(occurrence)
    return occurrences


__all__ = [
    "REPORT_SUPPORTED_RUN_STATUSES",
    "build_report_payload",
    "run_findings",
    "run_occurrences_by_finding",
]
