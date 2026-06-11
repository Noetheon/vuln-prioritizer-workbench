"""Repositories for Decision/Evidence Kernel v2 payloads."""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from sqlmodel import Session, col, select

from app.decision_core.contracts import (
    ANALYSIS_EVIDENCE_SCHEMA_VERSION,
    FINDING_DECISION_EVIDENCE_SCHEMA_VERSION,
    AnalysisEvidenceV2,
    FindingDecisionEvidenceV2,
    RunDiagnosticsV2,
)
from app.models import AnalysisEvidence, FindingDecisionEvidence
from app.models.base import get_datetime_utc


class EvidenceRepository:
    """Persist and fetch v2 run/finding evidence contracts."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def upsert_analysis_evidence(
        self,
        *,
        project_id: uuid.UUID,
        analysis_run_id: uuid.UUID,
        provider_snapshot_id: uuid.UUID | None,
        evidence: AnalysisEvidenceV2,
        diagnostics: RunDiagnosticsV2 | None = None,
    ) -> AnalysisEvidence:
        """Persist the validated run-wide evidence contract."""
        existing = self.get_analysis_evidence_record(analysis_run_id)
        record = existing or AnalysisEvidence(
            project_id=project_id,
            analysis_run_id=analysis_run_id,
            provider_snapshot_id=provider_snapshot_id,
        )
        if existing is None:
            self.session.add(record)
            self.session.flush()
        payload = evidence.model_copy(update={"analysis_evidence_id": str(record.id)})
        record.project_id = project_id
        record.analysis_run_id = analysis_run_id
        record.provider_snapshot_id = provider_snapshot_id
        record.schema_version = ANALYSIS_EVIDENCE_SCHEMA_VERSION
        record.payload_json = payload.to_jsonable()
        record.diagnostics_json = diagnostics.to_jsonable() if diagnostics is not None else {}
        record.updated_at = get_datetime_utc()
        self.session.add(record)
        self.session.flush()
        return record

    def prepare_analysis_evidence_record(
        self,
        *,
        project_id: uuid.UUID,
        analysis_run_id: uuid.UUID,
        provider_snapshot_id: uuid.UUID | None,
    ) -> AnalysisEvidence:
        """Create the run evidence row before chunked finding evidence writes."""
        existing = self.get_analysis_evidence_record(analysis_run_id)
        record = existing or AnalysisEvidence(
            project_id=project_id,
            analysis_run_id=analysis_run_id,
            provider_snapshot_id=provider_snapshot_id,
        )
        if existing is None:
            self.session.add(record)
            self.session.flush()
        record.project_id = project_id
        record.analysis_run_id = analysis_run_id
        record.provider_snapshot_id = provider_snapshot_id
        record.schema_version = ANALYSIS_EVIDENCE_SCHEMA_VERSION
        record.updated_at = get_datetime_utc()
        self.session.add(record)
        self.session.flush()
        return record

    def replace_finding_decision_evidence(
        self,
        *,
        analysis_evidence_id: uuid.UUID,
        project_id: uuid.UUID,
        analysis_run_id: uuid.UUID,
        evidence_items: Iterable[FindingDecisionEvidenceV2],
    ) -> list[FindingDecisionEvidence]:
        """Upsert current finding evidence records for a run."""
        records: list[FindingDecisionEvidence] = []
        for item in evidence_items:
            finding_id = uuid.UUID(item.finding_id)
            existing = self.get_finding_decision_evidence_record(
                finding_id=finding_id,
                analysis_run_id=analysis_run_id,
            )
            record = existing or FindingDecisionEvidence(
                analysis_evidence_id=analysis_evidence_id,
                project_id=project_id,
                analysis_run_id=analysis_run_id,
                finding_id=finding_id,
                cve_id=item.cve_id,
                dedup_key=item.dedup_key,
                priority=item.priority,
                status=item.status,
            )
            if existing is None:
                self.session.add(record)
            record.analysis_evidence_id = analysis_evidence_id
            record.project_id = project_id
            record.analysis_run_id = analysis_run_id
            record.finding_id = finding_id
            record.schema_version = FINDING_DECISION_EVIDENCE_SCHEMA_VERSION
            record.cve_id = item.cve_id
            record.dedup_key = item.dedup_key
            record.priority = item.priority
            record.status = item.status
            record.payload_json = item.to_jsonable()
            record.updated_at = get_datetime_utc()
            records.append(record)
        self.session.flush()
        return records

    def get_analysis_evidence_record(
        self,
        analysis_run_id: uuid.UUID,
    ) -> AnalysisEvidence | None:
        """Return the persisted run-wide evidence row."""
        return self.session.exec(
            select(AnalysisEvidence).where(AnalysisEvidence.analysis_run_id == analysis_run_id)
        ).first()

    def get_analysis_evidence(self, analysis_run_id: uuid.UUID) -> AnalysisEvidenceV2 | None:
        """Return the validated run-wide evidence contract."""
        record = self.get_analysis_evidence_record(analysis_run_id)
        if record is None:
            return None
        return AnalysisEvidenceV2.model_validate(record.payload_json)

    def get_run_diagnostics(self, analysis_run_id: uuid.UUID) -> RunDiagnosticsV2 | None:
        """Return typed run diagnostics when they exist."""
        record = self.get_analysis_evidence_record(analysis_run_id)
        if record is None or not record.diagnostics_json:
            return None
        return RunDiagnosticsV2.model_validate(record.diagnostics_json)

    def get_finding_decision_evidence_record(
        self,
        *,
        finding_id: uuid.UUID,
        analysis_run_id: uuid.UUID,
    ) -> FindingDecisionEvidence | None:
        """Return finding evidence for one run."""
        return self.session.exec(
            select(FindingDecisionEvidence).where(
                FindingDecisionEvidence.finding_id == finding_id,
                FindingDecisionEvidence.analysis_run_id == analysis_run_id,
            )
        ).first()

    def latest_finding_decision_evidence(
        self,
        finding_id: uuid.UUID,
    ) -> FindingDecisionEvidenceV2 | None:
        """Return the newest evidence contract for a finding."""
        record = self.latest_finding_decision_evidence_record(finding_id)
        if record is None:
            return None
        return FindingDecisionEvidenceV2.model_validate(record.payload_json)

    def latest_finding_decision_evidence_record(
        self,
        finding_id: uuid.UUID,
    ) -> FindingDecisionEvidence | None:
        """Return the newest evidence row for a finding."""
        return self.session.exec(
            select(FindingDecisionEvidence)
            .where(FindingDecisionEvidence.finding_id == finding_id)
            .order_by(col(FindingDecisionEvidence.created_at).desc())
        ).first()

    def latest_finding_decision_evidence_for_findings(
        self,
        finding_ids: Iterable[uuid.UUID],
    ) -> dict[uuid.UUID, FindingDecisionEvidenceV2]:
        """Return newest evidence contracts for findings keyed by finding id."""
        ids = list(finding_ids)
        if not ids:
            return {}
        rows = self.session.exec(
            select(FindingDecisionEvidence)
            .where(col(FindingDecisionEvidence.finding_id).in_(ids))
            .order_by(
                col(FindingDecisionEvidence.finding_id),
                col(FindingDecisionEvidence.created_at).desc(),
            )
        ).all()
        evidence_by_finding: dict[uuid.UUID, FindingDecisionEvidenceV2] = {}
        for row in rows:
            if row.finding_id in evidence_by_finding:
                continue
            evidence_by_finding[row.finding_id] = FindingDecisionEvidenceV2.model_validate(
                row.payload_json
            )
        return evidence_by_finding

    def finding_decision_evidence_for_run(
        self,
        analysis_run_id: uuid.UUID,
    ) -> dict[uuid.UUID, FindingDecisionEvidenceV2]:
        """Return all finding evidence contracts for one run keyed by finding id."""
        rows = self.session.exec(
            select(FindingDecisionEvidence).where(
                FindingDecisionEvidence.analysis_run_id == analysis_run_id
            )
        ).all()
        return {
            row.finding_id: FindingDecisionEvidenceV2.model_validate(row.payload_json)
            for row in rows
        }

    def finding_decision_evidence_rows_for_runs(
        self,
        analysis_run_ids: Iterable[uuid.UUID],
    ) -> list[FindingDecisionEvidence]:
        """Return raw finding evidence rows for several runs in one query."""
        ids = list(analysis_run_ids)
        if not ids:
            return []
        return list(
            self.session.exec(
                select(FindingDecisionEvidence).where(
                    col(FindingDecisionEvidence.analysis_run_id).in_(ids)
                )
            ).all()
        )

    def analysis_evidence_run_ids(
        self,
        analysis_run_ids: Iterable[uuid.UUID],
    ) -> set[uuid.UUID]:
        """Return the subset of run ids that have persisted run-wide evidence."""
        ids = list(analysis_run_ids)
        if not ids:
            return set()
        rows = self.session.exec(
            select(AnalysisEvidence.analysis_run_id).where(
                col(AnalysisEvidence.analysis_run_id).in_(ids)
            )
        ).all()
        return set(rows)
