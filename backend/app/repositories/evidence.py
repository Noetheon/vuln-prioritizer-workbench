"""Repositories for Decision/Evidence Kernel v2 payloads."""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from sqlmodel import Session, col, func, select

from app.decision_core.contracts import (
    ANALYSIS_EVIDENCE_SCHEMA_VERSION,
    FINDING_DECISION_EVIDENCE_SCHEMA_VERSION,
    AnalysisEvidenceV2,
    FindingDecisionEvidenceV2,
    RunDiagnosticsV2,
)
from app.decision_core.ledger import DecisionLedgerInvariantError
from app.models import AnalysisEvidence, FindingDecisionEvidence
from app.models.base import get_datetime_utc
from app.repositories.current_projections import FindingCurrentProjectionRepository


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
        """Finalize one immutable validated run-wide evidence contract."""
        if evidence.project_id != str(project_id):
            raise DecisionLedgerInvariantError(
                "Analysis evidence project does not match its persistence envelope."
            )
        if evidence.analysis_run_id != str(analysis_run_id):
            raise DecisionLedgerInvariantError(
                "Analysis evidence run does not match its persistence envelope."
            )
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
        payload_json = payload.to_jsonable()
        diagnostics_json = diagnostics.to_jsonable() if diagnostics is not None else {}
        if existing is not None and (
            existing.project_id != project_id
            or existing.provider_snapshot_id != provider_snapshot_id
        ):
            raise DecisionLedgerInvariantError(
                f"Analysis evidence run {analysis_run_id} changed persistence identity."
            )
        if existing is not None and existing.payload_json:
            if (
                existing.payload_json != payload_json
                or existing.diagnostics_json != diagnostics_json
            ):
                raise DecisionLedgerInvariantError(
                    f"Analysis evidence for run {analysis_run_id} is immutable once finalized."
                )
            return existing
        record.project_id = project_id
        record.analysis_run_id = analysis_run_id
        record.provider_snapshot_id = provider_snapshot_id
        record.schema_version = ANALYSIS_EVIDENCE_SCHEMA_VERSION
        record.payload_json = payload_json
        record.diagnostics_json = diagnostics_json
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
        """Create an empty run evidence envelope before chunked finding writes."""
        existing = self.get_analysis_evidence_record(analysis_run_id)
        record = existing or AnalysisEvidence(
            project_id=project_id,
            analysis_run_id=analysis_run_id,
            provider_snapshot_id=provider_snapshot_id,
        )
        if existing is None:
            self.session.add(record)
            self.session.flush()
        else:
            if existing.project_id != project_id:
                raise DecisionLedgerInvariantError(
                    f"Analysis evidence run {analysis_run_id} changed project identity."
                )
            if existing.provider_snapshot_id != provider_snapshot_id:
                raise DecisionLedgerInvariantError(
                    f"Analysis evidence run {analysis_run_id} changed provider snapshot identity."
                )
            return existing
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
        """Append immutable finding evidence and atomically advance current projections."""
        items = list(evidence_items)
        records: list[FindingDecisionEvidence] = []
        projection_items: list[tuple[FindingDecisionEvidence, FindingDecisionEvidenceV2]] = []
        finding_ids = [uuid.UUID(item.finding_id) for item in items]
        existing_records: dict[uuid.UUID, FindingDecisionEvidence] = {}
        unique_finding_ids = list(dict.fromkeys(finding_ids))
        for index in range(0, len(unique_finding_ids), 500):
            statement = select(FindingDecisionEvidence).where(
                FindingDecisionEvidence.analysis_run_id == analysis_run_id,
                col(FindingDecisionEvidence.finding_id).in_(
                    unique_finding_ids[index : index + 500]
                ),
            )
            for record in self.session.exec(statement).all():
                existing_records[record.finding_id] = record

        for item, finding_id in zip(items, finding_ids, strict=True):
            if item.project_id != str(project_id):
                raise DecisionLedgerInvariantError(
                    "Finding decision evidence project does not match its persistence envelope."
                )
            if item.analysis_run_id != str(analysis_run_id):
                raise DecisionLedgerInvariantError(
                    "Finding decision evidence run does not match its persistence envelope."
                )
            existing = existing_records.get(finding_id)
            payload_json = item.to_jsonable()
            if existing is not None:
                if (
                    existing.analysis_evidence_id != analysis_evidence_id
                    or existing.project_id != project_id
                    or existing.analysis_run_id != analysis_run_id
                    or existing.finding_id != finding_id
                    or existing.cve_id != item.cve_id
                    or existing.dedup_key != item.dedup_key
                    or existing.priority != item.priority
                    or existing.status != item.status
                    or existing.payload_json != payload_json
                ):
                    raise DecisionLedgerInvariantError(
                        "Finding decision evidence is immutable once persisted for a run."
                    )
                records.append(existing)
                projection_items.append((existing, item))
                continue
            record = FindingDecisionEvidence(
                analysis_evidence_id=analysis_evidence_id,
                project_id=project_id,
                analysis_run_id=analysis_run_id,
                finding_id=finding_id,
                cve_id=item.cve_id,
                dedup_key=item.dedup_key,
                priority=item.priority,
                status=item.status,
            )
            record.schema_version = FINDING_DECISION_EVIDENCE_SCHEMA_VERSION
            record.payload_json = payload_json
            self.session.add(record)
            existing_records[finding_id] = record
            records.append(record)
            projection_items.append((record, item))
        self.session.flush()
        projection_repository = FindingCurrentProjectionRepository(self.session)
        projections_by_finding_id = {
            projection.finding_id: projection
            for projection in projection_repository.records_for_findings(finding_ids)
        }
        for record, item in projection_items:
            finding_id = uuid.UUID(item.finding_id)
            projection = projection_repository.upsert_from_evidence_record(
                source_record=record,
                evidence=item,
                existing_record=projections_by_finding_id.get(finding_id),
                lookup_existing=False,
                flush=False,
            )
            projections_by_finding_id[finding_id] = projection
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
            .order_by(
                col(FindingDecisionEvidence.created_at).desc(),
                col(FindingDecisionEvidence.id).desc(),
            )
        ).first()

    def latest_finding_decision_evidence_for_findings(
        self,
        finding_ids: Iterable[uuid.UUID],
    ) -> dict[uuid.UUID, FindingDecisionEvidenceV2]:
        """Return newest evidence contracts for findings keyed by finding id."""
        ids = list(finding_ids)
        if not ids:
            return {}
        ranked = (
            select(
                col(FindingDecisionEvidence.id).label("evidence_id"),
                func.row_number()
                .over(
                    partition_by=col(FindingDecisionEvidence.finding_id),
                    order_by=(
                        col(FindingDecisionEvidence.created_at).desc(),
                        col(FindingDecisionEvidence.id).desc(),
                    ),
                )
                .label("row_number"),
            )
            .where(col(FindingDecisionEvidence.finding_id).in_(ids))
            .subquery()
        )
        rows = self.session.exec(
            select(FindingDecisionEvidence)
            .join(ranked, col(FindingDecisionEvidence.id) == ranked.c.evidence_id)
            .where(ranked.c.row_number == 1)
        ).all()
        return {
            row.finding_id: FindingDecisionEvidenceV2.model_validate(row.payload_json)
            for row in rows
        }

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
