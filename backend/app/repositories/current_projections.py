"""Repository for the materialized current side of the Decision Ledger."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterable
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func
from sqlmodel import Session, col, select

from app.decision_core.contracts import FindingDecisionEvidenceV2
from app.decision_core.ledger import (
    FINDING_CURRENT_PROJECTION_SCHEMA_VERSION,
    DecisionLedgerInvariantError,
    canonical_payload_sha256,
)
from app.models import FindingCurrentProjection, FindingDecisionEvidence
from app.models.base import get_datetime_utc


@dataclass(frozen=True, slots=True)
class ProjectionParityResult:
    """Result of a bounded current-projection versus source-evidence check."""

    checked: int = 0
    mismatches: tuple[str, ...] = ()

    @property
    def matches(self) -> bool:
        """Return whether every checked projection matches its immutable source."""
        return not self.mismatches


class FindingCurrentProjectionRepository:
    """Persist and read one current projection row per finding."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def get_record(self, finding_id: uuid.UUID) -> FindingCurrentProjection | None:
        """Return the current projection row for one finding."""
        return self.session.get(FindingCurrentProjection, finding_id)

    def get_evidence(self, finding_id: uuid.UUID) -> FindingDecisionEvidenceV2 | None:
        """Return the validated effective current decision contract."""
        record = self.get_record(finding_id)
        if record is None:
            return None
        return self.evidence_for_records([record])[record.finding_id]

    def current_payload(self, finding_id: uuid.UUID) -> dict[str, Any] | None:
        """Return source evidence with the sparse lifecycle overlay applied."""
        evidence = self.get_evidence(finding_id)
        return evidence.to_jsonable() if evidence is not None else None

    def evidence_for_findings(
        self,
        finding_ids: Iterable[uuid.UUID],
    ) -> dict[uuid.UUID, FindingDecisionEvidenceV2]:
        """Return current decision contracts for a bounded finding set."""
        ids = list(dict.fromkeys(finding_ids))
        if not ids:
            return {}
        rows = self.records_for_findings(ids)
        return self.evidence_for_records(rows)

    def evidence_for_records(
        self,
        projections: Iterable[FindingCurrentProjection],
    ) -> dict[uuid.UUID, FindingDecisionEvidenceV2]:
        """Rehydrate effective contracts from immutable sources in one bounded query."""
        rows = list(projections)
        source_ids = [
            row.source_finding_evidence_id
            for row in rows
            if row.source_finding_evidence_id is not None
        ]
        sources = {
            source.id: source
            for source in self.session.exec(
                select(FindingDecisionEvidence).where(
                    col(FindingDecisionEvidence.id).in_(source_ids)
                )
            ).all()
        }
        result: dict[uuid.UUID, FindingDecisionEvidenceV2] = {}
        for projection in rows:
            source_id = projection.source_finding_evidence_id
            source = sources.get(source_id) if source_id is not None else None
            if source is None:
                raise DecisionLedgerInvariantError(
                    f"Current projection {projection.finding_id} has no immutable source."
                )
            result[projection.finding_id] = FindingDecisionEvidenceV2.model_validate(
                _effective_projection_payload(projection, source)
            )
        return result

    def records_for_findings(
        self,
        finding_ids: Iterable[uuid.UUID],
    ) -> list[FindingCurrentProjection]:
        """Return current projection records for a bounded finding set."""
        ids = list(dict.fromkeys(finding_ids))
        if not ids:
            return []
        return list(
            self.session.exec(
                select(FindingCurrentProjection).where(
                    col(FindingCurrentProjection.finding_id).in_(ids)
                )
            ).all()
        )

    def upsert_from_evidence_record(
        self,
        *,
        source_record: FindingDecisionEvidence,
        evidence: FindingDecisionEvidenceV2,
    ) -> FindingCurrentProjection:
        """Advance current state to a newer immutable per-run evidence record."""
        finding_id = uuid.UUID(evidence.finding_id)
        project_id = uuid.UUID(evidence.project_id)
        analysis_run_id = uuid.UUID(evidence.analysis_run_id)
        payload = evidence.to_jsonable()
        if source_record.finding_id != finding_id:
            raise DecisionLedgerInvariantError(
                "Projection source finding does not match the decision contract."
            )
        if source_record.project_id != project_id:
            raise DecisionLedgerInvariantError(
                "Projection source project does not match the decision contract."
            )
        if source_record.analysis_run_id != analysis_run_id:
            raise DecisionLedgerInvariantError(
                "Projection source run does not match the decision contract."
            )
        if (
            source_record.cve_id != evidence.cve_id
            or source_record.dedup_key != evidence.dedup_key
            or source_record.priority != evidence.priority
            or source_record.status != evidence.status
            or source_record.payload_json != payload
        ):
            raise DecisionLedgerInvariantError(
                "Projection source columns do not match the decision contract."
            )

        existing = self.get_record(finding_id)
        if existing is not None and existing.source_finding_evidence_id == source_record.id:
            expected_hash = canonical_payload_sha256(source_record.payload_json)
            if existing.source_payload_sha256 != expected_hash:
                raise DecisionLedgerInvariantError(
                    f"Current projection {finding_id} no longer matches its immutable source hash."
                )
            return existing
        if existing is not None and not _source_is_newer(source_record, existing):
            return existing

        source_hash = canonical_payload_sha256(source_record.payload_json)
        if canonical_payload_sha256(payload) != source_hash:
            raise DecisionLedgerInvariantError(
                "Projection contract payload differs from the persisted source evidence."
            )
        now = get_datetime_utc()
        record = existing or FindingCurrentProjection(
            finding_id=finding_id,
            project_id=project_id,
            cve_id=evidence.cve_id,
            dedup_key=evidence.dedup_key,
            priority=evidence.priority,
            status=evidence.status,
            source_payload_sha256=source_hash,
            projection_payload_sha256=source_hash,
            source_created_at=source_record.created_at,
        )
        _apply_projection_columns(record, evidence)
        record.schema_version = FINDING_CURRENT_PROJECTION_SCHEMA_VERSION
        record.project_id = project_id
        record.source_analysis_run_id = source_record.analysis_run_id
        record.source_finding_evidence_id = source_record.id
        record.source_created_at = source_record.created_at
        record.source_payload_sha256 = source_hash
        record.projection_payload_sha256 = source_hash
        record.lifecycle_overlay_json = {}
        record.lifecycle_revision = 0
        record.revision = (existing.revision + 1) if existing is not None else 1
        record.updated_at = now
        self.session.add(record)
        self.session.flush()
        return record

    def update_current_payload(
        self,
        finding_id: uuid.UUID,
        payload: dict[str, Any],
    ) -> FindingCurrentProjection | None:
        """Validate and replace mutable current state without rewriting history."""
        record = self.get_record(finding_id)
        if record is None:
            return None
        source = self._source_for_projection(record)
        source_payload = dict(source.payload_json or {})
        source_hash = canonical_payload_sha256(source_payload)
        if record.source_payload_sha256 != source_hash:
            raise DecisionLedgerInvariantError(
                f"Current projection {finding_id} no longer matches its immutable source hash."
            )
        evidence = FindingDecisionEvidenceV2.model_validate(payload)
        if uuid.UUID(evidence.finding_id) != finding_id:
            raise DecisionLedgerInvariantError(
                "Lifecycle projection payload changed the finding identity."
            )
        if uuid.UUID(evidence.project_id) != record.project_id:
            raise DecisionLedgerInvariantError(
                "Lifecycle projection payload changed the project identity."
            )
        if uuid.UUID(evidence.analysis_run_id) != source.analysis_run_id:
            raise DecisionLedgerInvariantError(
                "Lifecycle projection payload changed the source run identity."
            )
        if evidence.cve_id != source.cve_id or evidence.dedup_key != source.dedup_key:
            raise DecisionLedgerInvariantError(
                "Lifecycle projection payload changed immutable finding identity fields."
            )
        normalized = evidence.to_jsonable()
        overlay = _top_level_overlay(source_payload, normalized)
        reconstructed = _apply_top_level_overlay(source_payload, overlay)
        if reconstructed != normalized:
            raise DecisionLedgerInvariantError(
                "Lifecycle overlay could not reproduce the validated current payload."
            )
        _apply_projection_columns(record, evidence)
        record.lifecycle_overlay_json = overlay
        record.projection_payload_sha256 = canonical_payload_sha256(normalized)
        record.lifecycle_revision += 1
        record.revision += 1
        record.updated_at = get_datetime_utc()
        self.session.add(record)
        self.session.flush()
        return record

    def mutate_current_payload(
        self,
        finding_id: uuid.UUID,
        transform: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> FindingCurrentProjection | None:
        """Apply a validated lifecycle transform to current state only."""
        record = self.get_record(finding_id)
        if record is None:
            return None
        current_payload = self.current_payload(finding_id)
        if current_payload is None:  # pragma: no cover - guarded by the record lookup
            return None
        return self.update_current_payload(finding_id, transform(current_payload))

    def backfill_missing(self, *, batch_size: int = 500) -> int:
        """Backfill missing current rows from each finding's newest immutable evidence."""
        inserted = 0
        bounded_batch = max(1, min(batch_size, 2_000))
        while True:
            records = self._latest_evidence_without_projection(limit=bounded_batch)
            if not records:
                return inserted
            for source_record in records:
                evidence = FindingDecisionEvidenceV2.model_validate(source_record.payload_json)
                self.upsert_from_evidence_record(source_record=source_record, evidence=evidence)
                inserted += 1

    def verify_source_parity(
        self,
        projections: Iterable[FindingCurrentProjection],
        *,
        sample_size: int = 25,
    ) -> ProjectionParityResult:
        """Shadow-check projection provenance against immutable source rows."""
        sample = list(projections)[: max(0, sample_size)]
        source_ids = [
            row.source_finding_evidence_id
            for row in sample
            if row.source_finding_evidence_id is not None
        ]
        sources = {
            row.id: row
            for row in self.session.exec(
                select(FindingDecisionEvidence).where(
                    col(FindingDecisionEvidence.id).in_(source_ids)
                )
            ).all()
        }
        mismatches: list[str] = []
        for projection in sample:
            source_id = projection.source_finding_evidence_id
            source = sources.get(source_id) if source_id is not None else None
            if source is None:
                mismatches.append(f"{projection.finding_id}:missing-source")
                continue
            source_hash = canonical_payload_sha256(source.payload_json)
            if (
                source.finding_id != projection.finding_id
                or source.project_id != projection.project_id
                or source.analysis_run_id != projection.source_analysis_run_id
            ):
                mismatches.append(f"{projection.finding_id}:source-identity")
            if _as_utc(source.created_at) != _as_utc(projection.source_created_at):
                mismatches.append(f"{projection.finding_id}:source-created-at")
            if projection.source_payload_sha256 != source_hash:
                mismatches.append(f"{projection.finding_id}:source-hash")
            try:
                effective_payload = _effective_projection_payload(projection, source)
                projection_hash = canonical_payload_sha256(effective_payload)
                if projection.projection_payload_sha256 != projection_hash:
                    mismatches.append(f"{projection.finding_id}:projection-hash")
                if projection.lifecycle_revision == 0 and projection_hash != source_hash:
                    mismatches.append(f"{projection.finding_id}:source-projection-hash")
                evidence = FindingDecisionEvidenceV2.model_validate(effective_payload)
            except ValueError:
                mismatches.append(f"{projection.finding_id}:invalid-projection-payload")
            else:
                if not _projection_columns_match_evidence(projection, evidence):
                    mismatches.append(f"{projection.finding_id}:materialized-columns")
        return ProjectionParityResult(checked=len(sample), mismatches=tuple(mismatches))

    def _source_for_projection(
        self,
        projection: FindingCurrentProjection,
    ) -> FindingDecisionEvidence:
        source_id = projection.source_finding_evidence_id
        source = self.session.get(FindingDecisionEvidence, source_id) if source_id else None
        if source is None:
            raise DecisionLedgerInvariantError(
                f"Current projection {projection.finding_id} has no immutable source."
            )
        return source

    def verify_all_source_parity(self, *, batch_size: int = 500) -> ProjectionParityResult:
        """Verify projection coverage and parity in bounded keyset batches."""
        bounded_batch = max(1, min(batch_size, 2_000))
        history_findings = int(
            self.session.exec(
                select(func.count(func.distinct(FindingDecisionEvidence.finding_id)))
            ).one()
        )
        projection_findings = int(
            self.session.exec(select(func.count()).select_from(FindingCurrentProjection)).one()
        )
        mismatches: list[str] = []
        if history_findings != projection_findings:
            mismatches.append(
                f"coverage:history={history_findings},projection={projection_findings}"
            )

        checked = 0
        last_finding_id: uuid.UUID | None = None
        while True:
            statement = select(FindingCurrentProjection).order_by(
                col(FindingCurrentProjection.finding_id)
            )
            if last_finding_id is not None:
                statement = statement.where(
                    col(FindingCurrentProjection.finding_id) > last_finding_id
                )
            rows = list(self.session.exec(statement.limit(bounded_batch)).all())
            if not rows:
                break
            result = self.verify_source_parity(rows, sample_size=len(rows))
            checked += result.checked
            mismatches.extend(result.mismatches)
            last_finding_id = rows[-1].finding_id
        return ProjectionParityResult(checked=checked, mismatches=tuple(mismatches))

    def _latest_evidence_without_projection(
        self,
        *,
        limit: int,
    ) -> list[FindingDecisionEvidence]:
        ranked = select(
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
        ).subquery()
        statement = (
            select(FindingDecisionEvidence)
            .join(ranked, col(FindingDecisionEvidence.id) == ranked.c.evidence_id)
            .outerjoin(
                FindingCurrentProjection,
                col(FindingCurrentProjection.finding_id) == col(FindingDecisionEvidence.finding_id),
            )
            .where(
                ranked.c.row_number == 1,
                col(FindingCurrentProjection.finding_id).is_(None),
            )
            .order_by(col(FindingDecisionEvidence.finding_id))
            .limit(limit)
        )
        return list(self.session.exec(statement).all())


def projection_insert_values(
    *,
    source_record_id: uuid.UUID,
    source_created_at: Any,
    evidence: FindingDecisionEvidenceV2,
    source_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build insert values for the bulk import dual-write path."""
    payload = source_payload or evidence.to_jsonable()
    payload_hash = canonical_payload_sha256(payload)
    now = get_datetime_utc()
    return {
        "finding_id": uuid.UUID(evidence.finding_id),
        "project_id": uuid.UUID(evidence.project_id),
        "source_analysis_run_id": uuid.UUID(evidence.analysis_run_id),
        "source_finding_evidence_id": source_record_id,
        "source_created_at": source_created_at,
        "schema_version": FINDING_CURRENT_PROJECTION_SCHEMA_VERSION,
        "cve_id": evidence.cve_id,
        "dedup_key": evidence.dedup_key,
        "priority": evidence.priority,
        "status": evidence.status,
        "priority_rank": evidence.priority_rank,
        "risk_score": evidence.risk_score,
        "operational_rank": evidence.operational_rank,
        "in_kev": evidence.in_kev,
        "epss": evidence.epss,
        "cvss_base_score": evidence.cvss_base_score,
        "attack_mapped": evidence.attack_mapped,
        "suppressed_by_vex": evidence.suppressed_by_vex,
        "under_investigation": evidence.under_investigation,
        "waived": evidence.waived,
        "rationale": evidence.rationale,
        "recommended_action": evidence.recommended_action,
        "lifecycle_overlay_json": {},
        "source_payload_sha256": payload_hash,
        "projection_payload_sha256": payload_hash,
        "revision": 1,
        "lifecycle_revision": 0,
        "created_at": now,
        "updated_at": now,
    }


def _apply_projection_columns(
    record: FindingCurrentProjection,
    evidence: FindingDecisionEvidenceV2,
) -> None:
    record.cve_id = evidence.cve_id
    record.dedup_key = evidence.dedup_key
    record.priority = evidence.priority
    record.status = evidence.status
    record.priority_rank = evidence.priority_rank
    record.risk_score = evidence.risk_score
    record.operational_rank = evidence.operational_rank
    record.in_kev = evidence.in_kev
    record.epss = evidence.epss
    record.cvss_base_score = evidence.cvss_base_score
    record.attack_mapped = evidence.attack_mapped
    record.suppressed_by_vex = evidence.suppressed_by_vex
    record.under_investigation = evidence.under_investigation
    record.waived = evidence.waived
    record.rationale = evidence.rationale
    record.recommended_action = evidence.recommended_action


def _effective_projection_payload(
    projection: FindingCurrentProjection,
    source: FindingDecisionEvidence,
) -> dict[str, Any]:
    if source.finding_id != projection.finding_id:
        raise ValueError("Projection source finding identity mismatch.")
    if source.project_id != projection.project_id:
        raise ValueError("Projection source project identity mismatch.")
    if source.analysis_run_id != projection.source_analysis_run_id:
        raise ValueError("Projection source run identity mismatch.")
    return _apply_top_level_overlay(
        dict(source.payload_json or {}),
        dict(projection.lifecycle_overlay_json or {}),
    )


def _top_level_overlay(
    source_payload: dict[str, Any],
    effective_payload: dict[str, Any],
) -> dict[str, Any]:
    """Return only changed top-level contract fields, preserving explicit nulls."""
    missing = object()
    return {
        key: deepcopy(value)
        for key, value in effective_payload.items()
        if source_payload.get(key, missing) != value
    }


def _apply_top_level_overlay(
    source_payload: dict[str, Any],
    overlay: dict[str, Any],
) -> dict[str, Any]:
    result = deepcopy(source_payload)
    for key, value in overlay.items():
        result[key] = deepcopy(value)
    return result


def _projection_columns_match_evidence(
    projection: FindingCurrentProjection,
    evidence: FindingDecisionEvidenceV2,
) -> bool:
    """Return whether query columns faithfully materialize the validated payload."""
    return (
        projection.finding_id == uuid.UUID(evidence.finding_id)
        and projection.project_id == uuid.UUID(evidence.project_id)
        and projection.source_analysis_run_id == uuid.UUID(evidence.analysis_run_id)
        and projection.cve_id == evidence.cve_id
        and projection.dedup_key == evidence.dedup_key
        and projection.priority == evidence.priority
        and projection.status == evidence.status
        and projection.priority_rank == evidence.priority_rank
        and projection.risk_score == evidence.risk_score
        and projection.operational_rank == evidence.operational_rank
        and projection.in_kev == evidence.in_kev
        and projection.epss == evidence.epss
        and projection.cvss_base_score == evidence.cvss_base_score
        and projection.attack_mapped == evidence.attack_mapped
        and projection.suppressed_by_vex == evidence.suppressed_by_vex
        and projection.under_investigation == evidence.under_investigation
        and projection.waived == evidence.waived
        and projection.rationale == evidence.rationale
        and projection.recommended_action == evidence.recommended_action
    )


def _source_is_newer(
    source: FindingDecisionEvidence,
    current: FindingCurrentProjection,
) -> bool:
    source_key = (_as_utc(source.created_at), str(source.id))
    current_key = (
        _as_utc(current.source_created_at),
        str(current.source_finding_evidence_id or ""),
    )
    return source_key > current_key


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
