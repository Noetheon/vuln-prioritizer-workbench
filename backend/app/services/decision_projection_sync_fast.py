"""Bounded rank convergence for immutable, governance-free current decisions."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

from sqlmodel import Session, col, select

from app.decision_core.contracts import FindingDecisionEvidenceV2
from app.decision_core.projection_evaluation import (
    _projection_scope_sort_key,
    _stored_projection_decision,
)
from app.domain.engine.services.decision_guidance import DecisionGuidanceService
from app.domain.engine.services.prioritization_ranking import global_operational_sort_key
from app.models import Finding, FindingCurrentProjection, Project
from app.models.base import get_datetime_utc
from app.repositories.current_projections import FindingCurrentProjectionRepository

_BATCH_SIZE = 250
_RANK_OVERLAY_FIELDS = {"operational_rank", "priority_evidence", "remediation"}


def sync_unchanged_project_ranks(
    session: Session,
    project_id: uuid.UUID,
    *,
    changed_finding_ids: set[uuid.UUID] | None = None,
) -> bool:
    """
    Converge ranks, or decline before writing if any scope needs evaluation.

    The caller has established that the project has no Workbench waivers and
    holds its decision lock. Only compact sort keys survive each read batch.
    All changed projections still pass the normal Ledger identity/hash checks.
    """
    missing = session.exec(
        select(Finding.id)
        .outerjoin(FindingCurrentProjection, col(FindingCurrentProjection.finding_id) == Finding.id)
        .where(Finding.project_id == project_id, col(FindingCurrentProjection.finding_id).is_(None))
        .limit(1)
    ).first()
    if missing is not None:
        return False
    repository = FindingCurrentProjectionRepository(session)
    candidates: list[tuple[tuple[Any, ...], uuid.UUID, int | None]] = []
    for records in _projection_batches(session, project_id):
        evidence_by_finding = repository.evidence_for_records(records)
        for record in records:
            evidence = evidence_by_finding[record.finding_id]
            if not _rank_only_eligible(record, evidence):
                return False
            decision = _stored_projection_decision(evidence)
            candidates.append(
                (
                    global_operational_sort_key(decision, _projection_scope_sort_key(evidence)),
                    record.finding_id,
                    evidence.operational_rank,
                )
            )
    candidates.sort(key=lambda item: (*item[0], str(item[1])))
    changed_ranks = {
        finding_id: rank
        for rank, (_, finding_id, previous_rank) in enumerate(candidates, 1)
        if rank != previous_rank
    }
    ids = list(changed_ranks)
    now = get_datetime_utc()
    for offset in range(0, len(ids), _BATCH_SIZE):
        batch_ids = ids[offset : offset + _BATCH_SIZE]
        records = repository.records_for_findings(batch_ids)
        sources = repository.source_records_for_records(records)
        evidence_by_finding = repository.evidence_for_records(records, source_records=sources)
        for record in records:
            evidence = evidence_by_finding[record.finding_id]
            payload = _with_operational_rank(evidence, changed_ranks[record.finding_id])
            source_id = record.source_finding_evidence_id
            assert source_id is not None
            repository.update_current_payload(
                record.finding_id,
                payload,
                existing_record=record,
                source_record=sources[source_id],
                flush=False,
            )
        findings = session.exec(select(Finding).where(col(Finding.id).in_(batch_ids))).all()
        for finding in findings:
            finding.updated_at = now
            session.add(finding)
        session.flush()
        if changed_finding_ids is not None:
            changed_finding_ids.update(batch_ids)
    project = session.get(Project, project_id)
    if project is not None:
        project.waiver_evaluated_on = now.date()
        session.add(project)
    session.flush()
    return True


def _projection_batches(
    session: Session, project_id: uuid.UUID
) -> Iterator[list[FindingCurrentProjection]]:
    after: uuid.UUID | None = None
    while True:
        statement = (
            select(FindingCurrentProjection)
            .where(FindingCurrentProjection.project_id == project_id)
            .order_by(col(FindingCurrentProjection.finding_id))
            .limit(_BATCH_SIZE)
        )
        if after is not None:
            statement = statement.where(col(FindingCurrentProjection.finding_id) > after)
        records = list(session.exec(statement).all())
        if not records:
            return
        yield records
        after = records[-1].finding_id


def _rank_only_eligible(
    record: FindingCurrentProjection, evidence: FindingDecisionEvidenceV2
) -> bool:
    inputs = evidence.evaluation_input
    return (
        inputs is not None
        and not inputs.waiver_rules
        and inputs.workbench_waiver is None
        and not evidence.governance.waiver
        and not evidence.waived
        and set(record.lifecycle_overlay_json or {}).issubset(_RANK_OVERLAY_FIELDS)
        and not any(
            flag.code == "asset_context_rescore_needed"
            for flag in evidence.priority_evidence.data_quality_flags
        )
    )


def _with_operational_rank(evidence: FindingDecisionEvidenceV2, rank: int) -> dict[str, Any]:
    decision = _stored_projection_decision(evidence).model_copy(update={"operational_rank": rank})
    guidance = DecisionGuidanceService().build(decision)
    guidance_payload = guidance.model_dump(mode="json")
    payload = evidence.to_jsonable()
    payload["operational_rank"] = rank
    raw = payload["priority_evidence"]["raw"]
    raw["operational_rank"] = rank
    raw["decision_guidance"] = guidance_payload
    payload["remediation"].update(
        {
            "decision_statement": guidance.decision_statement,
            "recommendation": guidance.recommendation,
            "recommendation_label": guidance.recommendation_label,
            "business_impact": guidance.business_impact.text,
            "sla": guidance.sla.model_dump(mode="json"),
            "raw": guidance_payload,
        }
    )
    return payload
