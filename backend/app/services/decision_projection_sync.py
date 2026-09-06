"""Coordinate complete scope evaluation and bounded project ranking."""

from __future__ import annotations

import uuid
from typing import Any

from sqlmodel import Session, col, select

from app.decision_core.ledger import DecisionLedgerInvariantError
from app.decision_core.projection_evaluation import (
    _apply_recomputed_decision,
    _projection_scope_sort_key,
    _recompute_projection_decision,
    _stored_projection_decision,
)
from app.domain.engine.services.decision_guidance import DecisionGuidanceService
from app.domain.engine.services.prioritization_ranking import global_operational_sort_key
from app.models import FindingCurrentProjection, FindingStatus, Project
from app.models.base import get_datetime_utc
from app.repositories.current_projections import FindingCurrentProjectionRepository
from app.repositories.waivers import (
    WaiverRepository,
    _apply_effective_waiver,
    _ProjectionRankCandidate,
    _restore_source_waiver_state,
    _selected_waiver,
    _waiver_selection_sort_key,
)


class DecisionProjectionService:
    """Application-level governance evaluation; repositories only persist data."""

    def __init__(self, session: Session) -> None:
        self.repository = WaiverRepository(session)

    def sync_project_waivers(
        self,
        project_id: uuid.UUID,
        *,
        force: bool = False,
        changed_finding_ids: set[uuid.UUID] | None = None,
        revision_cause: str | None = None,
    ) -> dict[uuid.UUID, int]:
        """Reevaluate affected decisions and converge their project ranks."""
        return sync_project_decisions(
            self.repository,
            project_id,
            force=force,
            changed_finding_ids=changed_finding_ids,
            revision_cause=revision_cause,
        )


def sync_project_decisions(
    repository: WaiverRepository,
    project_id: uuid.UUID,
    *,
    force: bool = False,
    changed_finding_ids: set[uuid.UUID] | None = None,
    revision_cause: str | None = None,
) -> dict[uuid.UUID, int]:
    """Apply waiver state and rebuild the queue in bounded evidence batches."""
    revision_payloads: dict[uuid.UUID, dict[str, Any]] = {}
    evaluated_on = get_datetime_utc().date()
    waivers = repository.list_project_waivers(project_id)
    matched_counts: dict[uuid.UUID, int] = {waiver.id: 0 for waiver in waivers}
    if not waivers and not force:
        source_acceptance = repository.session.exec(
            select(FindingCurrentProjection.finding_id)
            .where(
                FindingCurrentProjection.project_id == project_id,
                col(FindingCurrentProjection.waived).is_(True),
            )
            .limit(1)
        ).first()
        if source_acceptance is None:
            return matched_counts
    if not waivers and revision_cause is None:
        from app.services.decision_projection_sync_fast import sync_unchanged_project_ranks

        if sync_unchanged_project_ranks(
            repository.session, project_id, changed_finding_ids=changed_finding_ids
        ):
            return matched_counts
    ordered_waivers = sorted(
        waivers,
        key=lambda item: _waiver_selection_sort_key(item, today=evaluated_on),
    )
    projection_repository = FindingCurrentProjectionRepository(repository.session)
    candidates: list[_ProjectionRankCandidate] = []
    last_finding_id: uuid.UUID | None = None
    while True:
        findings = repository._project_findings_batch(
            project_id,
            after_finding_id=last_finding_id,
        )
        if not findings:
            break
        (
            _projection_records,
            _source_records,
            current_evidence,
            source_evidence,
        ) = repository._projection_batch_state(projection_repository, findings)
        for finding in findings:
            waiver = _selected_waiver(ordered_waivers, finding)
            if waiver is not None:
                matched_counts[waiver.id] = matched_counts.get(waiver.id, 0) + 1
            current = current_evidence.get(finding.id)
            if current is None:
                previous_status = FindingStatus(finding.status)
                repository._sync_finding_status_without_projection(
                    finding,
                    waiver,
                    today=evaluated_on,
                )
                if changed_finding_ids is not None and finding.status != previous_status:
                    changed_finding_ids.add(finding.id)
                continue
            payload = _restore_source_waiver_state(
                current.to_jsonable(),
                source_evidence=source_evidence[finding.id],
            )
            payload = _apply_effective_waiver(payload, waiver, today=evaluated_on)
            unchanged_inputs = (
                current.evaluation_input is not None
                and current.evaluation is not None
                and current.evaluation.input_sha256 == current.evaluation_input.fingerprint()
                and payload.get("evaluation_input")
                == current.evaluation_input.model_dump(mode="json")
                and payload.get("waived", False) == current.waived
            )
            decision = (
                _stored_projection_decision(current)
                if unchanged_inputs
                else _recompute_projection_decision(payload)
            )
            candidates.append(
                _ProjectionRankCandidate(
                    finding_id=finding.id,
                    sort_key=global_operational_sort_key(
                        decision,
                        _projection_scope_sort_key(current),
                    ),
                )
            )
        repository.session.flush()
        last_finding_id = findings[-1].id

    ordered = sorted(
        candidates,
        # The UUID is only a corruption-safe fallback for duplicate scopes;
        # valid projects are fully ordered by the canonical scope key.
        key=lambda item: (*item.sort_key, str(item.finding_id)),
    )
    rank_by_finding_id = {
        item.finding_id: operational_rank for operational_rank, item in enumerate(ordered, start=1)
    }
    guidance_service = DecisionGuidanceService()
    last_finding_id = None
    while True:
        findings = repository._project_findings_batch(
            project_id,
            after_finding_id=last_finding_id,
        )
        if not findings:
            break
        (
            projection_records,
            source_records,
            current_evidence,
            source_evidence,
        ) = repository._projection_batch_state(projection_repository, findings)
        for finding in findings:
            current = current_evidence.get(finding.id)
            projection = projection_records.get(finding.id)
            if current is None or projection is None:
                continue
            original_payload = current.to_jsonable()
            payload = _restore_source_waiver_state(
                original_payload,
                source_evidence=source_evidence[finding.id],
            )
            payload = _apply_effective_waiver(
                payload,
                _selected_waiver(ordered_waivers, finding),
                today=evaluated_on,
            )
            unchanged_inputs = (
                current.evaluation_input is not None
                and current.evaluation is not None
                and current.evaluation.input_sha256 == current.evaluation_input.fingerprint()
                and payload.get("evaluation_input")
                == current.evaluation_input.model_dump(mode="json")
                and payload.get("waived", False) == current.waived
            )
            decision = (
                _stored_projection_decision(current)
                if unchanged_inputs
                else _recompute_projection_decision(payload)
            )
            if (
                unchanged_inputs
                and rank_by_finding_id[finding.id] == current.operational_rank
                and payload == original_payload
            ):
                continue
            ranked = decision.model_copy(
                update={"operational_rank": rank_by_finding_id[finding.id]}
            )
            ranked = ranked.model_copy(update={"decision_guidance": guidance_service.build(ranked)})
            updated_payload = _apply_recomputed_decision(payload, ranked)
            finding.status = FindingStatus(str(updated_payload["status"]))
            if updated_payload != original_payload:
                source_id = projection.source_finding_evidence_id
                source_record = source_records.get(source_id) if source_id is not None else None
                if source_record is None:  # pragma: no cover - validated by batch hydration
                    raise DecisionLedgerInvariantError(
                        f"Current projection {finding.id} has no immutable source."
                    )
                projection_repository.update_current_payload(
                    finding.id,
                    updated_payload,
                    existing_record=projection,
                    source_record=source_record,
                    flush=False,
                )
                finding.updated_at = get_datetime_utc()
                if revision_cause is not None and current.evaluation_input is not None:
                    revision_payloads[finding.id] = updated_payload
                if changed_finding_ids is not None:
                    changed_finding_ids.add(finding.id)
            repository.session.add(finding)
        repository.session.flush()
        last_finding_id = findings[-1].id

    project = repository.session.get(Project, project_id)
    if project is not None:
        project.waiver_evaluated_on = evaluated_on
        repository.session.add(project)
    repository.session.flush()
    if revision_payloads:
        from app.services.evaluation_publication import publish_evaluation_run

        publish_evaluation_run(
            repository.session,
            project_id=project_id,
            payloads=revision_payloads,
            cause=revision_cause or "governance",
        )
    return matched_counts
