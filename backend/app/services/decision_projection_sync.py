"""Evaluate changed governance inputs, then converge the compact project queue."""

from __future__ import annotations

import uuid
from datetime import date
from typing import Any

from sqlmodel import Session

from app.decision_core.contracts import FindingDecisionEvidenceV2
from app.decision_core.current_queue import with_current_rank
from app.decision_core.governance_state import governance_sync_state
from app.decision_core.projection_evaluation import (
    _apply_recomputed_decision,
    _projection_scope_sort_key,
    _recompute_projection_decision,
)
from app.domain.engine.services.decision_guidance import DecisionGuidanceService
from app.domain.engine.services.prioritization_ranking import global_operational_sort_key
from app.models import FindingCurrentProjection, FindingStatus, Project, Waiver
from app.models.base import get_datetime_utc
from app.repositories.current_projections import FindingCurrentProjectionRepository
from app.repositories.waivers import (
    WaiverRepository,
    _apply_effective_waiver,
    _restore_source_waiver_state,
    _selected_waiver,
    _waiver_selection_sort_key,
    waiver_scope_label,
    workbench_waiver_rule,
)
from app.services.decision_projection_sync_fast import sync_unchanged_project_ranks


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
    """
    Hydrate changed scopes once; rank-only peers never become new revisions.

    ``force`` remains an accepted caller hint, but invalidation state now decides
    which scopes need evaluation. Even a forced pass reuses unchanged decisions.
    The caller holds the project publication fence and owns the transaction.
    """
    session = repository.session
    now = get_datetime_utc()
    evaluated_on = now.date()
    waivers = sorted(
        repository.list_project_waivers(project_id),
        key=lambda item: _waiver_selection_sort_key(item, today=evaluated_on),
    )
    matched_counts: dict[uuid.UUID, int] = {waiver.id: 0 for waiver in waivers}
    projection_repository = FindingCurrentProjectionRepository(session)
    revision_payloads: dict[uuid.UUID, dict[str, Any]] = {}
    fallback_keys: dict[uuid.UUID, list[Any]] = {}
    after: uuid.UUID | None = None
    while True:
        findings = repository._project_findings_batch(project_id, after_finding_id=after)
        if not findings:
            break
        projections = {
            row.finding_id: row
            for row in projection_repository.records_for_findings(item.id for item in findings)
        }
        selected = {finding.id: _selected_waiver(waivers, finding) for finding in findings}
        affected = []
        for finding in findings:
            waiver = selected[finding.id]
            if waiver is not None:
                matched_counts[waiver.id] += 1
            projection = projections.get(finding.id)
            if projection is None:
                previous_status = FindingStatus(finding.status)
                repository._sync_finding_status_without_projection(
                    finding, waiver, today=evaluated_on
                )
                if changed_finding_ids is not None and finding.status != previous_status:
                    changed_finding_ids.add(finding.id)
            elif _needs_evaluation(projection, waiver, today=evaluated_on):
                affected.append(finding)
        if affected:
            records, sources, current_by_id, source_by_id = repository._projection_batch_state(
                projection_repository, affected
            )
            for finding in affected:
                current = current_by_id[finding.id]
                projection = records[finding.id]
                original = current.to_jsonable()
                payload = _restore_source_waiver_state(
                    original, source_evidence=source_by_id[finding.id]
                )
                payload = _apply_effective_waiver(payload, selected[finding.id], today=evaluated_on)
                unchanged_inputs = (
                    current.evaluation_input is not None
                    and current.evaluation is not None
                    and current.evaluation.input_sha256 == current.evaluation_input.fingerprint()
                    and payload.get("evaluation_input")
                    == current.evaluation_input.model_dump(mode="json")
                    and payload == original
                )
                if unchanged_inputs and projection.operational_sort_key_json is not None:
                    # A migrated row can lack its compact state while its decision
                    # is already current. Backfill metadata without a new revision.
                    projection.governance_sync_json = governance_sync_state(current)
                    session.add(projection)
                    continue
                decision = _recompute_projection_decision(payload).model_copy(
                    update={"operational_rank": current.operational_rank}
                )
                decision = decision.model_copy(
                    update={"decision_guidance": DecisionGuidanceService().build(decision)}
                )
                updated = _apply_recomputed_decision(payload, decision)
                if current.evaluation_input is not None and current.evaluation is not None:
                    inputs = FindingDecisionEvidenceV2.model_validate(updated).evaluation_input
                    assert inputs is not None
                    updated["evaluation"] = current.evaluation.model_copy(
                        update={
                            "input_sha256": inputs.fingerprint(),
                            "evaluated_at": now.isoformat(),
                            "cause": revision_cause or "import",
                        }
                    ).model_dump(mode="json")
                fallback_keys[finding.id] = list(
                    global_operational_sort_key(decision, _projection_scope_sort_key(current))
                )
                if updated == original:
                    continue
                source_id = projection.source_finding_evidence_id
                assert source_id is not None  # batch hydration verifies the immutable source
                projection_repository.update_current_payload(
                    finding.id,
                    updated,
                    existing_record=projection,
                    source_record=sources[source_id],
                    flush=False,
                )
                finding.status = FindingStatus(str(updated["status"]))
                finding.updated_at = now
                session.add(finding)
                if revision_cause is not None and current.evaluation_input is not None:
                    revision_payloads[finding.id] = updated
                if changed_finding_ids is not None:
                    changed_finding_ids.add(finding.id)
        session.flush()
        after = findings[-1].id

    if not sync_unchanged_project_ranks(
        session,
        project_id,
        changed_finding_ids=changed_finding_ids,
        fallback_keys=fallback_keys,
        require_complete=False,
    ):  # pragma: no cover - every missing key was evaluated above
        raise RuntimeError("A current decision has no canonical queue key after synchronization.")
    if revision_payloads:
        from app.services.evaluation_publication import publish_evaluation_run

        ranks = {
            record.finding_id: record.operational_rank
            for record in projection_repository.records_for_findings(revision_payloads)
        }
        publish_evaluation_run(
            session,
            project_id=project_id,
            payloads={
                key: with_current_rank(value, ranks[key])
                for key, value in revision_payloads.items()
            },
            cause=revision_cause or "governance",
        )
    project = session.get(Project, project_id)
    if project is not None:
        project.waiver_evaluated_on = evaluated_on
        session.add(project)
    session.flush()
    return matched_counts


def _needs_evaluation(
    projection: FindingCurrentProjection, waiver: Waiver | None, *, today: date
) -> bool:
    state = projection.governance_sync_json
    if state is None or projection.operational_sort_key_json is None:
        return True
    override = workbench_waiver_rule(waiver, cve_id=projection.cve_id)
    return (
        state.get("workbench_waiver") != (override.model_dump(mode="json") if override else None)
        or state.get("scope") != (waiver_scope_label(waiver) if waiver else None)
        or (
            (bool(state.get("source_rules")) or override is not None)
            and state.get("evaluation_date") != today.isoformat()
        )
    )
