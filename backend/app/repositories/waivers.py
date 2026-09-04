"""Persisted waiver/risk-acceptance repository for the Workbench."""

from __future__ import annotations

import unicodedata
import uuid
from copy import deepcopy
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any, cast

from pydantic import ValidationError
from sqlalchemy import case
from sqlalchemy.orm import QueryableAttribute, selectinload
from sqlmodel import Session, col, func, select

from app.decision_core.contracts import (
    FindingDecisionEvidenceV2,
    OccurrenceEvidenceV2,
    OccurrenceScopeV2,
)
from app.decision_core.decision_graph import ScopeKey
from app.decision_core.ledger import DecisionLedgerInvariantError
from app.domain.asset_identity import normalize_asset_identity_value
from app.domain.engine.models import (
    FindingProvenance,
    InputOccurrence,
    PrioritizedFinding,
    ProviderEvidence,
)
from app.domain.engine.services.contextualization import (
    SUPPRESSED_VEX_STATUSES,
    aggregate_provenance,
    is_suppressed_by_vex,
    is_under_investigation,
)
from app.domain.engine.services.decision_guidance import DecisionGuidanceService
from app.domain.engine.services.prioritization import PrioritizationService
from app.domain.engine.services.prioritization_ranking import global_operational_sort_key
from app.models import (
    Finding,
    FindingCurrentProjection,
    FindingDecisionEvidence,
    FindingStatus,
    Project,
    Waiver,
    WaiverCreate,
    WaiverUpdate,
)
from app.models.base import get_datetime_utc
from app.repositories.current_projections import FindingCurrentProjectionRepository

_WAIVER_DECISION_FIELDS = (
    "waiver",
    "waived",
    "waiver_status",
    "waiver_owner",
    "waiver_reason",
    "waiver_expires_on",
    "waiver_review_on",
    "waiver_days_remaining",
    "waiver_scope",
    "waiver_id",
    "waiver_matched_scope",
    "waiver_approval_ref",
    "waiver_ticket_url",
)

_PROJECTION_SYNC_BATCH_SIZE = 250


@dataclass(frozen=True, slots=True)
class _ProjectionRankCandidate:
    """Compact global-order material retained between bounded passes."""

    finding_id: uuid.UUID
    sort_key: tuple[Any, ...]


class WaiverRepository:
    """Waiver persistence plus finding synchronization."""

    def __init__(self, session: Session) -> None:
        """Initialize a new instance of WaiverRepository."""
        self.session = session

    def list_project_waivers(
        self,
        project_id: uuid.UUID,
        *,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Waiver]:
        """Return project waivers in stable expiry order."""
        statement = (
            select(Waiver)
            .where(Waiver.project_id == project_id)
            .order_by(col(Waiver.expires_at), col(Waiver.created_at))
            .offset(offset)
        )
        if limit is not None:
            statement = statement.limit(limit)
        return list(self.session.exec(statement).all())

    def list_project_waivers_page(
        self,
        project_id: uuid.UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[Waiver], int]:
        """Return a bounded waiver page and total count."""
        count_statement = (
            select(func.count()).select_from(Waiver).where(Waiver.project_id == project_id)
        )
        count = int(self.session.exec(count_statement).one())
        return self.list_project_waivers(project_id, limit=limit, offset=offset), count

    def list_project_waiver_debt_items(
        self,
        project_id: uuid.UUID,
        *,
        limit: int,
    ) -> list[Waiver]:
        """Return the highest-priority waiver debt rows for governance rollups."""
        today = get_datetime_utc().date()
        review_due_cutoff = today + timedelta(days=14)
        expires_at = col(Waiver.expires_at)
        review_at = col(Waiver.review_at)
        status_rank = case(
            (expires_at < today, 0),
            (review_at <= today, 1),
            (expires_at <= review_due_cutoff, 1),
            else_=2,
        )
        statement = (
            select(Waiver)
            .where(Waiver.project_id == project_id)
            .order_by(status_rank, col(Waiver.expires_at), col(Waiver.owner))
            .limit(limit)
        )
        return list(self.session.exec(statement).all())

    def project_waiver_lifecycle_summary(self, project_id: uuid.UUID) -> dict[str, Any]:
        """Return waiver lifecycle counts without loading full waiver rows."""
        today = get_datetime_utc().date()
        review_due_cutoff = today + timedelta(days=14)
        expires_at = col(Waiver.expires_at)
        review_at = col(Waiver.review_at)
        columns: list[Any] = [
            func.sum(
                _case_int(
                    (expires_at >= today)
                    & (
                        (review_at.is_(None) | (review_at > today))
                        & (expires_at > review_due_cutoff)
                    )
                )
            ),
            func.sum(
                _case_int(
                    (expires_at >= today)
                    & ((review_at <= today) | (expires_at <= review_due_cutoff))
                )
            ),
            func.sum(_case_int(expires_at < today)),
            func.sum(_case_int((expires_at >= today) & (expires_at <= review_due_cutoff))),
            func.count(),
        ]
        active_count, review_due_count, expired_count, expiring_soon_count, total = (
            self.session.exec(
                select(*columns).select_from(Waiver).where(Waiver.project_id == project_id)
            ).one()
        )
        return {
            "waiver_count": int(total or 0),
            "active_count": int(active_count or 0),
            "review_due_count": int(review_due_count or 0),
            "expired_count": int(expired_count or 0),
            "expiring_soon_count": int(expiring_soon_count or 0),
            "owner_counts": self._waiver_group_counts(project_id, Waiver.owner),
            "service_counts": self._waiver_group_counts(project_id, Waiver.service),
        }

    def _waiver_group_counts(self, project_id: uuid.UUID, column: Any) -> dict[str, int]:
        statement = (
            select(column, func.count())
            .select_from(Waiver)
            .where(Waiver.project_id == project_id, column.is_not(None), column != "")
            .group_by(column)
            .order_by(column)
        )
        return {str(label): int(count) for label, count in self.session.exec(statement).all()}

    def get_waiver(self, waiver_id: uuid.UUID) -> Waiver | None:
        """Return a waiver by primary key."""
        return self.session.get(Waiver, waiver_id)

    def create_project_waiver(
        self,
        *,
        project_id: uuid.UUID,
        waiver_in: WaiverCreate,
    ) -> Waiver:
        """Create a waiver without committing the transaction."""
        waiver = Waiver(project_id=project_id, **_waiver_model_data(waiver_in))
        self.session.add(waiver)
        self.session.flush()
        return waiver

    def update_waiver(self, waiver: Waiver, waiver_in: WaiverUpdate) -> Waiver:
        """Replace a waiver's scope and governance fields."""
        waiver.sqlmodel_update(_waiver_model_data(waiver_in))
        waiver.updated_at = get_datetime_utc()
        self.session.add(waiver)
        self.session.flush()
        return waiver

    def expire_waiver(self, waiver: Waiver) -> Waiver:
        """Expire a waiver deterministically so lifecycle status becomes expired."""
        expired_at = get_datetime_utc().date() - timedelta(days=1)
        waiver.expires_at = expired_at
        if waiver.review_at is not None and waiver.review_at > expired_at:
            waiver.review_at = expired_at
        waiver.updated_at = get_datetime_utc()
        self.session.add(waiver)
        self.session.flush()
        return waiver

    def delete_waiver(self, waiver: Waiver) -> None:
        """Delete a waiver without committing the surrounding transaction."""
        self.session.delete(waiver)
        self.session.flush()

    def sync_project_waivers(
        self,
        project_id: uuid.UUID,
        *,
        force: bool = False,
        changed_finding_ids: set[uuid.UUID] | None = None,
    ) -> dict[uuid.UUID, int]:
        """Apply waiver state and rebuild the queue in bounded evidence batches."""
        evaluated_on = get_datetime_utc().date()
        waivers = self.list_project_waivers(project_id)
        matched_counts: dict[uuid.UUID, int] = {waiver.id: 0 for waiver in waivers}
        if not waivers and not force:
            return matched_counts
        ordered_waivers = sorted(
            waivers,
            key=lambda item: _waiver_selection_sort_key(item, today=evaluated_on),
        )
        projection_repository = FindingCurrentProjectionRepository(self.session)
        candidates: list[_ProjectionRankCandidate] = []
        last_finding_id: uuid.UUID | None = None
        while True:
            findings = self._project_findings_batch(
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
            ) = self._projection_batch_state(projection_repository, findings)
            for finding in findings:
                waiver = _selected_waiver(ordered_waivers, finding)
                if waiver is not None:
                    matched_counts[waiver.id] = matched_counts.get(waiver.id, 0) + 1
                current = current_evidence.get(finding.id)
                if current is None:
                    previous_status = FindingStatus(finding.status)
                    self._sync_finding_status_without_projection(
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
                decision = _recompute_projection_decision(payload)
                candidates.append(
                    _ProjectionRankCandidate(
                        finding_id=finding.id,
                        sort_key=global_operational_sort_key(
                            decision,
                            _projection_scope_sort_key(current),
                        ),
                    )
                )
            self.session.flush()
            last_finding_id = findings[-1].id

        ordered = sorted(
            candidates,
            # The UUID is only a corruption-safe fallback for duplicate scopes;
            # valid projects are fully ordered by the canonical scope key.
            key=lambda item: (*item.sort_key, str(item.finding_id)),
        )
        rank_by_finding_id = {
            item.finding_id: operational_rank
            for operational_rank, item in enumerate(ordered, start=1)
        }
        guidance_service = DecisionGuidanceService()
        last_finding_id = None
        while True:
            findings = self._project_findings_batch(
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
            ) = self._projection_batch_state(projection_repository, findings)
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
                decision = _recompute_projection_decision(payload)
                ranked = decision.model_copy(
                    update={"operational_rank": rank_by_finding_id[finding.id]}
                )
                ranked = ranked.model_copy(
                    update={"decision_guidance": guidance_service.build(ranked)}
                )
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
                    if changed_finding_ids is not None:
                        changed_finding_ids.add(finding.id)
                self.session.add(finding)
            self.session.flush()
            last_finding_id = findings[-1].id

        project = self.session.get(Project, project_id)
        if project is not None:
            project.waiver_evaluated_on = evaluated_on
            self.session.add(project)
        self.session.flush()
        return matched_counts

    def matching_finding_count(self, waiver: Waiver) -> int:
        """Count project findings with the exact effective matcher semantics."""
        return self.matching_finding_counts([waiver]).get(waiver.id, 0)

    def matching_finding_counts(self, waivers: list[Waiver]) -> dict[uuid.UUID, int]:
        """Count a page of waivers from one batched finding/asset snapshot."""
        if not waivers:
            return {}
        project_ids = {waiver.project_id for waiver in waivers}
        if len(project_ids) != 1:
            raise ValueError("Waiver match counts require one project scope.")
        findings = self._project_findings(next(iter(project_ids)))
        return {
            waiver.id: sum(_waiver_matches_finding(waiver, finding) for finding in findings)
            for waiver in waivers
        }

    def _project_findings(self, project_id: uuid.UUID) -> list[Finding]:
        """Project findings method for WaiverRepository."""
        asset_relationship = cast(QueryableAttribute[Any], Finding.asset)
        statement = (
            select(Finding)
            .options(selectinload(asset_relationship))
            .where(Finding.project_id == project_id)
            .order_by(Finding.cve_id, col(Finding.id))
        )
        return list(self.session.exec(statement).all())

    def _project_findings_batch(
        self,
        project_id: uuid.UUID,
        *,
        after_finding_id: uuid.UUID | None,
    ) -> list[Finding]:
        """Load one stable, asset-hydrated project batch for queue convergence."""
        asset_relationship = cast(QueryableAttribute[Any], Finding.asset)
        statement = (
            select(Finding)
            .options(selectinload(asset_relationship))
            .where(Finding.project_id == project_id)
            .order_by(col(Finding.id))
            .limit(_PROJECTION_SYNC_BATCH_SIZE)
        )
        if after_finding_id is not None:
            statement = statement.where(col(Finding.id) > after_finding_id)
        return list(self.session.exec(statement).all())

    def _projection_batch_state(
        self,
        projection_repository: FindingCurrentProjectionRepository,
        findings: list[Finding],
    ) -> tuple[
        dict[uuid.UUID, FindingCurrentProjection],
        dict[uuid.UUID, FindingDecisionEvidence],
        dict[uuid.UUID, FindingDecisionEvidenceV2],
        dict[uuid.UUID, FindingDecisionEvidenceV2],
    ]:
        """Hydrate current and immutable evidence for one bounded finding batch."""
        records = projection_repository.records_for_findings(finding.id for finding in findings)
        records_by_finding = {record.finding_id: record for record in records}
        source_records = projection_repository.source_records_for_records(records)
        current_evidence = projection_repository.evidence_for_records(
            records,
            source_records=source_records,
        )
        source_evidence = {
            record.finding_id: FindingDecisionEvidenceV2.model_validate(
                source_records[record.source_finding_evidence_id].payload_json
            )
            for record in records
            if record.source_finding_evidence_id in source_records
        }
        return records_by_finding, source_records, current_evidence, source_evidence

    def _sync_finding_status_without_projection(
        self,
        finding: Finding,
        waiver: Waiver | None,
        *,
        today: date,
    ) -> None:
        status = waiver_lifecycle_status(waiver, today=today)[0] if waiver is not None else None
        current_status = FindingStatus(finding.status)
        if status in {"active", "review_due"} and current_status not in {
            FindingStatus.FIXED,
            FindingStatus.SUPPRESSED,
        }:
            finding.status = FindingStatus.ACCEPTED
        elif current_status == FindingStatus.ACCEPTED:
            finding.status = FindingStatus.OPEN
        finding.updated_at = get_datetime_utc()
        self.session.add(finding)


def _restore_source_waiver_state(
    payload: dict[str, Any],
    *,
    source_evidence: FindingDecisionEvidenceV2,
) -> dict[str, Any]:
    """Remove only the Workbench waiver overlay and restore immutable source state."""
    restored = deepcopy(payload)
    priority_evidence = _object_value(restored.get("priority_evidence"))
    raw = _object_value(priority_evidence.get("raw"))
    governance = _object_value(restored.get("governance"))
    current_waiver = _object_value(governance.get("waiver") or raw.get("waiver"))
    if current_waiver.get("source") != "workbench-api":
        return restored

    source_payload = source_evidence.to_jsonable()
    source_priority = _object_value(source_payload.get("priority_evidence"))
    source_raw = _object_value(source_priority.get("raw"))
    source_governance = _object_value(source_payload.get("governance"))
    for key in _WAIVER_DECISION_FIELDS:
        if key in source_raw:
            raw[key] = deepcopy(source_raw[key])
        else:
            raw.pop(key, None)

    governance["waiver"] = deepcopy(source_governance.get("waiver") or {})
    governance["waived"] = source_evidence.waived
    restored["waived"] = source_evidence.waived
    restored["status"] = _restored_status(current_waiver, source_evidence.status)
    raw["waived"] = source_evidence.waived
    priority_evidence["raw"] = raw
    restored["priority_evidence"] = priority_evidence
    restored["governance"] = governance
    return restored


def _restored_status(waiver_payload: dict[str, Any], source_status: str) -> str:
    previous_status = waiver_payload.get("previous_status")
    try:
        return FindingStatus(str(previous_status)).value
    except ValueError:
        return FindingStatus(source_status).value


def _apply_effective_waiver(
    payload: dict[str, Any],
    waiver: Waiver | None,
    *,
    today: date,
) -> dict[str, Any]:
    """Overlay the selected Workbench waiver on one current decision payload."""
    updated = deepcopy(payload)
    if waiver is None:
        return updated

    priority_evidence = _object_value(updated.get("priority_evidence"))
    raw = _object_value(priority_evidence.get("raw"))
    governance = _object_value(updated.get("governance"))
    status, days_remaining = waiver_lifecycle_status(waiver, today=today)
    scope = waiver_scope_label(waiver)
    waived = status in {"active", "review_due"}
    previous_status = _finding_status_value(updated.get("status"))
    waiver_payload = {
        "source": "workbench-api",
        "waiver_id": str(waiver.id),
        "waiver_status": status,
        "waiver_reason": waiver.reason,
        "waiver_owner": waiver.owner,
        "waiver_expires_on": waiver.expires_at.isoformat(),
        "waiver_review_on": waiver.review_at.isoformat() if waiver.review_at else None,
        "waiver_days_remaining": days_remaining,
        "waiver_scope": scope,
        "waiver_approval_ref": waiver.approval_ref,
        "waiver_ticket_url": waiver.ticket_url,
        "previous_status": previous_status,
    }
    raw.update(
        {
            "waiver": waiver_payload,
            "waived": waived,
            "waiver_id": str(waiver.id),
            "waiver_status": status,
            "waiver_reason": waiver.reason,
            "waiver_owner": waiver.owner,
            "waiver_expires_on": waiver.expires_at.isoformat(),
            "waiver_review_on": waiver.review_at.isoformat() if waiver.review_at else None,
            "waiver_days_remaining": days_remaining,
            "waiver_scope": scope,
            "waiver_matched_scope": scope,
            "waiver_approval_ref": waiver.approval_ref,
            "waiver_ticket_url": waiver.ticket_url,
        }
    )
    governance["waiver"] = waiver_payload
    governance["waived"] = waived
    updated["waived"] = waived
    if waived:
        updated["status"] = FindingStatus.ACCEPTED.value
    elif previous_status == FindingStatus.ACCEPTED.value:
        updated["status"] = FindingStatus.OPEN.value
    priority_evidence["raw"] = raw
    updated["priority_evidence"] = priority_evidence
    updated["governance"] = governance
    return updated


def _recompute_projection_decision(payload: dict[str, Any]) -> PrioritizedFinding:
    """Rebuild score, priority state, reasons, and context guidance via the domain engine."""
    evidence = FindingDecisionEvidenceV2.model_validate(payload)
    raw = deepcopy(evidence.priority_evidence.raw)
    raw.pop("waiver", None)
    raw.pop("explanation", None)
    raw.pop("decision_guidance", None)
    # Lifecycle-only metadata is retained in evidence but is not part of the
    # strict domain decision model.
    raw.pop("asset_context", None)
    input_occurrences = _projection_input_occurrences(evidence)
    provenance = aggregate_provenance([evidence.cve_id], input_occurrences)[evidence.cve_id]
    has_typed_vex_evidence = any(item.vex_status for item in input_occurrences)
    if not has_typed_vex_evidence and evidence.governance.vex_statuses:
        provenance = _with_compact_vex_provenance(
            provenance,
            evidence.governance.vex_statuses,
            stored_suppressed=evidence.suppressed_by_vex,
        )
    suppressed_by_vex = is_suppressed_by_vex(provenance)
    under_investigation = is_under_investigation(provenance)
    if not has_typed_vex_evidence:
        # Compact distributions can be partial, while the stored decision flags
        # are the reviewed aggregate outcome. Preserve a positive investigation
        # signal even when its row-level status is absent from the distribution.
        under_investigation = (
            under_investigation
            or evidence.under_investigation
            or evidence.governance.under_investigation
        )
    if not has_typed_vex_evidence and not evidence.governance.vex_statuses:
        # Older and compact projections can carry a reviewed VEX decision only
        # at the finding/governance level.  A waiver refresh must not silently
        # turn that evidence into an actionable finding merely because the
        # historical occurrence list is absent.
        suppressed_by_vex = evidence.suppressed_by_vex or evidence.governance.suppressed_by_vex
    raw["provenance"] = provenance.model_dump(mode="json")
    raw.update(
        {
            "cve_id": evidence.cve_id,
            "cvss_base_score": evidence.cvss_base_score,
            "epss": evidence.epss,
            "in_kev": evidence.in_kev,
            "attack_mapped": evidence.attack_mapped,
            "suppressed_by_vex": suppressed_by_vex,
            "under_investigation": under_investigation,
            "highest_asset_criticality": provenance.highest_asset_criticality,
            "asset_count": provenance.asset_count,
            "waived": evidence.waived,
            "priority_label": evidence.priority_evidence.priority_label,
            "priority_rank": evidence.priority_rank,
            "priority_state": evidence.priority_evidence.priority_state,
            "operational_rank": evidence.operational_rank,
            "operational_score": int(
                evidence.priority_evidence.operational_score or evidence.risk_score or 0
            ),
            "operational_score_reasons": list(evidence.priority_evidence.operational_score_reasons),
            "rationale": evidence.rationale
            or "Stored Workbench finding without raw rationale payload.",
            "recommended_action": evidence.recommended_action
            or "Review the finding with the asset owner.",
        }
    )
    provider_payload = evidence.provider.provider_evidence
    if provider_payload:
        try:
            raw["provider_evidence"] = ProviderEvidence.model_validate(provider_payload)
        except (TypeError, ValueError, ValidationError):
            raw.pop("provider_evidence", None)
    domain_payload = {
        key: value for key, value in raw.items() if key in PrioritizedFinding.model_fields
    }
    try:
        decision = PrioritizedFinding.model_validate(domain_payload)
    except (TypeError, ValueError, ValidationError) as exc:
        raise DecisionLedgerInvariantError(
            f"Current projection {evidence.finding_id} cannot be recomputed losslessly."
        ) from exc
    return PrioritizationService().assign_operational_ranks([decision])[0]


def _with_compact_vex_provenance(
    provenance: FindingProvenance,
    vex_statuses: dict[str, int],
    *,
    stored_suppressed: bool,
) -> FindingProvenance:
    """Restore aggregate VEX counts when compact evidence has no row details."""
    normalized_statuses: dict[str, int] = {}
    for status, count in vex_statuses.items():
        normalized_status = status.strip().lower()
        normalized_count = int(count)
        if normalized_status and normalized_count > 0:
            normalized_statuses[normalized_status] = (
                normalized_statuses.get(normalized_status, 0) + normalized_count
            )
    total = sum(normalized_statuses.values())
    if total == 0:
        return provenance
    known_suppressed = sum(
        count for status, count in normalized_statuses.items() if status in SUPPRESSED_VEX_STATUSES
    )
    known_active = total - known_suppressed
    if stored_suppressed and known_active == 0:
        occurrence_count = max(provenance.occurrence_count, total, 1)
        active_occurrence_count = 0
        suppressed_occurrence_count = occurrence_count
    else:
        # vex_statuses contains only annotated rows. A stored non-suppressed
        # decision proves at least one active row may be absent from the
        # compact distribution, so partial counts cannot imply suppression.
        active_occurrence_count = max(
            provenance.active_occurrence_count,
            known_active,
            1,
        )
        occurrence_count = max(
            provenance.occurrence_count,
            total,
            known_suppressed + active_occurrence_count,
        )
        suppressed_occurrence_count = min(
            known_suppressed,
            occurrence_count - active_occurrence_count,
        )
    return provenance.model_copy(
        update={
            "occurrence_count": occurrence_count,
            "active_occurrence_count": active_occurrence_count,
            "suppressed_occurrence_count": suppressed_occurrence_count,
            "vex_statuses": normalized_statuses,
        }
    )


def _projection_input_occurrences(
    evidence: FindingDecisionEvidenceV2,
) -> list[InputOccurrence]:
    """Restore typed occurrences, with the v2 scope as a legacy fallback."""
    if evidence.occurrences:
        return [
            _input_occurrence_from_evidence(item, cve_id=evidence.cve_id)
            for item in evidence.occurrences
        ]
    scope = evidence.occurrence_scope
    if not scope.model_dump(exclude_none=True):
        return []
    return [_input_occurrence_from_scope(scope, cve_id=evidence.cve_id)]


def _projection_scope_sort_key(
    evidence: FindingDecisionEvidenceV2,
) -> tuple[str, tuple[bool, str], str, tuple[bool, str]]:
    """
    Restore the canonical final scope used by Decision Graph ranking.

    New v2 projections carry one explicit occurrence scope.  For older v2
    payloads, all retained occurrences must still agree on one final scope;
    otherwise reranking would invent an order for ambiguous historical data.
    """
    dedup_scope_keys = {
        ScopeKey(
            cve_id=parts.cve_id,
            component_identity=parts.component_identity,
            target_kind=parts.target_kind,
            target_ref=parts.target_ref,
        )
        for item in evidence.occurrences
        if (parts := item.dedup.parts) is not None
        and parts.cve_id is not None
        and parts.target_kind is not None
    }
    if dedup_scope_keys:
        if len(dedup_scope_keys) != 1:
            raise DecisionLedgerInvariantError(
                f"Current projection {evidence.finding_id} contains multiple dedup scopes."
            )
        return next(iter(dedup_scope_keys)).sort_key()

    occurrences = _projection_input_occurrences(evidence)
    if not occurrences:
        occurrences = [InputOccurrence(cve_id=evidence.cve_id)]
    scope_keys = {ScopeKey.from_occurrence(item) for item in occurrences}
    if len(scope_keys) != 1:
        raise DecisionLedgerInvariantError(
            f"Current projection {evidence.finding_id} contains multiple final scopes."
        )
    return next(iter(scope_keys)).sort_key()


def _input_occurrence_from_scope(
    scope: OccurrenceScopeV2,
    *,
    cve_id: str,
) -> InputOccurrence:
    """Restore the evidence-safe subset available in a compact v2 scope."""
    return InputOccurrence(
        cve_id=cve_id,
        source_format=scope.source or "current-projection-scope",
        source_id=scope.source_id,
        source_record_id=scope.source_record_id,
        component_name=scope.component_name,
        component_version=scope.component_version,
        purl=scope.purl,
        package_type=scope.package_type,
        target_kind=scope.target_kind or "generic",
        target_ref=scope.target_ref,
        asset_id=scope.asset_id,
        asset_criticality=scope.asset_criticality,
        asset_exposure=scope.asset_exposure,
        asset_environment=scope.asset_environment,
        asset_owner=scope.asset_owner,
        asset_business_service=scope.asset_business_service,
        vex_status=scope.vex_status,
        vex_match_type=scope.vex_match_type,
        vex_source_path=scope.vex_source_path,
    )


def _input_occurrence_from_evidence(
    item: OccurrenceEvidenceV2,
    *,
    cve_id: str,
) -> InputOccurrence:
    """Restore typed occurrence context omitted from the compact raw decision payload."""
    import_evidence = item.import_evidence
    fix_versions = list(item.fix_versions or [])
    if not fix_versions and item.fix_version:
        fix_versions = [item.fix_version]
    asset_id = item.asset_id or _string_value(import_evidence.get("asset_id"))
    if asset_id is not None:
        asset_id = normalize_asset_identity_value(asset_id) or None
    asset_criticality = (
        item.asset_criticality
        or _string_value(import_evidence.get("asset_criticality"))
        or _string_value(import_evidence.get("criticality"))
    )
    asset_exposure = (
        item.asset_exposure
        or _string_value(import_evidence.get("asset_exposure"))
        or _string_value(import_evidence.get("exposure"))
    )
    asset_environment = (
        item.asset_environment
        or _string_value(import_evidence.get("asset_environment"))
        or _string_value(import_evidence.get("environment"))
    )
    return InputOccurrence(
        cve_id=cve_id,
        source_format=item.source_format or item.source or "unknown",
        source_id=item.source_id,
        source_record_id=item.source_record_id,
        component_name=item.component_name,
        component_version=item.component_version,
        purl=item.purl,
        package_type=item.package_type or _string_value(import_evidence.get("package_type")),
        file_path=_string_value(import_evidence.get("file_path")),
        dependency_path=_string_value(import_evidence.get("dependency_path")),
        fix_versions=fix_versions,
        raw_severity=item.raw_severity,
        target_kind=item.target_kind
        or _string_value(import_evidence.get("target_kind"))
        or "generic",
        target_ref=item.target_ref,
        asset_id=asset_id,
        asset_criticality=asset_criticality,
        asset_exposure=asset_exposure,
        asset_environment=asset_environment,
        asset_owner=item.asset_owner
        or _string_value(import_evidence.get("asset_owner"))
        or _string_value(import_evidence.get("owner")),
        asset_business_service=item.asset_business_service
        or _string_value(import_evidence.get("asset_business_service"))
        or _string_value(import_evidence.get("business_service")),
        asset_match_rule_id=_string_value(import_evidence.get("asset_match_rule_id")),
        asset_match_row=_int_value(import_evidence.get("asset_match_row")),
        asset_match_mode=_string_value(import_evidence.get("asset_match_mode")),
        asset_match_pattern=_string_value(import_evidence.get("asset_match_pattern")),
        asset_match_precedence=_int_value(import_evidence.get("asset_match_precedence")),
        asset_match_candidate_count=(
            _int_value(import_evidence.get("asset_match_candidate_count")) or 0
        ),
        vex_status=item.vex_status,
        vex_justification=item.vex_justification,
        vex_action_statement=item.vex_action_statement,
        vex_match_type=item.vex_match_type,
        vex_source_format=item.vex_source_format,
        vex_source_record_id=item.vex_source_record_id,
        vex_source_path=item.vex_source_path,
        vex_candidate_count=item.vex_candidate_count,
    )


def _apply_recomputed_decision(
    payload: dict[str, Any],
    decision: PrioritizedFinding,
) -> dict[str, Any]:
    """Project a recomputed domain decision into mutable v2 current evidence."""
    updated = deepcopy(payload)
    priority_evidence = _object_value(updated.get("priority_evidence"))
    governance = _object_value(updated.get("governance"))
    remediation = _object_value(updated.get("remediation"))
    decision_payload = decision.model_dump(mode="json", exclude={"provider_evidence"})
    provenance = _object_value(decision_payload.get("provenance"))
    provenance.pop("occurrences", None)
    decision_payload["provenance"] = provenance
    if governance.get("waiver"):
        decision_payload["waiver"] = deepcopy(governance["waiver"])
    lifecycle_asset_context = _object_value(
        _object_value(priority_evidence.get("raw")).get("asset_context")
    )
    if lifecycle_asset_context:
        decision_payload["asset_context"] = deepcopy(lifecycle_asset_context)

    priority_evidence.update(
        {
            "priority_label": decision.priority_label,
            "priority_rank": decision.priority_rank,
            "priority_state": decision.priority_state,
            "operational_score": decision.operational_score,
            "operational_score_reasons": list(decision.operational_score_reasons),
            "explanation": decision.explanation.model_dump(mode="json")
            if decision.explanation is not None
            else {},
            "rationale": decision.rationale,
            "raw": decision_payload,
        }
    )
    guidance = decision.decision_guidance
    if guidance is not None:
        guidance_payload = guidance.model_dump(mode="json")
        remediation.update(
            {
                "recommended_action": decision.recommended_action,
                "decision_statement": guidance.decision_statement,
                "recommendation": guidance.recommendation,
                "recommendation_label": guidance.recommendation_label,
                "business_impact": guidance.business_impact.text,
                "sla": guidance.sla.model_dump(mode="json"),
                "raw": guidance_payload,
            }
        )
    governance["waived"] = decision.waived
    governance["suppressed_by_vex"] = decision.suppressed_by_vex
    governance["under_investigation"] = decision.under_investigation
    governance["vex_statuses"] = dict(decision.provenance.vex_statuses)
    updated.update(
        {
            "status": _status_for_recomputed_decision(
                decision,
                current_status=_finding_status_value(updated.get("status")),
            ),
            "risk_score": float(decision.operational_score),
            "operational_rank": decision.operational_rank,
            "waived": decision.waived,
            "suppressed_by_vex": decision.suppressed_by_vex,
            "under_investigation": decision.under_investigation,
            "rationale": decision.rationale,
            "recommended_action": decision.recommended_action,
            "priority_evidence": priority_evidence,
            "governance": governance,
            "remediation": remediation,
        }
    )
    return FindingDecisionEvidenceV2.model_validate(updated).to_jsonable()


def _status_for_recomputed_decision(
    decision: PrioritizedFinding,
    *,
    current_status: str,
) -> str:
    """Keep workflow state unless terminal governance determines the public status."""
    if decision.priority_state == "Fixed":
        return FindingStatus.FIXED.value
    if decision.priority_state == "Suppressed" or decision.suppressed_by_vex:
        return FindingStatus.SUPPRESSED.value
    if decision.priority_state == "Accepted" or decision.waived:
        return FindingStatus.ACCEPTED.value
    return current_status


def waiver_lifecycle_status(
    waiver: Waiver,
    *,
    today: date | None = None,
) -> tuple[str, int]:
    """Return active/review_due/expired plus days remaining."""
    evaluated_on = today or get_datetime_utc().date()
    days_remaining = (waiver.expires_at - evaluated_on).days
    if waiver.expires_at < evaluated_on:
        return "expired", days_remaining
    if waiver.review_at is not None and waiver.review_at <= evaluated_on:
        return "review_due", days_remaining
    if days_remaining <= 14:
        return "review_due", days_remaining
    return "active", days_remaining


def waiver_scope_label(waiver: Waiver) -> str:
    """Return a concise display label for the waiver scope."""
    parts = []
    for label, value in (
        ("finding", waiver.finding_id),
        ("cve", waiver.cve_id),
        ("asset", waiver.asset_key or waiver.asset_id),
        ("service", waiver.service),
    ):
        if value:
            parts.append(f"{label}:{value}")
    return ", ".join(parts) or "project"


def _waiver_model_data(waiver_in: WaiverCreate | WaiverUpdate) -> dict[str, Any]:
    """Waiver model data function."""
    data = waiver_in.model_dump()
    if data.get("cve_id"):
        data["cve_id"] = str(data["cve_id"]).upper()
    return data


def _waiver_matches_finding(waiver: Waiver, finding: Finding) -> bool:
    """Waiver matches finding function."""
    if waiver.finding_id is not None and waiver.finding_id != finding.id:
        return False
    if waiver.cve_id and waiver.cve_id != finding.cve_id:
        return False
    if waiver.asset_id is not None and waiver.asset_id != finding.asset_id:
        return False
    if waiver.asset_key and (
        finding.asset is None
        or _normalized_match_text(waiver.asset_key)
        != _normalized_match_text(finding.asset.asset_key)
    ):
        return False
    if waiver.service and (
        finding.asset is None
        or _normalized_match_text(waiver.service)
        != _normalized_match_text(finding.asset.business_service or "")
    ):
        return False
    return True


def _selected_waiver(ordered_waivers: list[Waiver], finding: Finding) -> Waiver | None:
    """Return the first matching waiver from the pre-ranked governance list."""
    return next(
        (waiver for waiver in ordered_waivers if _waiver_matches_finding(waiver, finding)),
        None,
    )


def _waiver_selection_sort_key(
    waiver: Waiver,
    *,
    today: date,
) -> tuple[int, int, int, int, date, str, str]:
    """Rank effective waivers by validity, scope specificity, then lifecycle."""
    lifecycle_rank = _waiver_status_sort_key(waiver, today=today)
    expired_rank = int(lifecycle_rank == 2)
    exact_finding_rank = int(waiver.finding_id is None)
    specificity = sum(
        bool(value)
        for value in (
            waiver.finding_id,
            waiver.cve_id,
            waiver.asset_id,
            waiver.asset_key,
            waiver.service,
        )
    )
    return (
        expired_rank,
        exact_finding_rank,
        -specificity,
        lifecycle_rank,
        waiver.expires_at,
        waiver.created_at.isoformat(),
        str(waiver.id),
    )


def _normalized_match_text(value: str) -> str:
    """Apply one frozen Unicode normalization to both waiver and asset values."""
    return unicodedata.normalize("NFC", value).casefold()


def _waiver_status_sort_key(waiver: Waiver, *, today: date | None = None) -> int:
    """Waiver status sort key function."""
    status, _days_remaining = waiver_lifecycle_status(waiver, today=today)
    return {"review_due": 0, "active": 1, "expired": 2}.get(status, 9)


def _object_value(value: object) -> dict[str, Any]:
    """Object value function."""
    return value if isinstance(value, dict) else {}


def _finding_status_value(status: object) -> str:
    """Return the persisted status string for enum and SQL-loaded string values."""
    if isinstance(status, FindingStatus):
        return status.value
    return str(status or FindingStatus.OPEN.value)


def _string_value(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _int_value(value: object) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None


def _case_int(condition: Any) -> Any:
    return case((condition, 1), else_=0)
