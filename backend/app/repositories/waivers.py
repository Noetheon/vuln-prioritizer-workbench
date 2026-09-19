"""Persisted waiver/risk-acceptance repository for the Workbench."""

from __future__ import annotations

import unicodedata
import uuid
from copy import deepcopy
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any, cast

from sqlalchemy import case
from sqlalchemy.orm import QueryableAttribute, selectinload
from sqlmodel import Session, col, func, select

from app.decision_core.contracts import (
    FindingDecisionEvidenceV2,
)
from app.domain.engine.models import WaiverRule
from app.models import (
    Finding,
    FindingCurrentProjection,
    FindingDecisionEvidence,
    FindingStatus,
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
    source_waived = source_evidence.waived
    if _object_value(source_governance.get("waiver")).get("source") == "workbench-api":
        # A native evaluation can itself be the immutable source of an API
        # waiver. Its effective decision is not the pre-waiver workflow state.
        source_raw = {
            key: value for key, value in source_raw.items() if key not in _WAIVER_DECISION_FIELDS
        }
        source_governance = {**source_governance, "waiver": {}}
        source_waived = False
    for key in _WAIVER_DECISION_FIELDS:
        if key in source_raw:
            raw[key] = deepcopy(source_raw[key])
        else:
            raw.pop(key, None)

    governance["waiver"] = deepcopy(source_governance.get("waiver") or {})
    governance["waived"] = source_waived
    restored["waived"] = source_waived
    restored["status"] = _restored_status(current_waiver, source_evidence.status)
    raw["waived"] = source_waived
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
    evidence = FindingDecisionEvidenceV2.model_validate(updated)
    if evidence.evaluation_input is not None:
        inputs = evidence.evaluation_input
        override = (
            WaiverRule(
                id=str(waiver.id),
                cve_id=evidence.cve_id,
                owner=waiver.owner,
                reason=waiver.reason,
                expires_on=waiver.expires_at.isoformat(),
                review_on=waiver.review_at.isoformat() if waiver.review_at else None,
                approval_ref=waiver.approval_ref,
                ticket_url=waiver.ticket_url,
            )
            if waiver is not None
            else None
        )
        inputs = inputs.model_copy(
            update={
                "workbench_waiver": override,
                "evaluation_date": today
                if inputs.waiver_rules or override
                else inputs.evaluation_date,
            }
        )
        updated["evaluation_input"] = inputs.model_dump(mode="json")
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
