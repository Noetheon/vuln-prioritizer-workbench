"""Persisted waiver/risk-acceptance repository for the Workbench."""

from __future__ import annotations

import uuid
from copy import deepcopy
from datetime import timedelta
from typing import Any

from sqlalchemy import case
from sqlmodel import Session, col, func, select

from app.models import Asset, Finding, FindingStatus, Waiver, WaiverCreate, WaiverUpdate
from app.models.base import get_datetime_utc
from app.repositories.current_projections import FindingCurrentProjectionRepository


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

    def sync_project_waivers(self, project_id: uuid.UUID) -> dict[uuid.UUID, int]:
        """Apply current waiver lifecycle state to project findings."""
        findings = self._project_findings(project_id)
        waivers = self.list_project_waivers(project_id)
        matched_counts: dict[uuid.UUID, int] = {waiver.id: 0 for waiver in waivers}

        for finding in findings:
            self._clear_workbench_waiver_state(finding)

        for finding in findings:
            matches = [waiver for waiver in waivers if _waiver_matches_finding(waiver, finding)]
            if not matches:
                continue
            matches.sort(key=lambda waiver: (_waiver_status_sort_key(waiver), waiver.expires_at))
            waiver = matches[0]
            matched_counts[waiver.id] = matched_counts.get(waiver.id, 0) + 1
            self._apply_waiver_to_finding(finding, waiver)

        self.session.flush()
        return matched_counts

    def matching_finding_count(self, waiver: Waiver) -> int:
        """Count project findings matching this waiver's scope."""
        statement = select(func.count()).select_from(Finding)
        if waiver.asset_key or waiver.service:
            statement = statement.outerjoin(Asset, col(Finding.asset_id) == col(Asset.id))
        filters = _waiver_match_filters(waiver)
        return int(self.session.exec(statement.where(*filters)).one())

    def _project_findings(self, project_id: uuid.UUID) -> list[Finding]:
        """Project findings method for WaiverRepository."""
        statement = (
            select(Finding)
            .where(Finding.project_id == project_id)
            .order_by(Finding.cve_id, col(Finding.id))
        )
        return list(self.session.exec(statement).all())

    def _clear_workbench_waiver_state(self, finding: Finding) -> None:
        """Clear workbench waiver state method for WaiverRepository."""
        projection_repository = FindingCurrentProjectionRepository(self.session)
        projection_record = projection_repository.get_record(finding.id)
        payload = (
            deepcopy(projection_repository.current_payload(finding.id) or {})
            if projection_record is not None
            else {}
        )
        priority_evidence = _object_value(payload.get("priority_evidence"))
        explanation = _object_value(priority_evidence.get("raw"))
        governance = _object_value(payload.get("governance"))
        waiver_record = _object_value(governance.get("waiver") or explanation.get("waiver"))
        if waiver_record.get("source") != "workbench-api":
            return

        for key in (
            "waiver",
            "waiver_status",
            "waiver_owner",
            "waiver_reason",
            "waiver_expires_on",
            "waiver_review_on",
            "waiver_approval_ref",
            "waiver_scope",
        ):
            explanation.pop(key, None)
        governance.pop("waiver", None)
        governance["waived"] = False
        if finding.status == FindingStatus.ACCEPTED:
            finding.status = FindingStatus.OPEN
        if projection_record is not None:
            priority_evidence["raw"] = explanation
            payload["priority_evidence"] = priority_evidence
            payload["governance"] = governance
            payload["waived"] = False
            payload["status"] = _finding_status_value(finding.status)
            projection_repository.update_current_payload(finding.id, payload)
        finding.updated_at = get_datetime_utc()
        self.session.add(finding)

    def _apply_waiver_to_finding(self, finding: Finding, waiver: Waiver) -> None:
        """Apply waiver to finding method for WaiverRepository."""
        status, days_remaining = waiver_lifecycle_status(waiver)
        scope = waiver_scope_label(waiver)
        waived = status in {"active", "review_due"}
        if waived:
            finding.status = FindingStatus.ACCEPTED
        elif finding.status == FindingStatus.ACCEPTED:
            finding.status = FindingStatus.OPEN

        projection_repository = FindingCurrentProjectionRepository(self.session)
        projection_record = projection_repository.get_record(finding.id)
        payload = (
            deepcopy(projection_repository.current_payload(finding.id) or {})
            if projection_record is not None
            else {}
        )
        priority_evidence = _object_value(payload.get("priority_evidence"))
        explanation = _object_value(priority_evidence.get("raw"))
        governance = _object_value(payload.get("governance"))
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
        }
        explanation["waiver"] = waiver_payload
        explanation["waiver_status"] = status
        explanation["waiver_owner"] = waiver.owner
        explanation["waiver_reason"] = waiver.reason
        explanation["waiver_expires_on"] = waiver.expires_at.isoformat()
        explanation["waiver_review_on"] = waiver.review_at.isoformat() if waiver.review_at else None
        explanation["waiver_approval_ref"] = waiver.approval_ref
        explanation["waiver_scope"] = scope
        governance["waiver"] = waiver_payload
        governance["waived"] = waived
        if projection_record is not None:
            priority_evidence["raw"] = explanation
            payload["priority_evidence"] = priority_evidence
            payload["governance"] = governance
            payload["waived"] = waived
            payload["status"] = _finding_status_value(finding.status)
            projection_repository.update_current_payload(finding.id, payload)
        finding.updated_at = get_datetime_utc()
        self.session.add(finding)


def waiver_lifecycle_status(waiver: Waiver) -> tuple[str, int]:
    """Return active/review_due/expired plus days remaining."""
    today = get_datetime_utc().date()
    days_remaining = (waiver.expires_at - today).days
    if waiver.expires_at < today:
        return "expired", days_remaining
    if waiver.review_at is not None and waiver.review_at <= today:
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
        finding.asset is None or waiver.asset_key.casefold() != finding.asset.asset_key.casefold()
    ):
        return False
    if waiver.service and (
        finding.asset is None
        or waiver.service.casefold() != (finding.asset.business_service or "").casefold()
    ):
        return False
    return True


def _waiver_match_filters(waiver: Waiver) -> list[Any]:
    """Return SQL filters equivalent to the in-memory waiver matcher."""
    filters: list[Any] = [Finding.project_id == waiver.project_id]
    if waiver.finding_id is not None:
        filters.append(Finding.id == waiver.finding_id)
    if waiver.cve_id:
        filters.append(Finding.cve_id == waiver.cve_id)
    if waiver.asset_id is not None:
        filters.append(Finding.asset_id == waiver.asset_id)
    if waiver.asset_key:
        filters.append(func.lower(Asset.asset_key) == waiver.asset_key.casefold())
    if waiver.service:
        filters.append(func.lower(Asset.business_service) == waiver.service.casefold())
    return filters


def _waiver_status_sort_key(waiver: Waiver) -> int:
    """Waiver status sort key function."""
    status, _days_remaining = waiver_lifecycle_status(waiver)
    return {"review_due": 0, "active": 1, "expired": 2}.get(status, 9)


def _object_value(value: object) -> dict[str, object]:
    """Object value function."""
    return value if isinstance(value, dict) else {}


def _finding_status_value(status: FindingStatus | str | None) -> str:
    """Return the persisted status string for enum and SQL-loaded string values."""
    if isinstance(status, FindingStatus):
        return status.value
    return str(status or FindingStatus.OPEN.value)


def _case_int(condition: Any) -> Any:
    return case((condition, 1), else_=0)
