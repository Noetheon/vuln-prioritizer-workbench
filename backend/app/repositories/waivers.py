"""Persisted waiver/risk-acceptance repository for the Workbench."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

from sqlmodel import Session, col, select

from app.models import Finding, FindingStatus, Waiver, WaiverCreate, WaiverUpdate
from app.models.base import get_datetime_utc


class WaiverRepository:
    """Waiver persistence plus finding synchronization."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def list_project_waivers(self, project_id: uuid.UUID) -> list[Waiver]:
        """Return project waivers in stable expiry order."""
        statement = (
            select(Waiver)
            .where(Waiver.project_id == project_id)
            .order_by(col(Waiver.expires_at), col(Waiver.created_at))
        )
        return list(self.session.exec(statement).all())

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
        return sum(
            1
            for finding in self._project_findings(waiver.project_id)
            if _waiver_matches_finding(waiver, finding)
        )

    def _project_findings(self, project_id: uuid.UUID) -> list[Finding]:
        statement = (
            select(Finding)
            .where(Finding.project_id == project_id)
            .order_by(col(Finding.operational_rank), col(Finding.priority_rank), Finding.cve_id)
        )
        return list(self.session.exec(statement).all())

    def _clear_workbench_waiver_state(self, finding: Finding) -> None:
        explanation = dict(finding.explanation_json or {})
        evidence = dict(finding.evidence_json or {})
        waiver_record = _object_value(explanation.get("waiver"))
        if waiver_record.get("source") not in {"workbench-api", "template-api"}:
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
        evidence.pop("waiver", None)
        if finding.status == FindingStatus.ACCEPTED:
            finding.status = FindingStatus.OPEN
        finding.waived = False
        finding.explanation_json = explanation
        finding.evidence_json = evidence
        finding.updated_at = get_datetime_utc()
        self.session.add(finding)

    def _apply_waiver_to_finding(self, finding: Finding, waiver: Waiver) -> None:
        status, days_remaining = waiver_lifecycle_status(waiver)
        scope = waiver_scope_label(waiver)
        finding.waived = status in {"active", "review_due"}
        if finding.waived:
            finding.status = FindingStatus.ACCEPTED
        elif finding.status == FindingStatus.ACCEPTED:
            finding.status = FindingStatus.OPEN

        explanation = dict(finding.explanation_json or {})
        evidence = dict(finding.evidence_json or {})
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
        evidence["waiver"] = waiver_payload
        finding.explanation_json = explanation
        finding.evidence_json = evidence
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
    data = waiver_in.model_dump()
    if data.get("cve_id"):
        data["cve_id"] = str(data["cve_id"]).upper()
    return data


def _waiver_matches_finding(waiver: Waiver, finding: Finding) -> bool:
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


def _waiver_status_sort_key(waiver: Waiver) -> int:
    status, _days_remaining = waiver_lifecycle_status(waiver)
    return {"review_due": 0, "active": 1, "expired": 2}.get(status, 9)


def _object_value(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}
