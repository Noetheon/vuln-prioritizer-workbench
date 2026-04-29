"""Waiver validation, matching, and payload helpers for Workbench routes."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from fastapi import HTTPException

from vuln_prioritizer.api.schemas import WaiverRequest
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.utils import iso_utc_now, normalize_cve_id

PERSISTED_WAIVER_ID_PREFIX = "api:"


def _strip_or_none(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _validated_date(value: str | None, *, field_name: str, required: bool) -> str | None:
    normalized = _strip_or_none(value)
    if normalized is None:
        if required:
            raise HTTPException(status_code=422, detail=f"{field_name} is required.")
        return None
    try:
        date.fromisoformat(normalized[:10])
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"{field_name} must be YYYY-MM-DD.") from exc
    return normalized[:10]


def _today() -> date:
    try:
        return date.fromisoformat(iso_utc_now()[:10])
    except ValueError:
        return datetime.now(UTC).date()


def _validated_waiver_values(
    payload: WaiverRequest,
    *,
    project_id: str,
    repo: WorkbenchRepository,
) -> dict[str, Any]:
    cve_id = normalize_cve_id(payload.cve_id) if payload.cve_id else None
    if payload.cve_id and cve_id is None:
        raise HTTPException(status_code=422, detail="cve_id is not a valid CVE identifier.")
    finding_id = _strip_or_none(payload.finding_id)
    if finding_id is not None:
        finding = repo.get_finding(finding_id)
        if finding is None or finding.project_id != project_id:
            raise HTTPException(status_code=422, detail="finding_id does not belong to project.")
    expires_on = _validated_date(payload.expires_on, field_name="expires_on", required=True)
    if expires_on is None:
        raise HTTPException(status_code=422, detail="expires_on is required.")
    review_on = _validated_date(payload.review_on, field_name="review_on", required=False)
    values = {
        "cve_id": cve_id,
        "finding_id": finding_id,
        "asset_id": _strip_or_none(payload.asset_id),
        "component_name": _strip_or_none(payload.component_name),
        "component_version": _strip_or_none(payload.component_version),
        "service": _strip_or_none(payload.service),
        "owner": _strip_or_none(payload.owner),
        "reason": _strip_or_none(payload.reason),
        "expires_on": expires_on,
        "review_on": review_on,
        "approval_ref": _strip_or_none(payload.approval_ref),
        "ticket_url": _strip_or_none(payload.ticket_url),
    }
    if values["owner"] is None:
        raise HTTPException(status_code=422, detail="owner is required.")
    if values["reason"] is None:
        raise HTTPException(status_code=422, detail="reason is required.")
    if review_on is not None and review_on > expires_on:
        raise HTTPException(status_code=422, detail="review_on must not be after expires_on.")
    if not any(
        values[name]
        for name in (
            "cve_id",
            "finding_id",
            "asset_id",
            "component_name",
            "component_version",
            "service",
        )
    ):
        raise HTTPException(status_code=422, detail="At least one waiver scope is required.")
    return values


def _sync_project_waivers(repo: WorkbenchRepository, project_id: str) -> dict[str, int]:
    findings = repo.list_project_findings(project_id)
    waivers = repo.list_project_waivers(project_id)
    matched_counts = {waiver.id: 0 for waiver in waivers}
    for finding in findings:
        if (finding.waiver_id or "").startswith(PERSISTED_WAIVER_ID_PREFIX):
            _clear_persisted_waiver_state(finding)
    for finding in findings:
        matches = [waiver for waiver in waivers if _waiver_matches_finding(waiver, finding)]
        if not matches:
            continue
        matches.sort(key=lambda waiver: (_waiver_status_sort_key(waiver), waiver.expires_on))
        waiver = matches[0]
        matched_counts[waiver.id] = matched_counts.get(waiver.id, 0) + 1
        status, days_remaining = _waiver_status(waiver)
        finding.waived = status in {"active", "review_due"}
        finding.waiver_status = status
        finding.waiver_reason = waiver.reason
        finding.waiver_owner = waiver.owner
        finding.waiver_expires_on = waiver.expires_on
        finding.waiver_review_on = waiver.review_on
        finding.waiver_days_remaining = days_remaining
        finding.waiver_scope = _waiver_scope_label(waiver)
        finding.waiver_id = PERSISTED_WAIVER_ID_PREFIX + waiver.id
        finding.waiver_matched_scope = _waiver_scope_label(waiver)
        finding.waiver_approval_ref = waiver.approval_ref
        finding.waiver_ticket_url = waiver.ticket_url
        if status == "expired":
            finding.waived = False
    repo.session.flush()
    return matched_counts


def _clear_persisted_waiver_state(finding: Any) -> None:
    finding.waived = False
    finding.waiver_status = None
    finding.waiver_reason = None
    finding.waiver_owner = None
    finding.waiver_expires_on = None
    finding.waiver_review_on = None
    finding.waiver_days_remaining = None
    finding.waiver_scope = None
    finding.waiver_id = None
    finding.waiver_matched_scope = None
    finding.waiver_approval_ref = None
    finding.waiver_ticket_url = None


def _waiver_matches_finding(waiver: Any, finding: Any) -> bool:
    if waiver.finding_id and waiver.finding_id != finding.id:
        return False
    if waiver.cve_id and waiver.cve_id != finding.cve_id:
        return False
    if waiver.asset_id and (finding.asset is None or waiver.asset_id != finding.asset.asset_id):
        return False
    if waiver.component_name and (
        finding.component is None
        or waiver.component_name.casefold() != (finding.component.name or "").casefold()
    ):
        return False
    if waiver.component_version and (
        finding.component is None or waiver.component_version != finding.component.version
    ):
        return False
    if waiver.service and (
        finding.asset is None
        or waiver.service.casefold() != (finding.asset.business_service or "").casefold()
    ):
        return False
    return True


def _count_matching_waiver_findings(waiver: Any, findings: list[Any]) -> int:
    return sum(1 for finding in findings if _waiver_matches_finding(waiver, finding))


def _waiver_status(waiver: Any) -> tuple[str, int | None]:
    today = _today()
    expires_on = date.fromisoformat(waiver.expires_on[:10])
    days_remaining = (expires_on - today).days
    if expires_on < today:
        return "expired", days_remaining
    if waiver.review_on is not None and date.fromisoformat(waiver.review_on[:10]) <= today:
        return "review_due", days_remaining
    if days_remaining <= 14:
        return "review_due", days_remaining
    return "active", days_remaining


def _waiver_status_sort_key(waiver: Any) -> int:
    status, _days_remaining = _waiver_status(waiver)
    return {"review_due": 0, "active": 1, "expired": 2}.get(status, 9)


def _waiver_scope_label(waiver: Any) -> str:
    parts = []
    for label, value in (
        ("finding", waiver.finding_id),
        ("cve", waiver.cve_id),
        ("asset", waiver.asset_id),
        ("component", waiver.component_name),
        ("version", waiver.component_version),
        ("service", waiver.service),
    ):
        if value:
            parts.append(f"{label}:{value}")
    return ", ".join(parts) or "project"


def _waiver_payload(waiver: Any, *, matched_findings: int = 0) -> dict[str, Any]:
    status, days_remaining = _waiver_status(waiver)
    return {
        "id": waiver.id,
        "project_id": waiver.project_id,
        "cve_id": waiver.cve_id,
        "finding_id": waiver.finding_id,
        "asset_id": waiver.asset_id,
        "component_name": waiver.component_name,
        "component_version": waiver.component_version,
        "service": waiver.service,
        "owner": waiver.owner,
        "reason": waiver.reason,
        "expires_on": waiver.expires_on,
        "review_on": waiver.review_on,
        "approval_ref": waiver.approval_ref,
        "ticket_url": waiver.ticket_url,
        "status": status,
        "days_remaining": days_remaining,
        "matched_findings": matched_findings,
        "created_at": waiver.created_at.isoformat(),
        "updated_at": waiver.updated_at.isoformat(),
    }
