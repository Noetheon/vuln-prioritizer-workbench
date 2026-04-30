"""Governance rollups for the template Workbench."""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Callable, Sequence
from typing import Any

from app.models import (
    Finding,
    GovernanceRollupPublic,
    GovernanceWaiverDebtEntryPublic,
    GovernanceWaiverDebtPublic,
    ProjectGovernanceRollupsPublic,
    Waiver,
)
from app.models.base import get_datetime_utc
from app.repositories.waivers import (
    WaiverRepository,
    waiver_lifecycle_status,
    waiver_scope_label,
)

PRIORITY_LABELS = ("Critical", "High", "Medium", "Low")
STATUS_LABELS = ("open", "in_review", "remediating", "fixed", "accepted", "suppressed")
UNKNOWN_LABEL = "Unassigned"


def build_project_governance_rollups_payload(
    *,
    project_id: uuid.UUID,
    findings: Sequence[Finding],
    waivers: Sequence[Waiver] | None = None,
    waiver_repository: WaiverRepository | None = None,
    limit: int = 5,
) -> ProjectGovernanceRollupsPublic:
    """Build owner, service, asset, environment, and waiver-debt rollups for a project."""
    bounded_limit = max(1, min(limit, 50))
    owner_rollups = _rollups_for_dimension(
        findings,
        dimension="owner",
        label_for_finding=_owner_label,
        limit=bounded_limit,
    )
    service_rollups = _rollups_for_dimension(
        findings,
        dimension="service",
        label_for_finding=_service_label,
        limit=bounded_limit,
    )
    asset_rollups = _rollups_for_dimension(
        findings,
        dimension="asset",
        label_for_finding=_asset_label,
        limit=bounded_limit,
    )
    environment_rollups = _rollups_for_dimension(
        findings,
        dimension="environment",
        label_for_finding=_environment_label,
        limit=bounded_limit,
    )
    return ProjectGovernanceRollupsPublic(
        project_id=project_id,
        generated_at=get_datetime_utc(),
        owners=owner_rollups,
        services=service_rollups,
        assets=asset_rollups,
        environments=environment_rollups,
        top_services_by_risk=service_rollups[:bounded_limit],
        top_assets_by_risk=asset_rollups[:bounded_limit],
        waiver_debt=_waiver_debt_summary(
            findings=findings,
            waivers=list(waivers or []),
            waiver_repository=waiver_repository,
            limit=bounded_limit,
        ),
    )


def _rollups_for_dimension(
    findings: Sequence[Finding],
    *,
    dimension: str,
    label_for_finding: Callable[[Finding], str],
    limit: int,
) -> list[GovernanceRollupPublic]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        label = label_for_finding(finding)
        grouped.setdefault(label, []).append(finding)

    rollups = [
        _rollup_for_findings(dimension=dimension, label=label, findings=items)
        for label, items in grouped.items()
    ]
    rollups.sort(
        key=lambda item: (
            -item.risk_score_total,
            -item.critical_count,
            -item.high_count,
            -item.finding_count,
            item.label.casefold(),
        )
    )
    return rollups[:limit]


def _rollup_for_findings(
    *,
    dimension: str,
    label: str,
    findings: Sequence[Finding],
) -> GovernanceRollupPublic:
    priority_counts = Counter(_priority_label(finding) for finding in findings)
    status_counts = Counter(_status_label(finding) for finding in findings)
    risk_scores = [float(finding.risk_score or 0.0) for finding in findings]
    waiver_statuses = [_waiver_status(finding) for finding in findings]
    ordered_findings = sorted(
        findings,
        key=lambda finding: (
            int(finding.operational_rank or 0),
            int(finding.priority_rank or 99),
            finding.cve_id,
        ),
    )
    return GovernanceRollupPublic(
        dimension=dimension,
        label=label,
        finding_count=len(findings),
        open_count=sum(
            status_counts.get(status, 0) for status in ("open", "in_review", "remediating")
        ),
        accepted_count=status_counts.get("accepted", 0)
        + sum(
            1
            for finding in findings
            if bool(finding.waived) and _status_label(finding) != "accepted"
        ),
        fixed_count=status_counts.get("fixed", 0),
        suppressed_count=status_counts.get("suppressed", 0),
        critical_count=priority_counts.get("Critical", 0),
        high_count=priority_counts.get("High", 0),
        kev_count=sum(1 for finding in findings if finding.in_kev),
        attack_mapped_count=sum(1 for finding in findings if finding.attack_mapped),
        suppressed_by_vex_count=sum(1 for finding in findings if finding.suppressed_by_vex),
        under_investigation_count=sum(1 for finding in findings if finding.under_investigation),
        waived_count=sum(1 for finding in findings if finding.waived),
        expired_waiver_count=sum(1 for status in waiver_statuses if status == "expired"),
        review_due_waiver_count=sum(1 for status in waiver_statuses if status == "review_due"),
        risk_score_total=round(sum(risk_scores), 3),
        risk_score_max=round(max(risk_scores), 3) if risk_scores else None,
        highest_priority=_highest_priority(priority_counts),
        priority_counts={
            priority: priority_counts.get(priority, 0) for priority in PRIORITY_LABELS
        },
        status_counts={status: status_counts.get(status, 0) for status in STATUS_LABELS},
        top_cves=[finding.cve_id for finding in ordered_findings[:5]],
    )


def _waiver_debt_summary(
    *,
    findings: Sequence[Finding],
    waivers: Sequence[Waiver],
    waiver_repository: WaiverRepository | None,
    limit: int,
) -> GovernanceWaiverDebtPublic:
    status_counts: Counter[str] = Counter()
    owner_counts: Counter[str] = Counter()
    service_counts: Counter[str] = Counter()
    matched_finding_count = 0
    items: list[GovernanceWaiverDebtEntryPublic] = []

    for waiver in waivers:
        status, days_remaining = waiver_lifecycle_status(waiver)
        status_counts[status] += 1
        owner_counts[waiver.owner or UNKNOWN_LABEL] += 1
        if waiver.service:
            service_counts[waiver.service] += 1
        matched_findings = (
            waiver_repository.matching_finding_count(waiver) if waiver_repository is not None else 0
        )
        matched_finding_count += matched_findings
        items.append(
            GovernanceWaiverDebtEntryPublic(
                id=waiver.id,
                owner=waiver.owner,
                scope=waiver_scope_label(waiver),
                status=status,
                days_remaining=days_remaining,
                expires_at=waiver.expires_at,
                review_at=waiver.review_at,
                matched_findings=matched_findings,
                cve_id=waiver.cve_id,
                service=waiver.service,
                asset_key=waiver.asset_key,
                finding_id=waiver.finding_id,
            )
        )

    items.sort(key=lambda item: (_waiver_status_sort_key(item.status), item.expires_at, item.owner))
    finding_waiver_statuses = [_waiver_status(finding) for finding in findings]
    return GovernanceWaiverDebtPublic(
        waiver_count=len(waivers),
        active_count=status_counts.get("active", 0),
        review_due_count=status_counts.get("review_due", 0),
        expired_count=status_counts.get("expired", 0),
        expiring_soon_count=sum(
            1 for item in items if item.status != "expired" and 0 <= item.days_remaining <= 14
        ),
        matched_finding_count=matched_finding_count,
        accepted_finding_count=sum(
            1 for finding in findings if _status_label(finding) == "accepted" or finding.waived
        ),
        expired_finding_count=sum(1 for status in finding_waiver_statuses if status == "expired"),
        review_due_finding_count=sum(
            1 for status in finding_waiver_statuses if status == "review_due"
        ),
        owner_counts=dict(sorted(owner_counts.items())),
        service_counts=dict(sorted(service_counts.items())),
        items=items[:limit],
    )


def _owner_label(finding: Finding) -> str:
    asset_owner = getattr(finding.asset, "owner", None)
    return _clean_label(
        asset_owner
        or _record_string(finding, ("owner", "asset_owner", "waiver_owner"))
        or UNKNOWN_LABEL
    )


def _service_label(finding: Finding) -> str:
    asset_service = getattr(finding.asset, "business_service", None)
    return _clean_label(
        asset_service
        or _record_string(
            finding,
            ("business_service", "service", "asset_business_service", "waiver_service"),
        )
        or UNKNOWN_LABEL
    )


def _asset_label(finding: Finding) -> str:
    asset = getattr(finding, "asset", None)
    asset_key = getattr(asset, "asset_key", None)
    asset_name = getattr(asset, "name", None)
    return _clean_label(
        asset_key
        or asset_name
        or _record_string(finding, ("asset_key", "asset_ref", "target_ref"))
        or UNKNOWN_LABEL
    )


def _environment_label(finding: Finding) -> str:
    asset_environment = getattr(finding.asset, "environment", None)
    return _clean_label(
        _enum_value(asset_environment)
        or _record_string(finding, ("environment", "asset_environment"))
        or "unknown"
    )


def _priority_label(finding: Finding) -> str:
    raw = _enum_value(finding.priority).strip().lower()
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }.get(raw, "Low")


def _status_label(finding: Finding) -> str:
    return _enum_value(finding.status).strip().lower() or "open"


def _highest_priority(priority_counts: Counter[str]) -> str | None:
    for priority in PRIORITY_LABELS:
        if priority_counts.get(priority, 0):
            return priority
    return None


def _waiver_status(finding: Finding) -> str | None:
    record = _waiver_record(finding)
    status = _string_value(record.get("waiver_status")) or _string_value(record.get("status"))
    return status.strip().lower() if status else None


def _waiver_record(finding: Finding) -> dict[str, Any]:
    explanation = _dict_value(finding.explanation_json)
    evidence = _dict_value(finding.evidence_json)
    record: dict[str, Any] = {}
    for source in (evidence.get("waiver"), explanation.get("waiver"), explanation, evidence):
        if isinstance(source, dict):
            record.update(source)
    return record


def _record_string(finding: Finding, keys: Sequence[str]) -> str | None:
    records = (
        _dict_value(finding.explanation_json),
        _dict_value(finding.evidence_json),
        _dict_value(_dict_value(finding.evidence_json).get("asset_context")),
        _dict_value(_dict_value(finding.explanation_json).get("provenance")),
    )
    for record in records:
        for key in keys:
            value = _string_value(record.get(key))
            if value:
                return value
    return None


def _clean_label(value: object) -> str:
    text = str(value).strip() if value is not None else ""
    return text or UNKNOWN_LABEL


def _enum_value(value: object) -> str:
    raw = getattr(value, "value", value)
    return str(raw) if raw is not None else ""


def _string_value(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _dict_value(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _waiver_status_sort_key(status: str) -> int:
    return {"expired": 0, "review_due": 1, "active": 2}.get(status, 9)
