"""Immutable governance rollups for one historical report run."""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Callable, Sequence
from datetime import date, datetime
from typing import Any

from app.services.report_formatting import dict_value as _dict_value
from app.services.report_formatting import iso_datetime as _iso_datetime
from app.services.report_models import MarkdownReportFinding

PRIORITY_LABELS = ("Critical", "High", "Medium", "Low")
STATUS_LABELS = ("open", "in_review", "remediating", "fixed", "accepted", "suppressed")
UNKNOWN_LABEL = "Unassigned"
WAIVER_STATUSES = ("active", "review_due", "expired")
WAIVER_RECORD_FIELDS = (
    "waiver_id",
    "waiver_status",
    "waiver_owner",
    "waiver_scope",
    "waiver_expires_on",
    "waiver_review_on",
    "waiver_days_remaining",
    "waiver_reason",
    "waiver_approval_ref",
    "waiver_ticket_url",
)


def build_run_governance_rollups(
    *,
    project_id: uuid.UUID,
    findings: Sequence[MarkdownReportFinding],
    generated_at: datetime,
    evaluated_at: datetime,
    limit: int = 5,
) -> dict[str, Any]:
    """Build report rollups solely from the selected run's finding evidence projection."""
    bounded_limit = max(1, min(limit, 50))
    owner_rollups = _rollups_for_dimension(
        findings,
        dimension="owner",
        label_for_finding=lambda finding: _clean_label(finding.owner, UNKNOWN_LABEL),
        limit=bounded_limit,
    )
    service_rollups = _rollups_for_dimension(
        findings,
        dimension="service",
        label_for_finding=lambda finding: _clean_label(
            finding.business_service,
            UNKNOWN_LABEL,
        ),
        limit=bounded_limit,
    )
    asset_rollups = _rollups_for_dimension(
        findings,
        dimension="asset",
        label_for_finding=lambda finding: _clean_label(
            finding.asset_key or finding.asset,
            UNKNOWN_LABEL,
        ),
        limit=bounded_limit,
    )
    environment_rollups = _rollups_for_dimension(
        findings,
        dimension="environment",
        label_for_finding=lambda finding: _clean_label(finding.environment, "unknown"),
        limit=bounded_limit,
    )
    return {
        "project_id": str(project_id),
        "generated_at": _iso_datetime(generated_at),
        "owners": owner_rollups,
        "services": service_rollups,
        "assets": asset_rollups,
        "environments": environment_rollups,
        "top_services_by_risk": service_rollups[:bounded_limit],
        "top_assets_by_risk": asset_rollups[:bounded_limit],
        "waiver_debt": _waiver_debt_summary(
            findings,
            evaluated_on=evaluated_at.date(),
            limit=bounded_limit,
        ),
    }


def _rollups_for_dimension(
    findings: Sequence[MarkdownReportFinding],
    *,
    dimension: str,
    label_for_finding: Callable[[MarkdownReportFinding], str],
    limit: int,
) -> list[dict[str, Any]]:
    grouped: dict[str, list[MarkdownReportFinding]] = {}
    for finding in findings:
        grouped.setdefault(label_for_finding(finding), []).append(finding)
    rollups = [
        _rollup_for_findings(dimension=dimension, label=label, findings=items)
        for label, items in grouped.items()
    ]
    rollups.sort(
        key=lambda item: (
            -float(item["risk_score_total"]),
            -int(item["critical_count"]),
            -int(item["high_count"]),
            -int(item["finding_count"]),
            str(item["label"]).casefold(),
        )
    )
    return rollups[:limit]


def _rollup_for_findings(
    *,
    dimension: str,
    label: str,
    findings: Sequence[MarkdownReportFinding],
) -> dict[str, Any]:
    priority_counts = Counter(_priority_label(finding.priority) for finding in findings)
    status_counts = Counter(_status_label(finding.status) for finding in findings)
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
    return {
        "dimension": dimension,
        "label": label,
        "finding_count": len(findings),
        "open_count": sum(
            status_counts.get(status, 0) for status in ("open", "in_review", "remediating")
        ),
        "accepted_count": status_counts.get("accepted", 0)
        + sum(
            1
            for finding in findings
            if finding.waived and _status_label(finding.status) != "accepted"
        ),
        "fixed_count": status_counts.get("fixed", 0),
        "suppressed_count": status_counts.get("suppressed", 0),
        "critical_count": priority_counts.get("Critical", 0),
        "high_count": priority_counts.get("High", 0),
        "kev_count": sum(1 for finding in findings if finding.in_kev),
        "attack_mapped_count": sum(1 for finding in findings if finding.attack_mapped),
        "suppressed_by_vex_count": sum(1 for finding in findings if finding.suppressed_by_vex),
        "under_investigation_count": sum(1 for finding in findings if finding.under_investigation),
        "waived_count": sum(1 for finding in findings if finding.waived),
        "expired_waiver_count": sum(1 for status in waiver_statuses if status == "expired"),
        "review_due_waiver_count": sum(1 for status in waiver_statuses if status == "review_due"),
        "risk_score_total": round(sum(risk_scores), 3),
        "risk_score_max": round(max(risk_scores), 3) if risk_scores else None,
        "highest_priority": next(
            (priority for priority in PRIORITY_LABELS if priority_counts.get(priority, 0)),
            None,
        ),
        "priority_counts": {
            priority: priority_counts.get(priority, 0) for priority in PRIORITY_LABELS
        },
        "status_counts": {status: status_counts.get(status, 0) for status in STATUS_LABELS},
        "top_cves": [finding.cve_id for finding in ordered_findings[:5]],
    }


def _waiver_debt_summary(
    findings: Sequence[MarkdownReportFinding],
    *,
    evaluated_on: date,
    limit: int,
) -> dict[str, Any]:
    grouped: dict[tuple[str, ...], tuple[dict[str, Any], list[MarkdownReportFinding]]] = {}
    for finding in findings:
        record = _waiver_record(finding)
        status = _normalized_waiver_status(record)
        if status is None:
            continue
        fallback_cve_id = _idless_waiver_cve_id(record, finding=finding)
        key = _waiver_identity(record, fallback_cve_id=fallback_cve_id)
        stored_record, matched = grouped.setdefault(key, (record, []))
        if stored_record != record:
            # The immutable source is internally inconsistent; keep records distinct
            # rather than silently merging different governance facts.
            key = (*key, finding.id or finding.cve_id)
            stored_record, matched = grouped.setdefault(key, (record, []))
        matched.append(finding)

    status_counts: Counter[str] = Counter()
    owner_counts: Counter[str] = Counter()
    service_counts: Counter[str] = Counter()
    items: list[dict[str, Any]] = []
    for key, (record, matched) in grouped.items():
        status = _normalized_waiver_status(record)
        expires_at = _date_value(record.get("waiver_expires_on"))
        if status is None or expires_at is None:
            continue
        owner = _string_value(record.get("waiver_owner")) or UNKNOWN_LABEL
        scope = _string_value(record.get("waiver_scope")) or "project"
        service = _scope_value(scope, "service") or _string_value(record.get("service"))
        asset_key = _scope_value(scope, "asset") or _string_value(record.get("asset_key"))
        cve_id = (
            _scope_value(scope, "cve")
            or _string_value(record.get("cve_id"))
            or (
                matched[0].cve_id
                if matched and _string_value(record.get("waiver_id")) is None
                else None
            )
        )
        finding_id = _uuid_or_none(
            _scope_value(scope, "finding") or _string_value(record.get("finding_id"))
        )
        days_remaining = _int_value(record.get("waiver_days_remaining"))
        if days_remaining is None:
            days_remaining = (expires_at - evaluated_on).days
        status_counts[status] += 1
        owner_counts[owner] += 1
        if service:
            service_counts[service] += 1
        items.append(
            {
                "id": _waiver_uuid(record, key),
                "owner": owner,
                "scope": scope,
                "status": status,
                "days_remaining": days_remaining,
                "expires_at": expires_at.isoformat(),
                "review_at": _date_string(record.get("waiver_review_on")),
                "matched_findings": len(matched),
                "cve_id": cve_id,
                "service": service,
                "asset_key": asset_key,
                "finding_id": finding_id,
                "reason": _string_value(record.get("waiver_reason")),
                "approval_ref": _string_value(record.get("waiver_approval_ref")),
                "ticket_url": _string_value(record.get("waiver_ticket_url")),
            }
        )

    items.sort(
        key=lambda item: (
            {"expired": 0, "review_due": 1, "active": 2}.get(str(item["status"]), 9),
            str(item["expires_at"]),
            str(item["owner"]),
        )
    )
    finding_statuses = [_waiver_status(finding) for finding in findings]
    return {
        "waiver_count": len(items),
        "active_count": status_counts.get("active", 0),
        "review_due_count": status_counts.get("review_due", 0),
        "expired_count": status_counts.get("expired", 0),
        "expiring_soon_count": sum(
            1
            for item in items
            if item["status"] != "expired" and 0 <= int(item["days_remaining"]) <= 14
        ),
        "matched_finding_count": sum(int(item["matched_findings"]) for item in items),
        "accepted_finding_count": sum(
            1
            for finding in findings
            if _status_label(finding.status) == "accepted" or finding.waived
        ),
        "expired_finding_count": sum(1 for status in finding_statuses if status == "expired"),
        "review_due_finding_count": sum(1 for status in finding_statuses if status == "review_due"),
        "owner_counts": dict(sorted(owner_counts.items())),
        "service_counts": dict(sorted(service_counts.items())),
        "items": items[:limit],
    }


def _waiver_record(finding: MarkdownReportFinding) -> dict[str, Any]:
    evidence = finding.evidence
    priority_raw = _dict_value(_dict_value(evidence.get("priority_evidence")).get("raw"))
    governance = _dict_value(evidence.get("governance"))
    record: dict[str, Any] = {}
    for source in (priority_raw, finding.explanation, governance):
        record.update(_dict_value(source.get("waiver")))
        for field_name in WAIVER_RECORD_FIELDS:
            if field_name in source:
                record[field_name] = source[field_name]
    return record


def _waiver_status(finding: MarkdownReportFinding) -> str | None:
    return _normalized_waiver_status(_waiver_record(finding))


def _normalized_waiver_status(record: dict[str, Any]) -> str | None:
    value = _string_value(record.get("waiver_status"))
    if value is None:
        return None
    normalized = value.casefold()
    return normalized if normalized in WAIVER_STATUSES else None


def _waiver_identity(
    record: dict[str, Any],
    *,
    fallback_cve_id: str | None,
) -> tuple[str, ...]:
    waiver_id = _string_value(record.get("waiver_id"))
    if waiver_id:
        return ("id", waiver_id)
    return (
        "facts",
        _string_value(record.get("waiver_owner")) or "",
        _string_value(record.get("waiver_scope")) or "",
        _string_value(record.get("waiver_status")) or "",
        _string_value(record.get("waiver_expires_on")) or "",
        _string_value(record.get("waiver_review_on")) or "",
        _string_value(record.get("waiver_reason")) or "",
        fallback_cve_id or "",
    )


def _idless_waiver_cve_id(
    record: dict[str, Any],
    *,
    finding: MarkdownReportFinding,
) -> str | None:
    """Avoid merging unidentifiable waiver rules across unrelated CVEs."""
    if _string_value(record.get("waiver_id")) is not None:
        return None
    scope = _string_value(record.get("waiver_scope")) or ""
    return _scope_value(scope, "cve") or _string_value(record.get("cve_id")) or finding.cve_id


def _waiver_uuid(record: dict[str, Any], key: tuple[str, ...]) -> str:
    raw = _string_value(record.get("waiver_id"))
    parsed = _uuid_or_none(raw)
    if parsed is not None:
        return parsed
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "vpw-report-waiver:" + "\x1f".join(key)))


def _scope_value(scope: str, label: str) -> str | None:
    prefix = f"{label}:"
    for part in scope.split(","):
        cleaned = part.strip()
        if cleaned.casefold().startswith(prefix):
            return _string_value(cleaned[len(prefix) :])
    equals_prefix = f"{label}s="
    for part in scope.split(";"):
        cleaned = part.strip()
        if cleaned.casefold().startswith(equals_prefix):
            values = [value.strip() for value in cleaned[len(equals_prefix) :].split(",")]
            return values[0] if len(values) == 1 and values[0] else None
    return None


def _priority_label(value: str) -> str:
    normalized = value.split(".", maxsplit=1)[-1].strip().casefold()
    return next(
        (label for label in PRIORITY_LABELS if label.casefold() == normalized),
        normalized.title(),
    )


def _status_label(value: str) -> str:
    return value.split(".", maxsplit=1)[-1].strip().casefold() or "open"


def _clean_label(value: object, fallback: str) -> str:
    return _string_value(value) or fallback


def _string_value(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None


def _int_value(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _date_value(value: object) -> date | None:
    raw = _string_value(value)
    if raw is None:
        return None
    try:
        return date.fromisoformat(raw.split("T", maxsplit=1)[0])
    except ValueError:
        return None


def _date_string(value: object) -> str | None:
    parsed = _date_value(value)
    return parsed.isoformat() if parsed is not None else None


def _uuid_or_none(value: object) -> str | None:
    raw = _string_value(value)
    if raw is None:
        return None
    try:
        return str(uuid.UUID(raw))
    except ValueError:
        return None


__all__ = ["build_run_governance_rollups"]
