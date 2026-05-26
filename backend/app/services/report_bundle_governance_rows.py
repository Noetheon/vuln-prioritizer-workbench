"""Governance row projection helpers for evidence bundle exports."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.services.report_formatting import dict_value as _dict_value
from app.services.report_models import MarkdownReportFinding
from app.services.report_renderer_common import (
    _boolish_signal,
    _priority_label,
    _string_from_mapping,
    _vex_statuses_label,
)


def _asset_context_rows(findings: Sequence[MarkdownReportFinding]) -> list[dict[str, Any]]:
    grouped: dict[str, list[MarkdownReportFinding]] = {}
    for finding in findings:
        label = finding.asset_key or finding.asset or "Unassigned"
        grouped.setdefault(label, []).append(finding)
    rows: list[dict[str, Any]] = []
    for label, items in grouped.items():
        first = items[0]
        rows.append(
            {
                "asset_key": first.asset_key,
                "label": label,
                "owner": first.owner,
                "business_service": first.business_service,
                "environment": first.environment,
                "exposure": first.exposure,
                "criticality": first.criticality,
                "finding_count": len(items),
                "accepted_count": sum(
                    1
                    for finding in items
                    if _boolish_signal(finding, "waived")
                    or finding.status.lower().endswith("accepted")
                ),
                "suppressed_by_vex_count": sum(
                    1 for finding in items if _boolish_signal(finding, "suppressed_by_vex")
                ),
                "top_cves": [finding.cve_id for finding in items[:5]],
            }
        )
    rows.sort(
        key=lambda item: (
            -int(item["finding_count"]),
            str(item["business_service"] or ""),
            str(item["label"]),
        )
    )
    return rows


def _governance_finding_row(finding: MarkdownReportFinding) -> dict[str, Any]:
    waiver = _dict_value(finding.explanation.get("waiver"))
    return {
        "id": finding.id,
        "cve_id": finding.cve_id,
        "priority": _priority_label(finding.priority),
        "status": finding.status,
        "risk_score": finding.risk_score,
        "asset": finding.asset,
        "asset_key": finding.asset_key,
        "owner": finding.owner,
        "business_service": finding.business_service,
        "environment": finding.environment,
        "waived": _boolish_signal(finding, "waived"),
        "waiver_status": _string_from_mapping(waiver, "waiver_status")
        or _string_from_mapping(finding.explanation, "waiver_status"),
        "waiver_owner": _string_from_mapping(waiver, "waiver_owner")
        or _string_from_mapping(finding.explanation, "waiver_owner"),
        "waiver_expires_on": _string_from_mapping(waiver, "waiver_expires_on")
        or _string_from_mapping(finding.explanation, "waiver_expires_on"),
        "waiver_review_on": _string_from_mapping(waiver, "waiver_review_on")
        or _string_from_mapping(finding.explanation, "waiver_review_on"),
        "suppressed_by_vex": _boolish_signal(finding, "suppressed_by_vex"),
        "under_investigation": _boolish_signal(finding, "under_investigation"),
        "vex_statuses": _vex_statuses_label(finding),
        "decision_statement": finding.decision_statement,
    }


__all__ = ["_asset_context_rows", "_governance_finding_row"]
