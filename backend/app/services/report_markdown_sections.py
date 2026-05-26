"""Markdown section helpers for Workbench technical reports."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.services.report_formatting import dict_value as _dict_value
from app.services.report_formatting import format_number as _format_number
from app.services.report_formatting import safe_cell as _safe_cell
from app.services.report_models import MarkdownReportFinding
from app.services.report_renderer_common import (
    _dict_list,
    _governance_vex_summary,
)


def _markdown_governance_section(
    governance_rollups: dict[str, Any],
    findings: Sequence[MarkdownReportFinding],
) -> list[str]:
    services = _dict_list(governance_rollups.get("top_services_by_risk"))[:5]
    assets = _dict_list(governance_rollups.get("top_assets_by_risk"))[:5]
    owners = _dict_list(governance_rollups.get("owners"))[:5]
    environments = _dict_list(governance_rollups.get("environments"))[:5]
    waiver_debt = _dict_value(governance_rollups.get("waiver_debt"))
    waiver_items = _dict_list(waiver_debt.get("items"))[:5]
    vex_summary = _governance_vex_summary(findings)
    lines = [
        "",
        "## Governance Rollups",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Waivers | {_safe_cell(waiver_debt.get('waiver_count', 0))} |",
        f"| Active Waivers | {_safe_cell(waiver_debt.get('active_count', 0))} |",
        f"| Expired Waivers | {_safe_cell(waiver_debt.get('expired_count', 0))} |",
        f"| Review Due Waivers | {_safe_cell(waiver_debt.get('review_due_count', 0))} |",
        f"| Expiring Soon Waivers | {_safe_cell(waiver_debt.get('expiring_soon_count', 0))} |",
        f"| Accepted Findings | {_safe_cell(waiver_debt.get('accepted_finding_count', 0))} |",
        f"| VEX Suppressed Findings | {_safe_cell(vex_summary['suppressed_by_vex_count'])} |",
        f"| VEX Under Investigation | {_safe_cell(vex_summary['under_investigation_count'])} |",
        "",
        "### Top Services by Risk",
        "",
    ]
    if not services:
        lines.append("No service rollups are available for this analysis run.")
    else:
        lines.extend(
            [
                "| Service | Findings | Critical | High | Risk Score | Waiver Debt |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for service in services:
            waiver_debt_count = int(service.get("expired_waiver_count") or 0) + int(
                service.get("review_due_waiver_count") or 0
            )
            lines.append(
                "| "
                + " | ".join(
                    [
                        _safe_cell(service.get("label")),
                        _safe_cell(service.get("finding_count", 0)),
                        _safe_cell(service.get("critical_count", 0)),
                        _safe_cell(service.get("high_count", 0)),
                        _safe_cell(_format_number(service.get("risk_score_total"))),
                        _safe_cell(waiver_debt_count),
                    ]
                )
                + " |"
            )
    lines.extend(
        [
            "",
            "### Top Assets by Risk",
            "",
        ]
    )
    if not assets:
        lines.append("No asset rollups are available for this analysis run.")
    else:
        lines.extend(
            [
                "| Asset | Findings | Critical | High | Risk Score | Accepted | VEX Suppressed |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for asset in assets:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _safe_cell(asset.get("label")),
                        _safe_cell(asset.get("finding_count", 0)),
                        _safe_cell(asset.get("critical_count", 0)),
                        _safe_cell(asset.get("high_count", 0)),
                        _safe_cell(_format_number(asset.get("risk_score_total"))),
                        _safe_cell(asset.get("accepted_count", 0)),
                        _safe_cell(asset.get("suppressed_by_vex_count", 0)),
                    ]
                )
                + " |"
            )
    lines.extend(
        [
            "",
            "### Accepted Risk and Expiring Waivers",
            "",
        ]
    )
    if waiver_items:
        lines.extend(
            [
                "| Scope | Owner | Status | Expires | Review | Matched Findings |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for item in waiver_items:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _safe_cell(item.get("scope")),
                        _safe_cell(item.get("owner")),
                        _safe_cell(item.get("status")),
                        _safe_cell(item.get("expires_at")),
                        _safe_cell(item.get("review_at")),
                        _safe_cell(item.get("matched_findings", 0)),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No accepted-risk waiver debt is currently recorded for this run.")

    lines.extend(
        [
            "",
            "### Owner and Environment Rollups",
            "",
            "| Dimension | Label | Findings | Critical | High | Accepted | Waiver Debt |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for dimension, rows in (("Owner", owners), ("Environment", environments)):
        for row in rows:
            waiver_debt_count = int(row.get("expired_waiver_count") or 0) + int(
                row.get("review_due_waiver_count") or 0
            )
            lines.append(
                "| "
                + " | ".join(
                    [
                        _safe_cell(dimension),
                        _safe_cell(row.get("label")),
                        _safe_cell(row.get("finding_count", 0)),
                        _safe_cell(row.get("critical_count", 0)),
                        _safe_cell(row.get("high_count", 0)),
                        _safe_cell(row.get("accepted_count", 0)),
                        _safe_cell(waiver_debt_count),
                    ]
                )
                + " |"
            )
    if not owners and not environments:
        lines.append("| Owner | Unassigned | 0 | 0 | 0 | 0 | 0 |")

    lines.extend(
        [
            "",
            "### VEX Summary",
            "",
            "| Field | Value |",
            "| --- | --- |",
            f"| Suppressed by VEX | {_safe_cell(vex_summary['suppressed_by_vex_count'])} |",
            f"| Under Investigation | {_safe_cell(vex_summary['under_investigation_count'])} |",
            f"| Fixed | {_safe_cell(vex_summary['fixed_count'])} |",
        ]
    )
    return lines


def _markdown_detection_coverage_section(detection_coverage: dict[str, Any]) -> list[str]:
    summary = _dict_value(detection_coverage.get("summary"))
    weak_items = [
        item
        for item in _dict_list(detection_coverage.get("items"))
        if str(item.get("coverage_level")) in {"partial", "not_covered", "unknown"}
    ][:5]
    lines = [
        "",
        "## Detection Coverage",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Covered | {_safe_cell(summary.get('covered', 0))} |",
        f"| Partial | {_safe_cell(summary.get('partial', 0))} |",
        f"| Not Covered | {_safe_cell(summary.get('not_covered', 0))} |",
        f"| Unknown | {_safe_cell(summary.get('unknown', 0))} |",
        "",
        (
            "Detection coverage is operator-supplied defensive review evidence; "
            "it is not proof of security or exploitation."
        ),
    ]
    if weak_items:
        lines.extend(
            [
                "",
                "### Coverage Gaps",
                "",
                "| Technique | Coverage | Findings | Owner | Action |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for item in weak_items:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _safe_cell(item.get("technique_id")),
                        _safe_cell(item.get("coverage_level")),
                        _safe_cell(item.get("finding_count", 0)),
                        _safe_cell(item.get("owner") or "Unassigned"),
                        _safe_cell(item.get("recommended_action")),
                    ]
                )
                + " |"
            )
    return lines


__all__ = [
    "_markdown_detection_coverage_section",
    "_markdown_governance_section",
]
