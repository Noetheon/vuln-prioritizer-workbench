"""Narrative helpers for executive HTML reports."""

from __future__ import annotations

from typing import Any

from app.services.report_html_helpers import (
    _executive_verdict_summary_helper,
    _html_business_impact_table_helper,
)
from app.services.report_models import MarkdownReportFinding


def _executive_verdict_summary(payload: Any) -> str:
    return _executive_verdict_summary_helper(payload)


def _html_business_impact_table(findings: list[MarkdownReportFinding]) -> str:
    return _html_business_impact_table_helper(findings)


def _executive_summary_text(
    finding_count: int,
    critical_or_high: int,
    locked_provider_data: str,
) -> str:
    if finding_count == 0:
        return (
            "The analyzed run has no recorded findings. Confirm import coverage before "
            "treating this as a no-risk result."
        )
    return (
        f"The run contains {finding_count} finding(s), including {critical_or_high} "
        "critical or high priority item(s). Prioritize the listed top risks first and "
        "validate execution against provider freshness. "
        f"Locked provider data: {locked_provider_data}."
    )


def _business_impact_summary(findings: list[MarkdownReportFinding]) -> str:
    impacts = [finding.business_impact for finding in findings if finding.business_impact]
    if impacts:
        return impacts[0]
    assets = [finding.asset for finding in findings[:5] if finding.asset]
    if assets:
        return (
            "Business exposure is concentrated in the top ranked affected assets: "
            f"{', '.join(assets)}. Confirm owner, environment, and service criticality "
            "before final scheduling."
        )
    if findings:
        return (
            "Asset and owner context is not complete for the top findings. Treat missing "
            "business context as unverified and validate before accepting risk."
        )
    return "No business impact can be derived because no findings were recorded."


def _decision_statement(finding: MarkdownReportFinding) -> str:
    return finding.decision_statement or finding.recommended_action or "Review and assign an owner."


__all__ = [
    "_business_impact_summary",
    "_decision_statement",
    "_executive_summary_text",
    "_executive_verdict_summary",
    "_html_business_impact_table",
]
