"""Finding rows and campaign groups for executive HTML reports."""

from __future__ import annotations

from app.services.report_formatting import format_number as _format_number
from app.services.report_formatting import safe_html as _safe_html
from app.services.report_html_helpers import (
    _actionability_summary_helper,
    _get_remediation_campaigns_helper,
    _html_deduplicated_recommendations_helper,
    _html_remediation_campaigns_helper,
)
from app.services.report_html_narrative import _decision_statement
from app.services.report_models import MarkdownReportFinding
from app.services.report_renderer_common import _priority_label


def _html_remediation_campaigns(
    findings: list[MarkdownReportFinding], project_name: str | None = None
) -> str:
    return _html_remediation_campaigns_helper(findings, project_name=project_name)


def _html_deduplicated_recommendations(
    findings: list[MarkdownReportFinding], project_name: str | None = None
) -> str:
    return _html_deduplicated_recommendations_helper(findings, project_name=project_name)


def _actionability_summary(findings: list[MarkdownReportFinding]) -> str:
    return _actionability_summary_helper(findings)


def _get_remediation_campaigns(findings: list[MarkdownReportFinding]) -> list[dict[str, object]]:
    return _get_remediation_campaigns_helper(findings)


def _html_top_risk_row(finding: MarkdownReportFinding) -> str:
    priority = _priority_label(finding.priority)
    priority_class = f"badge-{priority.lower()}"
    return (
        "            <tr>"
        f"<td>{finding.operational_rank}</td>"
        f"<td>{_safe_html(finding.cve_id)}</td>"
        f'<td><span class="badge {priority_class}">{_safe_html(priority)}</span></td>'
        f"<td>{_safe_html(_format_number(finding.risk_score))}</td>"
        f"<td>{_safe_html(_format_number(finding.epss))}</td>"
        f"<td>{_safe_html(_format_number(finding.cvss_base_score))}</td>"
        f"<td>{'Yes' if finding.in_kev else 'No'}</td>"
        f"<td>{_safe_html(finding.asset)}</td>"
        f"<td>{_safe_html(_decision_statement(finding))}</td>"
        "</tr>"
    )


__all__ = [
    "_actionability_summary",
    "_get_remediation_campaigns",
    "_html_top_risk_row",
    "_html_remediation_campaigns",
    "_html_deduplicated_recommendations",
]
