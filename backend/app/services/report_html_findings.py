"""Finding rows for executive HTML reports."""

from __future__ import annotations

from app.services.report_formatting import format_number as _format_number
from app.services.report_formatting import safe_html as _safe_html
from app.services.report_html_narrative import _decision_statement
from app.services.report_models import MarkdownReportFinding
from app.services.report_renderer_common import _priority_label


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


def _html_recommendation_item(finding: MarkdownReportFinding) -> str:
    sla = f" SLA: {finding.decision_sla}" if finding.decision_sla else ""
    action = finding.recommended_action or _decision_statement(finding)
    heading = f"{finding.cve_id} - {_priority_label(finding.priority)}"
    return (
        "        <li>"
        f"<strong>{_safe_html(heading)}</strong>"
        f"<span>{_safe_html(action + sla)}</span>"
        "</li>"
    )


__all__ = ["_html_recommendation_item", "_html_top_risk_row"]
