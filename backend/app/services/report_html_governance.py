"""Governance rollup HTML helpers."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.services.report_formatting import dict_value as _dict_value
from app.services.report_formatting import format_number as _format_number
from app.services.report_formatting import safe_html as _safe_html
from app.services.report_html_components import _html_metric
from app.services.report_html_governance_states import html_governed_state_summary
from app.services.report_html_helpers import (
    _actionability_counts_helper,
    _is_under_investigation_finding,
)
from app.services.report_models import MarkdownReportFinding
from app.services.report_renderer_common import _dict_list


def _html_governance_rollups(
    governance_rollups: dict[str, Any],
    findings: list[MarkdownReportFinding],
    generated_at: datetime | None = None,
) -> str:
    waiver_debt = _dict_value(governance_rollups.get("waiver_debt"))
    waiver_items = _dict_list(waiver_debt.get("items"))[:5]
    actionability = _actionability_counts_helper(findings)
    under_investigation = sum(1 for finding in findings if _is_under_investigation_finding(finding))
    waiver_rows = "\n".join(_html_waiver_debt_row(item, generated_at) for item in waiver_items)
    if not waiver_rows:
        waiver_rows = (
            '<tr><td colspan="7" class="empty-state">'
            "No accepted-risk waiver debt is currently recorded for this run.</td></tr>"
        )
    return (
        '    <section aria-labelledby="governance">\n'
        '      <p class="eyebrow">Governance</p>\n'
        '      <h2 id="governance">Governance Exceptions</h2>\n'
        '      <div class="metric-grid">\n'
        f"        {_html_metric('Waivers', waiver_debt.get('waiver_count', 0))}\n"
        f"        {_html_metric('Expired', waiver_debt.get('expired_count', 0))}\n"
        f"        {_html_metric('Review Due', waiver_debt.get('review_due_count', 0))}\n"
        f"        {_html_metric('Expiring Soon', waiver_debt.get('expiring_soon_count', 0))}\n"
        "        "
        f"{_html_metric('Accepted Findings', actionability.get('accepted', 0))}\n"
        f"        {_html_metric('VEX Suppressed', actionability.get('suppressed', 0))}\n"
        f"        {_html_metric('Fixed Findings', actionability.get('fixed', 0))}\n"
        f"        {_html_metric('Under Investigation', under_investigation)}\n"
        "      </div>\n"
        f"{html_governed_state_summary(actionability, under_investigation)}\n"
        "      <h3>Accepted Risk and Waiver Review</h3>\n"
        '      <div class="table-wrap">\n'
        "        <table>\n"
        "          <thead>\n"
        "            <tr><th>Scope</th><th>Owner</th><th>Status</th><th>Expires</th>"
        "<th>Review</th><th>Matched Findings</th>"
        "<th>Required Governance Action</th></tr>\n"
        "          </thead>\n"
        f"          <tbody>\n{waiver_rows}\n          </tbody>\n"
        "        </table>\n"
        "      </div>\n"
        "    </section>"
    )


def _html_service_rollup_row(service: dict[str, Any]) -> str:
    waiver_debt_count = int(service.get("expired_waiver_count") or 0) + int(
        service.get("review_due_waiver_count") or 0
    )
    return (
        "            <tr>"
        f"<td>{_safe_html(service.get('label'))}</td>"
        f"<td>{_safe_html(service.get('finding_count', 0))}</td>"
        f"<td>{_safe_html(service.get('critical_count', 0))}</td>"
        f"<td>{_safe_html(service.get('high_count', 0))}</td>"
        f"<td>{_safe_html(_format_number(service.get('risk_score_total')))}</td>"
        f"<td>{_safe_html(waiver_debt_count)}</td>"
        "</tr>"
    )


def _html_asset_rollup_row(asset: dict[str, Any]) -> str:
    return (
        "            <tr>"
        f"<td>{_safe_html(asset.get('label'))}</td>"
        f"<td>{_safe_html(asset.get('finding_count', 0))}</td>"
        f"<td>{_safe_html(asset.get('critical_count', 0))}</td>"
        f"<td>{_safe_html(asset.get('high_count', 0))}</td>"
        f"<td>{_safe_html(_format_number(asset.get('risk_score_total')))}</td>"
        f"<td>{_safe_html(asset.get('accepted_count', 0))}</td>"
        f"<td>{_safe_html(asset.get('suppressed_by_vex_count', 0))}</td>"
        "</tr>"
    )


def _status_badge_helper(status: str) -> str:
    status_lower = str(status or "").strip().lower().replace("_", " ")
    if "overdue" in status_lower:
        return f'<span class="badge badge-critical">{status_lower}</span>'
    if "due" in status_lower:
        return f'<span class="badge badge-warning">{status_lower}</span>'
    if "active" in status_lower:
        return f'<span class="badge badge-info">{status_lower}</span>'
    return f'<span class="badge badge-neutral">{status_lower}</span>'


def _html_waiver_debt_row(item: dict[str, Any], generated_at: datetime | None = None) -> str:
    status = str(item.get("status") or "")
    review_at = item.get("review_at")
    status_badge = _status_badge_helper(status)
    required_action = "Accepted risk active"
    if generated_at and review_at:
        try:
            dt = datetime.strptime(review_at.split("T")[0], "%Y-%m-%d")
            if dt.date() < generated_at.date():
                status_badge = '<span class="badge badge-critical">review overdue</span>'
                required_action = "Review now"
            elif dt.date() == generated_at.date():
                status_badge = '<span class="badge badge-warning">review due</span>'
                required_action = "Review now"
        except ValueError:
            pass

    matched_findings = int(item.get("matched_findings") or 0)
    expires_at = item.get("expires_at")
    normalized_status = str(status or "").strip().lower()
    if required_action != "Review now":
        if normalized_status in {"expired", "review_due", "due"}:
            required_action = "Review now"
        elif normalized_status in {"expiring_soon", "active_expiring"}:
            required_action = "Review before expiry"
        elif matched_findings > 0:
            required_action = "Accepted risk active"
        else:
            required_action = "No immediate action"

    return (
        "            <tr>"
        f"<td>{_safe_html(item.get('scope'))}</td>"
        f"<td>{_safe_html(item.get('owner'))}</td>"
        f"<td>{status_badge}</td>"
        f"<td>{_safe_html(expires_at)}</td>"
        f"<td>{_safe_html(review_at)}</td>"
        f"<td>{_safe_html(matched_findings)}</td>"
        f"<td>{_safe_html(required_action)}</td>"
        "</tr>"
    )


def _status_label(value: object) -> str:
    text = str(value or "").strip().replace("_", " ")
    return text.title() if text else "N/A"


__all__ = [
    "_html_asset_rollup_row",
    "_html_governance_rollups",
    "_html_service_rollup_row",
    "_html_waiver_debt_row",
]
