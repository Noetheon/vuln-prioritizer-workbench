"""Governance rollup HTML helpers."""

from __future__ import annotations

from typing import Any

from app.services.report_formatting import dict_value as _dict_value
from app.services.report_formatting import format_number as _format_number
from app.services.report_formatting import safe_html as _safe_html
from app.services.report_html_components import _html_metric
from app.services.report_models import MarkdownReportFinding
from app.services.report_renderer_common import _dict_list, _governance_vex_summary


def _html_governance_rollups(
    governance_rollups: dict[str, Any],
    findings: list[MarkdownReportFinding],
) -> str:
    services = _dict_list(governance_rollups.get("top_services_by_risk"))[:5]
    assets = _dict_list(governance_rollups.get("top_assets_by_risk"))[:5]
    waiver_debt = _dict_value(governance_rollups.get("waiver_debt"))
    waiver_items = _dict_list(waiver_debt.get("items"))[:5]
    vex_summary = _governance_vex_summary(findings)
    service_rows = "\n".join(_html_service_rollup_row(service) for service in services)
    if not service_rows:
        service_rows = (
            '<tr><td colspan="6" class="empty-state">'
            "No service rollups are available for this analysis run.</td></tr>"
        )
    asset_rows = "\n".join(_html_asset_rollup_row(asset) for asset in assets)
    if not asset_rows:
        asset_rows = (
            '<tr><td colspan="7" class="empty-state">'
            "No asset rollups are available for this analysis run.</td></tr>"
        )
    waiver_rows = "\n".join(_html_waiver_debt_row(item) for item in waiver_items)
    if not waiver_rows:
        waiver_rows = (
            '<tr><td colspan="6" class="empty-state">'
            "No accepted-risk waiver debt is currently recorded for this run.</td></tr>"
        )
    return (
        '    <section aria-labelledby="governance-rollups">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Governance</p>\n'
        '        <h2 id="governance-rollups">Service Risk, Accepted Risk, and VEX</h2>\n'
        "      </div>\n"
        '      <div class="metric-grid">\n'
        f"        {_html_metric('Waivers', waiver_debt.get('waiver_count', 0))}\n"
        f"        {_html_metric('Expired', waiver_debt.get('expired_count', 0))}\n"
        f"        {_html_metric('Review Due', waiver_debt.get('review_due_count', 0))}\n"
        f"        {_html_metric('Expiring Soon', waiver_debt.get('expiring_soon_count', 0))}\n"
        "        "
        f"{_html_metric('Accepted Findings', waiver_debt.get('accepted_finding_count', 0))}\n"
        f"        {_html_metric('VEX Suppressed', vex_summary['suppressed_by_vex_count'])}\n"
        "      </div>\n"
        "      <h3>Service Rollup</h3>\n"
        '      <div class="table-wrap">\n'
        "        <table>\n"
        "          <thead>\n"
        "            <tr><th>Service</th><th>Findings</th><th>Critical</th><th>High</th>"
        "<th>Risk Score</th><th>Waiver Debt</th></tr>\n"
        "          </thead>\n"
        f"          <tbody>\n{service_rows}\n          </tbody>\n"
        "        </table>\n"
        "      </div>\n"
        "      <h3>Asset Rollup</h3>\n"
        '      <div class="table-wrap">\n'
        "        <table>\n"
        "          <thead>\n"
        "            <tr><th>Asset</th><th>Findings</th><th>Critical</th><th>High</th>"
        "<th>Risk Score</th><th>Accepted</th><th>VEX Suppressed</th></tr>\n"
        "          </thead>\n"
        f"          <tbody>\n{asset_rows}\n          </tbody>\n"
        "        </table>\n"
        "      </div>\n"
        "      <h3>Accepted Risk and Expiring Waivers</h3>\n"
        '      <div class="table-wrap">\n'
        "        <table>\n"
        "          <thead>\n"
        "            <tr><th>Scope</th><th>Owner</th><th>Status</th><th>Expires</th>"
        "<th>Review</th><th>Matched</th></tr>\n"
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


def _html_waiver_debt_row(item: dict[str, Any]) -> str:
    return (
        "            <tr>"
        f"<td>{_safe_html(item.get('scope'))}</td>"
        f"<td>{_safe_html(item.get('owner'))}</td>"
        f"<td>{_safe_html(item.get('status'))}</td>"
        f"<td>{_safe_html(item.get('expires_at'))}</td>"
        f"<td>{_safe_html(item.get('review_at'))}</td>"
        f"<td>{_safe_html(item.get('matched_findings', 0))}</td>"
        "</tr>"
    )


__all__ = [
    "_html_asset_rollup_row",
    "_html_governance_rollups",
    "_html_service_rollup_row",
    "_html_waiver_debt_row",
]
