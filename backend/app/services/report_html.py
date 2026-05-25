"""Executive HTML Workbench report renderer."""

from __future__ import annotations

from app.services.report_html_components import _html_metric
from app.services.report_html_findings import (
    _actionability_summary,
    _get_remediation_campaigns,
    _html_top_risk_row,
)
from app.services.report_html_governance import (
    _html_asset_rollup_row,
    _html_governance_rollups,
    _html_service_rollup_row,
    _html_waiver_debt_row,
)
from app.services.report_html_helpers import (
    build_executive_report_view_model,
    render_html_executive_report_helper,
)
from app.services.report_html_narrative import (
    _business_impact_summary,
    _decision_statement,
    _executive_summary_text,
)
from app.services.report_html_provider import (
    _html_provider_snapshot,
    _provider_freshness_rows,
    _provider_freshness_status,
)
from app.services.report_html_styles import EXECUTIVE_REPORT_CSS as _EXECUTIVE_REPORT_CSS
from app.services.report_models import EvidencePackageContext, MarkdownReportPayload

EXECUTIVE_REPORT_CSS = _EXECUTIVE_REPORT_CSS


def render_html_executive_report(
    payload: MarkdownReportPayload,
    *,
    evidence_package_context: EvidencePackageContext | None = None,
) -> str:
    """Render a deterministic, escaped executive HTML report."""
    return render_html_executive_report_helper(
        payload,
        evidence_package_context=evidence_package_context,
    )


__all__ = [
    "EXECUTIVE_REPORT_CSS",
    "_actionability_summary",
    "_business_impact_summary",
    "_decision_statement",
    "_executive_summary_text",
    "_get_remediation_campaigns",
    "_html_asset_rollup_row",
    "_html_governance_rollups",
    "_html_metric",
    "_html_provider_snapshot",
    "_html_service_rollup_row",
    "_html_top_risk_row",
    "_html_waiver_debt_row",
    "_provider_freshness_rows",
    "_provider_freshness_status",
    "build_executive_report_view_model",
    "render_html_executive_report",
]
