"""Executive HTML Workbench report renderer."""

from __future__ import annotations

from app.services.report_formatting import iso_datetime as _iso_datetime
from app.services.report_formatting import metadata_bool as _metadata_bool
from app.services.report_formatting import safe_html as _safe_html
from app.services.report_html_components import _html_metric
from app.services.report_html_findings import (
    _html_recommendation_item,
    _html_top_risk_row,
)
from app.services.report_html_governance import (
    _html_asset_rollup_row,
    _html_governance_rollups,
    _html_service_rollup_row,
    _html_waiver_debt_row,
)
from app.services.report_html_narrative import (
    _business_impact_summary,
    _decision_statement,
    _executive_summary_text,
)
from app.services.report_html_provider import _html_provider_snapshot
from app.services.report_html_styles import EXECUTIVE_REPORT_CSS as _EXECUTIVE_REPORT_CSS
from app.services.report_models import MarkdownReportPayload
from app.services.report_renderer_common import (
    _counts_by_priority,
    _redacted_bundle_payload,
)

EXECUTIVE_REPORT_CSS = _EXECUTIVE_REPORT_CSS


def render_html_executive_report(payload: MarkdownReportPayload) -> str:
    """Render a deterministic, escaped executive HTML report."""
    payload, _redactions = _redacted_bundle_payload(payload)
    finding_count = len(payload.findings)
    counts = _counts_by_priority(payload.findings)
    top_findings = payload.findings[:10]
    critical_or_high = counts["Critical"] + counts["High"]
    generated_at = _safe_html(_iso_datetime(payload.generated_at))
    snapshot = payload.provider_snapshot
    locked_provider_data = (
        _metadata_bool(snapshot.source_metadata, "locked_provider_data")
        if snapshot is not None
        else "N/A"
    )
    executive_summary = _executive_summary_text(
        finding_count,
        critical_or_high,
        locked_provider_data,
    )

    rows = "\n".join(_html_top_risk_row(finding) for finding in top_findings)
    if not rows:
        rows = (
            '<tr><td colspan="9" class="empty-state">'
            "No findings were recorded for this analysis run.</td></tr>"
        )

    recommendations = "\n".join(_html_recommendation_item(finding) for finding in top_findings[:5])
    if not recommendations:
        recommendations = "<li>No remediation recommendations are available for this run.</li>"
    governance_section = (
        f"{_html_governance_rollups(payload.governance_rollups, payload.findings)}\n\n"
        if payload.governance_rollups
        else ""
    )

    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '  <meta charset="utf-8">\n'
        '  <meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "  <title>Executive Vulnerability Report</title>\n"
        "  <style>\n"
        f"{EXECUTIVE_REPORT_CSS}\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        '  <main class="report-shell">\n'
        "    <header>\n"
        '      <p class="eyebrow">Executive Vulnerability Report</p>\n'
        f"      <h1>{_safe_html(payload.project_name)}</h1>\n"
        '      <p class="lede">Decision-ready vulnerability prioritization summary '
        f"for analysis run {_safe_html(payload.run_id)} generated at {generated_at}.</p>\n"
        '      <dl class="meta-grid">\n'
        f"        <div><dt>Project ID</dt><dd>{_safe_html(payload.project_id)}</dd></div>\n"
        f"        <div><dt>Run Status</dt><dd>{_safe_html(payload.run_status)}</dd></div>\n"
        f"        <div><dt>Input Type</dt><dd>{_safe_html(payload.input_type)}</dd></div>\n"
        f"        <div><dt>Input File</dt><dd>{_safe_html(payload.filename)}</dd></div>\n"
        "      </dl>\n"
        "    </header>\n"
        "\n"
        '    <section aria-labelledby="executive-summary">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Summary</p>\n'
        '        <h2 id="executive-summary">Executive Summary</h2>\n'
        "      </div>\n"
        '      <div class="metric-grid">\n'
        f"        {_html_metric('Findings', finding_count)}\n"
        f"        {_html_metric('Critical', counts['Critical'])}\n"
        f"        {_html_metric('High', counts['High'])}\n"
        f"        {_html_metric('Critical or High', critical_or_high)}\n"
        "      </div>\n"
        "      <p>"
        f"{_safe_html(executive_summary)}"
        "</p>\n"
        "    </section>\n"
        "\n"
        f"{governance_section}"
        '    <section aria-labelledby="business-impact">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Impact</p>\n'
        '        <h2 id="business-impact">Business Impact</h2>\n'
        "      </div>\n"
        f"      <p>{_safe_html(_business_impact_summary(payload.findings))}</p>\n"
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="top-risks">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Priorities</p>\n'
        '        <h2 id="top-risks">Top Risks</h2>\n'
        "      </div>\n"
        '      <div class="table-wrap">\n'
        "        <table>\n"
        "          <thead>\n"
        "            <tr><th>Rank</th><th>CVE</th><th>Priority</th><th>Score</th>"
        "<th>EPSS</th><th>CVSS</th><th>KEV</th><th>Asset</th>"
        "<th>Decision Statement</th></tr>\n"
        "          </thead>\n"
        f"          <tbody>\n{rows}\n          </tbody>\n"
        "        </table>\n"
        "      </div>\n"
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="recommendations">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Actions</p>\n'
        '        <h2 id="recommendations">Recommendations</h2>\n'
        "      </div>\n"
        f'      <ol class="recommendation-list">\n{recommendations}\n      </ol>\n'
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="provider-freshness">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Evidence</p>\n'
        '        <h2 id="provider-freshness">Provider Freshness</h2>\n'
        "      </div>\n"
        f"{_html_provider_snapshot(snapshot)}\n"
        "    </section>\n"
        "  </main>\n"
        "</body>\n"
        "</html>\n"
    )


__all__ = [
    "EXECUTIVE_REPORT_CSS",
    "_business_impact_summary",
    "_decision_statement",
    "_executive_summary_text",
    "_html_asset_rollup_row",
    "_html_governance_rollups",
    "_html_metric",
    "_html_provider_snapshot",
    "_html_recommendation_item",
    "_html_service_rollup_row",
    "_html_top_risk_row",
    "_html_waiver_debt_row",
    "render_html_executive_report",
]
