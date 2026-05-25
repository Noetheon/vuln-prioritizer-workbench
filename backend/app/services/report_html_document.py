"""Executive HTML document composition."""

from __future__ import annotations

from app.services.report_html_attack_context import _html_attack_context_table_helper
from app.services.report_html_campaign_rendering import _html_business_impact_table_helper
from app.services.report_html_decision import (
    _html_action_plan_table_helper,
    _html_decision_signoff_helper,
    _html_risk_metric_definitions_helper,
)
from app.services.report_html_evidence_package import _html_evidence_package_table_helper
from app.services.report_html_provider_freshness import _html_provider_snapshot_helper
from app.services.report_html_view_model import build_executive_report_view_model
from app.services.report_models import EvidencePackageContext, MarkdownReportPayload


def render_html_executive_report_helper(
    payload: MarkdownReportPayload,
    *,
    evidence_package_context: EvidencePackageContext | None = None,
) -> str:
    """Render html executive report helper function."""
    from app.services.report_formatting import iso_datetime as _iso_datetime
    from app.services.report_formatting import safe_html as _safe_html
    from app.services.report_html_components import _html_metric
    from app.services.report_html_findings import (
        _html_deduplicated_recommendations,
        _html_remediation_campaigns,
    )
    from app.services.report_html_governance import _html_governance_rollups
    from app.services.report_html_styles import EXECUTIVE_REPORT_CSS as _EXECUTIVE_REPORT_CSS
    from app.services.report_renderer_common import _redacted_bundle_payload

    payload, _redactions = _redacted_bundle_payload(payload)
    view_model = build_executive_report_view_model(
        payload,
        evidence_package_context=evidence_package_context,
    )
    risk_posture = view_model.risk_posture
    decision_brief = view_model.decision_brief
    identity = view_model.report_identity
    finding_count = risk_posture["total_findings"]
    generated_at_dt = payload.generated_at
    generated_at = _safe_html(_iso_datetime(generated_at_dt))
    snapshot = payload.provider_snapshot

    if finding_count == 0:
        verdict_banner = (
            '      <div class="verdict-banner">\n'
            "        <p>No findings were recorded for this analysis run.</p>\n"
            "        <p>Confirm import coverage before treating this as a no-risk result.</p>\n"
            "      </div>"
        )
    else:
        verdict_banner = (
            '      <div class="verdict-banner">\n'
            "        <p><strong>Decision needed:</strong> "
            f"{_safe_html(decision_brief['decision_needed'])}</p>\n"
            f"        <p>{_safe_html(decision_brief['executive_summary'])}</p>\n"
            "      </div>"
        )

    approval_items = "".join(
        f"            <li>{_safe_html(item)}</li>\n"
        for item in decision_brief["management_approval_items"]
    )
    caution_items = "".join(
        f"            <li>{_safe_html(item)}</li>\n" for item in decision_brief["caution_items"]
    )
    validation_items = "".join(
        f"            <li>{_safe_html(item)}</li>\n" for item in decision_brief["validation_items"]
    )
    decision_grid = (
        '      <div class="decision-grid decision-grid--three">\n'
        '        <div class="decision-card">\n'
        '          <span class="status-label">What management should approve</span>\n'
        "          <ul>\n"
        f"{approval_items}"
        "          </ul>\n"
        "        </div>\n"
        '        <div class="decision-card">\n'
        '          <span class="status-label">What requires caution</span>\n'
        "          <ul>\n"
        f"{caution_items}"
        "          </ul>\n"
        "        </div>\n"
        '        <div class="decision-card">\n'
        '          <span class="status-label">What must be validated after remediation</span>\n'
        "          <ul>\n"
        f"{validation_items}"
        "          </ul>\n"
        "        </div>\n"
        "      </div>"
    )
    signoff_panel = _html_decision_signoff_helper(view_model)

    action_plan_table = _html_action_plan_table_helper(payload)
    campaigns_section = _html_remediation_campaigns(
        payload.findings,
        project_name=payload.project_name,
    )
    business_impact_table = _html_business_impact_table_helper(
        payload.findings,
        project_name=payload.project_name,
    )
    governance_section = (
        _html_governance_rollups(
            payload.governance_rollups,
            payload.findings,
            generated_at_dt,
        )
        + "\n\n"
    )
    has_attack_layer = bool(view_model.attack_context["mapped_techniques"])
    evidence_package_table = _html_evidence_package_table_helper(
        has_attack_layer=has_attack_layer,
        has_governance=bool(payload.governance_rollups),
        evidence_package_context=evidence_package_context,
    )
    attack_context_table = _html_attack_context_table_helper(payload.findings)
    recommendations_list = _html_deduplicated_recommendations(
        payload.findings,
        project_name=payload.project_name,
    )
    header_lede = (
        "Decision oriented vulnerability prioritization report for CISO and stakeholder "
        "review. This report summarizes actionable remediation campaigns, governance "
        "exceptions and evidence confidence for the current analysis run."
    )
    provider_snapshot_id = identity["provider_snapshot_id"] or "N/A"
    provider_snapshot_html = _html_provider_snapshot_helper(
        snapshot,
        generated_at_dt,
        project_name=payload.project_name,
        evidence_package_context=evidence_package_context,
    )
    appendix_note = (
        f"{view_model.technical_appendix['note']} This Executive HTML report intentionally "
        "summarizes the decision path for stakeholder review."
    )

    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '  <meta charset="utf-8">\n'
        '  <meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "  <title>Executive Vulnerability Report</title>\n"
        "  <style>\n"
        f"{_EXECUTIVE_REPORT_CSS}\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        '  <main class="report-shell">\n'
        "    <header>\n"
        '      <p class="eyebrow">Executive Evidence Brief</p>\n'
        f"      <h1>{_safe_html(identity['project_name'])}</h1>\n"
        f'      <p class="lede">{_safe_html(header_lede)}</p>\n'
        '      <dl class="meta-grid">\n'
        f"        <div><dt>Report Type</dt><dd>{_safe_html(identity['report_type'])}</dd></div>\n"
        f"        <div><dt>Project ID</dt><dd>{_safe_html(identity['project_id'])}</dd></div>\n"
        "        <div><dt>Project Name</dt><dd>"
        f"{_safe_html(identity['project_name'])}</dd></div>\n"
        "        <div><dt>Analysis Run ID</dt><dd>"
        f"{_safe_html(identity['analysis_run_id'])}</dd></div>\n"
        f"        <div><dt>Generated At</dt><dd>{generated_at}</dd></div>\n"
        f"        <div><dt>Run Status</dt><dd>{_safe_html(identity['run_status'])}</dd></div>\n"
        f"        <div><dt>Input Type</dt><dd>{_safe_html(identity['input_type'])}</dd></div>\n"
        f"        <div><dt>Input File</dt><dd>{_safe_html(identity['input_file'])}</dd></div>\n"
        "        <div><dt>Provider Snapshot</dt><dd>"
        f"{_safe_html(provider_snapshot_id)}</dd></div>\n"
        "      </dl>\n"
        "    </header>\n"
        "\n"
        '    <section aria-labelledby="decision-brief">\n'
        '      <p class="eyebrow">Decision Required</p>\n'
        '      <h2 id="decision-brief">Decision Brief</h2>\n'
        f"{verdict_banner}\n"
        f"{decision_grid}\n"
        f"{signoff_panel}\n"
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="risk-posture">\n'
        '      <p class="eyebrow">Risk Posture</p>\n'
        '      <h2 id="risk-posture">Executive Risk Posture</h2>\n'
        '      <div class="metric-grid">\n'
        f"        {_html_metric('Total Findings', risk_posture['total_findings'])}\n"
        f"        {_html_metric('Open Actionable', risk_posture['open_actionable_findings'])}\n"
        f"        {_html_metric('KEV Backed', risk_posture['kev_backed_findings'])}\n"
        f"        {_html_metric('Emergency SLA Campaigns', risk_posture['emergency_sla_count'])}\n"
        f"        {_html_metric('Accepted Risk', risk_posture['accepted_risk_findings'])}\n"
        f"        {_html_metric('VEX Suppressed', risk_posture['vex_suppressed_findings'])}\n"
        f"        {_html_metric('Fixed Evidence', risk_posture['fixed_evidence_findings'])}\n"
        "        "
        f"{_html_metric('Review Due / Expiring', risk_posture['review_due_or_expiring_count'])}\n"
        "        "
        f"{_html_metric('Internet Facing Prod', risk_posture['internet_facing_prod_count'])}\n"
        f"        {_html_metric('Unique CVEs', risk_posture['unique_cves_count'])}\n"
        "        "
        f"{_html_metric('Provider Freshness', risk_posture['provider_freshness_verdict'])}\n"
        f"        {_html_metric('Evidence Bundle Ready', risk_posture['evidence_bundle_status'])}\n"
        "      </div>\n"
        f"{_html_risk_metric_definitions_helper()}\n"
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="action-plan">\n'
        '      <p class="eyebrow">Action Plan</p>\n'
        '      <h2 id="action-plan">First 24h and 7d Action Plan</h2>\n'
        f"      {action_plan_table}\n"
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="campaigns">\n'
        '      <p class="eyebrow">Remediation</p>\n'
        '      <h2 id="campaigns">Top Remediation Campaigns</h2>\n'
        f"      {campaigns_section}\n"
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="business-services">\n'
        '      <p class="eyebrow">Business Impact</p>\n'
        '      <h2 id="business-services">Business Services at Risk</h2>\n'
        f"      {business_impact_table}\n"
        "    </section>\n"
        "\n"
        f"{governance_section}"
        "\n"
        '    <section aria-labelledby="evidence">\n'
        '      <p class="eyebrow">Evidence</p>\n'
        '      <h2 id="evidence">Evidence Confidence and Provider Freshness</h2>\n'
        f"{provider_snapshot_html}\n"
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="evidence-package">\n'
        '      <p class="eyebrow">Evidence Bundle</p>\n'
        '      <h2 id="evidence-package">Evidence Package Contents</h2>\n'
        f"      {evidence_package_table}\n"
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="recommendations">\n'
        '      <p class="eyebrow">Recommendations</p>\n'
        '      <h2 id="recommendations">Decision Ready Recommendations</h2>\n'
        f'      <ol class="recommendation-list">\n{recommendations_list}\n      </ol>\n'
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="attack">\n'
        '      <p class="eyebrow">SOC Context</p>\n'
        '      <h2 id="attack">ATT&amp;CK/TTP Context</h2>\n'
        f"      {attack_context_table}\n"
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="appendix">\n'
        '      <p class="eyebrow">Appendix</p>\n'
        '      <h2 id="appendix">Technical Appendix note</h2>\n'
        f'      <p class="footer-note">{_safe_html(appendix_note)}</p>\n'
        "    </section>\n"
        "  </main>\n"
        "</body>\n"
        "</html>\n"
    )


__all__ = [
    "render_html_executive_report_helper",
]
