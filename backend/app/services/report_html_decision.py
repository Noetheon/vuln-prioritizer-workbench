"""Action plan and decision sign-off helpers for executive HTML reports."""

from __future__ import annotations

from collections.abc import Sequence

from app.services.report_formatting import safe_html as _safe_html
from app.services.report_html_campaign_model import (
    _campaign_evidence_label,
    _campaign_requires_emergency,
    _campaigns_label,
    _first_available_owner,
    _get_remediation_campaigns_helper,
)
from app.services.report_html_common import (
    _count_findings,
    _finding_actionability_bucket,
    _pluralize,
    render_safe_text_with_links,
)
from app.services.report_models import (
    ActionPlanRow,
    ExecutiveReportViewModel,
    MarkdownReportPayload,
    RemediationCampaign,
    RiskPosture,
)

_RISK_INDEX_BANDS: dict[str, tuple[str, str]] = {
    "critical": ("Critical band, immediate action", "critical"),
    "elevated": ("Elevated band, prioritized remediation", "warning"),
    "low": ("Low band, routine handling", "success"),
    "none": ("No open actionable findings to score", "neutral"),
}


def _campaign_scope_sentence(campaigns: Sequence[RemediationCampaign], *, limit: int = 5) -> str:
    """Return a grammatical campaign scope sentence without duplicating list nouns."""
    if not campaigns:
        return "No emergency campaigns active"
    label = _campaigns_label(campaigns, limit=limit)
    if len(campaigns) > limit:
        return f"{label}."
    suffix = " campaign." if len(campaigns) == 1 else " campaigns."
    return f"{label}{suffix}"


def _blankable_html(value: object | None) -> str:
    """Escape HTML while preserving intentionally blank sign-off fields."""
    if value is None:
        return ""
    text = str(value).strip()
    return _safe_html(text) if text else ""


def _html_risk_index_panel_helper(risk_posture: RiskPosture) -> str:
    """Render the headline risk index gauge for the decision hero."""
    index = risk_posture.risk_index
    label, tone = _RISK_INDEX_BANDS.get(risk_posture.risk_index_band, _RISK_INDEX_BANDS["none"])
    if index is None:
        value_html = '<span class="risk-index-value">N/A</span>'
        needle = ""
        foot = "No open, non-accepted finding carries a risk score for this run."
    else:
        value_html = (
            f'<span class="risk-index-value">{index}<span class="risk-index-max">/100</span></span>'
        )
        needle = f'<span class="risk-gauge-needle" style="left:{index}%;"></span>'
        foot = (
            "Mean risk score across "
            f"{_pluralize(risk_posture.risk_index_population, 'open, non-accepted finding')}. "
            "Accepted risk, VEX suppressed and fixed-evidence findings are excluded."
        )
    return (
        f'      <div class="risk-index" data-tone="{tone}">\n'
        '        <span class="status-label">Risk Index, open and non-accepted</span>\n'
        f"        {value_html}\n"
        f'        <p class="risk-index-band">{_safe_html(label)}</p>\n'
        f'        <div class="risk-gauge">{needle}</div>\n'
        '        <div class="risk-gauge-scale"><span>0 low</span><span>40</span>'
        "<span>70</span><span>100 crit</span></div>\n"
        f'        <p class="risk-index-foot">{_safe_html(foot)}</p>\n'
        "      </div>"
    )


def _html_stale_data_alert_helper(view_model: ExecutiveReportViewModel) -> str:
    """
    Render a prominent provider-freshness alert when intelligence data is not current.

    Returns an empty string when freshness is acceptable so the section can be omitted.
    """
    verdict = view_model.risk_posture.provider_freshness_verdict
    if verdict not in {"Warning", "Stale"}:
        return ""
    stale_rows = [
        row
        for row in view_model.evidence_confidence.provider_rows
        if str(row.get("status")) in {"Stale", "Warning", "Needs Review"}
        and any(tag in str(row.get("signal", "")) for tag in ("NVD", "EPSS", "KEV"))
    ]
    chips = "".join(
        '<span class="stale-chip">'
        f"{_safe_html(row.get('signal'))}: <b>{_safe_html(row.get('value'))}</b> "
        f"&middot; {_safe_html(row.get('status'))}</span>"
        for row in stale_rows
    )
    chips_html = f'\n          <div class="stale-chips">{chips}</div>' if chips else ""
    return (
        '    <section aria-labelledby="freshness-alert">\n'
        '      <p class="eyebrow">Data Freshness</p>\n'
        f'      <h2 id="freshness-alert">Provider Intelligence is {_safe_html(verdict)}</h2>\n'
        '      <div class="stale-alert">\n'
        '        <span class="stale-flag">STALE DATA</span>\n'
        '        <div class="stale-body">\n'
        "          <strong>The snapshot is reproducible but not necessarily current.</strong>\n"
        '          <p class="stale-text">Locked provider data guarantees a deterministic, '
        "auditable replay, but it does not mean the intelligence is fresh. Re-import live "
        "NVD, EPSS and KEV data before treating this brief as current external intelligence "
        "for formal risk sign-off.</p>"
        f"{chips_html}\n"
        "        </div>\n"
        "      </div>\n"
        "    </section>"
    )


def _action_plan_rows_helper(payload: MarkdownReportPayload) -> list[ActionPlanRow]:
    """Action plan rows helper function."""
    campaigns = _get_remediation_campaigns_helper(payload.findings)
    open_campaigns = [campaign for campaign in campaigns if campaign.actionable_count > 0]
    emergency_campaigns = [
        campaign for campaign in open_campaigns if _campaign_requires_emergency(campaign)
    ]
    waiver_debt = payload.governance_rollups.get("waiver_debt", {})
    waiver_items = waiver_debt.get("items", [])
    review_due = int(waiver_debt.get("review_due_count") or 0)
    expiring_soon = int(waiver_debt.get("expiring_soon_count") or 0)
    accepted_count = _count_findings(
        payload.findings,
        lambda finding: _finding_actionability_bucket(finding) == "accepted",
    )

    if emergency_campaigns:
        first_scope = _campaign_scope_sentence(emergency_campaigns, limit=5)
        first_action = (
            "Approve 24h remediation for KEV-backed or critical production exposure "
            "and start validation tracking."
        )
        first_owner = _first_available_owner(emergency_campaigns)
        first_evidence = _campaign_evidence_label(emergency_campaigns)
    else:
        first_scope = "No emergency campaigns active"
        first_action = (
            "Confirm no 24h emergency remediation is required for KEV-backed or critical "
            "internet-facing campaigns."
        )
        first_owner = "Security owner"
        first_evidence = "Grouped campaign analysis"

    seventy_two_scope = "All open actionable findings and any VEX under investigation."
    seventy_two_action = (
        "Confirm owners, patch status and interim compensating controls for campaigns "
        "not yet closed."
    )
    seventy_two_owner = "Security owner plus service owners"
    seventy_two_evidence = "Technical Markdown, findings CSV, owner rollups and validation notes."

    seven_day_scope = "All remediation campaigns and fixed evidence."
    seven_day_action = (
        "Perform clean re-import, close fixed evidence and preserve the evidence package "
        "for audit review."
    )
    seven_day_owner = "Security operations and platform owners"
    seven_day_evidence = "Evidence ZIP, manifest, provider snapshot and analysis JSON."

    gov_parts = []
    if waiver_count := len(waiver_items):
        gov_parts.append(_pluralize(waiver_count, "waiver"))
    if review_due:
        gov_parts.append(f"{review_due} review due")
    if expiring_soon:
        gov_parts.append(f"{expiring_soon} expiring soon")
    if accepted_count:
        gov_parts.append(_pluralize(accepted_count, "accepted risk finding"))
    if gov_parts:
        governance_scope = ", ".join(gov_parts)
        governed_context = []
        vex_count = _count_findings(
            payload.findings,
            lambda finding: _finding_actionability_bucket(finding) == "suppressed",
        )
        if vex_count:
            governed_context.append(_pluralize(vex_count, "VEX suppressed finding"))
        if governed_context:
            governance_scope = f"{governance_scope}; {', '.join(governed_context)}."
    else:
        vex_count = _count_findings(
            payload.findings,
            lambda finding: _finding_actionability_bucket(finding) == "suppressed",
        )
        if vex_count:
            governance_scope = (
                f"No waiver debt recorded; {_pluralize(vex_count, 'VEX suppressed finding')}."
            )
        else:
            governance_scope = "No waiver debt recorded; no VEX suppressed findings."

    governance_action = (
        "Review due waiver, expiring waiver, accepted risks and VEX suppressed findings "
        "before formal risk sign-off."
    )
    governance_owner = "Risk owner and security owner"
    governance_evidence = "Waiver records, VEX overlays and governance artifacts."

    return [
        ActionPlanRow(
            time_window="24h",
            action=first_action,
            scope=first_scope,
            owner=first_owner,
            evidence_basis=first_evidence,
        ),
        ActionPlanRow(
            time_window="72h",
            action=seventy_two_action,
            scope=seventy_two_scope,
            owner=seventy_two_owner,
            evidence_basis=seventy_two_evidence,
        ),
        ActionPlanRow(
            time_window="7d",
            action=seven_day_action,
            scope=seven_day_scope,
            owner=seven_day_owner,
            evidence_basis=seven_day_evidence,
        ),
        ActionPlanRow(
            time_window="Governance review",
            action=governance_action,
            scope=governance_scope,
            owner=governance_owner,
            evidence_basis=governance_evidence,
        ),
    ]


def _html_action_plan_table_helper(payload: MarkdownReportPayload) -> str:
    """Html action plan table helper function."""
    action_rows = _action_plan_rows_helper(payload)
    rows = [
        "<tr>"
        f"<td><strong>{_safe_html(row.time_window)}</strong></td>"
        f"<td>{render_safe_text_with_links(row.action)}</td>"
        f"<td>{_safe_html(row.scope)}</td>"
        f"<td>{_safe_html(row.owner)}</td>"
        f"<td>{render_safe_text_with_links(row.evidence_basis)}</td>"
        "</tr>"
        for row in action_rows
    ]
    return (
        '<div class="table-wrap">\n'
        "  <table class='compact-table action-plan-table'>\n"
        "    <thead>\n"
        "      <tr><th>Time Window</th><th>Action</th><th>Scope</th>"
        "<th>Owner</th><th>Evidence Basis</th></tr>\n"
        "    </thead>\n"
        f"    <tbody>\n      {chr(10).join(rows)}\n    </tbody>\n"
        "  </table>\n"
        "</div>"
    )


def _decision_needed_statement_helper(
    campaigns: list[RemediationCampaign],
    *,
    provider_freshness: str,
    review_due_or_expiring: int,
) -> str:
    """Decision needed statement helper function."""
    open_campaigns = [campaign for campaign in campaigns if campaign.actionable_count > 0]
    emergency_campaigns = [
        campaign for campaign in open_campaigns if _campaign_requires_emergency(campaign)
    ]
    owner_gap_count = sum(1 for campaign in open_campaigns if not campaign.owners)
    parts: list[str] = []
    if emergency_campaigns:
        parts.append(
            f"Approve {_pluralize(len(emergency_campaigns), 'emergency remediation campaign')} "
            "for 24h action now"
        )
    elif open_campaigns:
        parts.append(
            "Approve owners and remediation windows for "
            f"{_pluralize(len(open_campaigns), 'open campaign')}"
        )
    else:
        parts.append("Confirm no active remediation campaign requires approval")
    if provider_freshness in {"Warning", "Stale"}:
        parts.append(
            "defer formal risk sign-off until provider data is refreshed and clean validation "
            "evidence is attached"
        )
    else:
        parts.append(
            "complete formal risk sign-off only after clean validation evidence is attached"
        )
    if owner_gap_count:
        parts.append(f"assign owners for {_pluralize(owner_gap_count, 'unowned campaign')}")
    else:
        parts.append("confirm assigned owners for the top remediation campaigns")
    if review_due_or_expiring:
        parts.append(
            f"review {_pluralize(review_due_or_expiring, 'due or expiring governance item')}"
        )
    return "; ".join(parts) + "."


def _html_risk_metric_definitions_helper() -> str:
    """Html risk metric definitions helper function."""
    definitions = [
        (
            "Open Actionable",
            "Findings that still require remediation or mitigation after accepted risk, "
            "VEX suppressed and fixed evidence states are separated.",
        ),
        ("KEV-Backed", "Findings with a CISA KEV catalog signal."),
        (
            "Emergency SLA Campaigns",
            "Remediation campaigns with open actionable KEV, critical CVSS or "
            "critical EPSS signals.",
        ),
        (
            "Fixed Evidence",
            "Findings retained as fixed-state validation evidence, not active remediation work.",
        ),
        (
            "Review Due or Expiring",
            "Waiver or accepted-risk governance items due, overdue or nearing expiry.",
        ),
        (
            "Internet-Facing Prod",
            "Open actionable findings on production assets with internet-facing or "
            "external exposure.",
        ),
        (
            "Provider Freshness",
            "Deterministic verdict from centralized NVD, EPSS and KEV freshness thresholds.",
        ),
        (
            "Evidence Bundle Ready",
            "Expected evidence ZIP contents can be generated for offline audit review.",
        ),
    ]
    rows = [
        f"<tr><td><strong>{_safe_html(term)}</strong></td><td>{_safe_html(definition)}</td></tr>"
        for term, definition in definitions
    ]
    return (
        "      <h3>Metric Definitions</h3>\n"
        "      <div class='table-wrap'>\n"
        "        <table class='compact-table'>\n"
        "          <thead><tr><th>Metric</th><th>Definition</th></tr></thead>\n"
        f"          <tbody>{''.join(rows)}</tbody>\n"
        "        </table>\n"
        "      </div>"
    )


def _html_decision_signoff_helper(view_model: ExecutiveReportViewModel) -> str:
    """Html decision signoff helper function."""
    identity = view_model.report_identity
    evidence_status = view_model.risk_posture.evidence_bundle_status
    evidence_reference = (
        "manifest.json in Evidence ZIP"
        if evidence_status == "Ready"
        else "Generate Evidence ZIP to record manifest.json"
    )
    rows = [
        ("Decision owner", ""),
        ("Approval outcome", ""),
        ("Decision date", ""),
        ("Evidence package reference", evidence_reference),
        ("Validation required", "Clean re-import and fixed evidence before closure"),
        ("Analysis run", identity.analysis_run_id or "N/A"),
        ("Notes", ""),
    ]
    row_html = "\n".join(
        f"          <div><dt>{_safe_html(label)}</dt><dd>{_blankable_html(value)}</dd></div>"
        for label, value in rows
    )
    return (
        '      <div class="signoff-panel" aria-label="Printable decision sign-off">\n'
        '        <span class="status-label">Printable decision sign-off</span>\n'
        '        <dl class="signoff-grid">\n'
        f"{row_html}\n"
        "        </dl>\n"
        "      </div>"
    )


__all__ = [
    "_action_plan_rows_helper",
    "_html_action_plan_table_helper",
    "_decision_needed_statement_helper",
    "_html_risk_index_panel_helper",
    "_html_risk_metric_definitions_helper",
    "_html_stale_data_alert_helper",
    "_html_decision_signoff_helper",
]
