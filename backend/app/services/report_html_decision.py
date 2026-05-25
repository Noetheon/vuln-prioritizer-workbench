"""Action plan and decision sign-off helpers for executive HTML reports."""

from __future__ import annotations

from typing import Any

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
from app.services.report_models import ExecutiveReportViewModel, MarkdownReportPayload


def _action_plan_rows_helper(payload: MarkdownReportPayload) -> list[dict[str, str]]:
    """Action plan rows helper function."""
    campaigns = _get_remediation_campaigns_helper(payload.findings)
    open_campaigns = [campaign for campaign in campaigns if campaign["actionable_count"] > 0]
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
        first_scope = f"{_campaigns_label(emergency_campaigns, limit=5)} campaigns."
        first_action = (
            "Approve emergency remediation for open KEV backed production findings "
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
        "Perform clean re import, close fixed evidence and preserve the evidence package "
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
        "before formal risk sign off."
    )
    governance_owner = "Risk owner and security owner"
    governance_evidence = "Waiver records, VEX overlays and governance artifacts."

    return [
        {
            "time_window": "24h",
            "action": first_action,
            "scope": first_scope,
            "owner": first_owner,
            "evidence_basis": first_evidence,
        },
        {
            "time_window": "72h",
            "action": seventy_two_action,
            "scope": seventy_two_scope,
            "owner": seventy_two_owner,
            "evidence_basis": seventy_two_evidence,
        },
        {
            "time_window": "7d",
            "action": seven_day_action,
            "scope": seven_day_scope,
            "owner": seven_day_owner,
            "evidence_basis": seven_day_evidence,
        },
        {
            "time_window": "Governance review",
            "action": governance_action,
            "scope": governance_scope,
            "owner": governance_owner,
            "evidence_basis": governance_evidence,
        },
    ]


def _html_action_plan_table_helper(payload: MarkdownReportPayload) -> str:
    """Html action plan table helper function."""
    action_rows = _action_plan_rows_helper(payload)
    rows = [
        "<tr>"
        f"<td><strong>{_safe_html(row['time_window'])}</strong></td>"
        f"<td>{render_safe_text_with_links(row['action'])}</td>"
        f"<td>{_safe_html(row['scope'])}</td>"
        f"<td>{_safe_html(row['owner'])}</td>"
        f"<td>{render_safe_text_with_links(row['evidence_basis'])}</td>"
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
    campaigns: list[dict[str, Any]],
    *,
    provider_freshness: str,
    review_due_or_expiring: int,
) -> str:
    """Decision needed statement helper function."""
    open_campaigns = [campaign for campaign in campaigns if campaign["actionable_count"] > 0]
    emergency_campaigns = [
        campaign for campaign in open_campaigns if _campaign_requires_emergency(campaign)
    ]
    owner_gap_count = sum(1 for campaign in open_campaigns if not campaign["owners"])
    parts: list[str] = []
    if emergency_campaigns:
        parts.append(
            f"Approve {_pluralize(len(emergency_campaigns), 'emergency remediation campaign')} "
            "within 24h"
        )
    elif open_campaigns:
        parts.append(
            "Approve owners and remediation windows for "
            f"{_pluralize(len(open_campaigns), 'open campaign')}"
        )
    else:
        parts.append("Confirm no active remediation campaign requires approval")
    if owner_gap_count:
        parts.append(f"assign owners for {_pluralize(owner_gap_count, 'unowned campaign')}")
    else:
        parts.append("confirm assigned owners for the top remediation campaigns")
    if review_due_or_expiring:
        parts.append(
            f"review {_pluralize(review_due_or_expiring, 'due or expiring governance item')}"
        )
    if provider_freshness in {"Warning", "Stale"}:
        parts.append(f"treat provider freshness as {provider_freshness.lower()} before sign-off")
    parts.append("require clean validation evidence after re-import")
    return "; ".join(parts) + "."


def _html_risk_metric_definitions_helper() -> str:
    """Html risk metric definitions helper function."""
    definitions = [
        (
            "Open Actionable",
            "Findings that still require remediation or mitigation after accepted risk, "
            "VEX suppressed and fixed evidence states are separated.",
        ),
        ("KEV Backed", "Findings with a CISA KEV catalog signal."),
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
            "Internet Facing Prod",
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
    evidence_status = view_model.risk_posture.get("evidence_bundle_status", "Expected")
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
        ("Analysis run", str(identity.get("analysis_run_id") or "N/A")),
        ("Notes", ""),
    ]
    row_html = "\n".join(
        f"          <div><dt>{_safe_html(label)}</dt><dd>{_safe_html(value)}</dd></div>"
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
    "_html_risk_metric_definitions_helper",
    "_html_decision_signoff_helper",
]
