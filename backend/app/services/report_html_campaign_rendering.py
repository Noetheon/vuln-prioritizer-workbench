"""Remediation campaign HTML rendering helpers."""

from __future__ import annotations

import re
from collections.abc import Sequence

from app.services.report_formatting import format_number as _format_number
from app.services.report_formatting import safe_html as _safe_html
from app.services.report_html_campaign_model import (
    _campaign_decision_statement,
    _campaign_requires_emergency,
    _campaign_scope_summary,
    _campaigns_label,
    _evidence_signal_summary,
    _get_remediation_campaigns_helper,
)
from app.services.report_html_common import (
    _actionability_summary_helper,
    _count_findings,
    _counted_or_full_list,
    _finding_actionability_bucket,
    _fixed_finding_count,
    _is_actionable_finding,
    _normalized_context_label,
    _pluralize,
    _short_list,
    _unique_values,
    render_safe_text_with_links,
)
from app.services.report_models import (
    MarkdownReportFinding,
    MarkdownReportPayload,
    RemediationCampaign,
)

_SLA_HOURS_PATTERN = re.compile(r"^(?P<label>.+?)\s*/\s*(?P<hours>\d+(?:\.\d+)?)h$")


def _executive_sla_label(label: str) -> str:
    """Return a compact SLA label for executive HTML display."""
    match = _SLA_HOURS_PATTERN.match(label.strip())
    if match is None:
        return label
    hours = float(match.group("hours"))
    if hours >= 72 and hours.is_integer() and int(hours) % 24 == 0:
        return f"{match.group('label')} / {int(hours) // 24}d"
    return label


def _html_evidence_signals_badges(campaign: RemediationCampaign) -> str:
    """Html evidence signals badges function."""
    badges = []
    if campaign.in_kev:
        badges.append("<span class='badge badge-critical'>KEV</span>")
    if campaign.max_epss is not None:
        epss_val = campaign.max_epss
        tone = (
            "badge-critical"
            if epss_val >= 0.1
            else "badge-high"
            if epss_val >= 0.01
            else "badge-neutral"
        )
        badges.append(f"<span class='badge {tone}'>EPSS {_format_number(epss_val)}</span>")
    if campaign.max_cvss is not None:
        cvss_val = campaign.max_cvss
        if cvss_val >= 9.0:
            tone = "badge-critical"
        elif cvss_val >= 7.0:
            tone = "badge-high"
        else:
            tone = "badge-neutral"
        badges.append(f"<span class='badge {tone}'>CVSS {_format_number(cvss_val)}</span>")
    technique_ids = campaign.attack_techniques
    for tech_id in technique_ids[:2]:
        badges.append(f"<span class='badge badge-info'>ATT&CK {tech_id}</span>")
    if not campaign.in_kev:
        badges.append("<span class='badge badge-neutral'>No KEV</span>")
    return f'<div class="signal-row">{"".join(badges)}</div>'


def _executive_verdict_summary_helper(payload: MarkdownReportPayload) -> str:
    """Executive verdict summary helper function."""
    total_findings = len(payload.findings)
    open_actionable = _count_findings(payload.findings, _is_actionable_finding)
    kev_backed = _count_findings(payload.findings, lambda finding: finding.in_kev)
    accepted_risk = _count_findings(
        payload.findings,
        lambda finding: _finding_actionability_bucket(finding) == "accepted",
    )
    vex_suppressed = _count_findings(
        payload.findings,
        lambda finding: _finding_actionability_bucket(finding) == "suppressed",
    )
    fixed_findings = _fixed_finding_count(payload.findings)

    filename = payload.filename or "source input"
    finding_word = "finding" if total_findings == 1 else "findings"

    open_phrase = (
        "1 finding is open and actionable"
        if open_actionable == 1
        else f"{open_actionable} findings are open and actionable"
    )
    kev_phrase = (
        "1 finding is KEV-backed" if kev_backed == 1 else f"{kev_backed} findings are KEV-backed"
    )
    accepted_phrase = (
        "1 finding is accepted risk"
        if accepted_risk == 1
        else f"{accepted_risk} findings are accepted risk"
    )
    vex_phrase = (
        "1 finding is VEX suppressed"
        if vex_suppressed == 1
        else f"{vex_suppressed} findings are VEX suppressed"
    )
    fixed_phrase = (
        "1 fixed finding is retained as evidence"
        if fixed_findings == 1
        else f"{fixed_findings} fixed findings are retained as evidence"
    )

    campaigns = _get_remediation_campaigns_helper(payload.findings)
    open_campaigns = [campaign for campaign in campaigns if campaign.actionable_count > 0]
    emergency_campaigns = [
        campaign for campaign in open_campaigns if _campaign_requires_emergency(campaign)
    ]
    if emergency_campaigns:
        top_campaigns = _campaigns_label(emergency_campaigns, limit=5)
        remaining_open = max(0, len(open_campaigns) - len(emergency_campaigns))
        focus_sentence = f"Immediate focus: {top_campaigns}."
        if remaining_open:
            focus_sentence += (
                f" Track {_pluralize(remaining_open, 'remaining open remediation campaign')} "
                "in the follow-on plan before governance exceptions are formally signed off."
            )
        else:
            focus_sentence += " Complete validation before formal sign-off."
    elif open_campaigns:
        top_campaigns = _campaigns_label(open_campaigns, limit=5)
        focus_sentence = (
            f"Immediate focus: {top_campaigns}. Confirm owners, remediation windows and "
            "validation evidence before formal sign-off."
        )
    elif campaigns:
        focus_sentence = (
            "No open remediation campaign needs approval; retain governance and fixed evidence "
            "for sign-off."
        )
    else:
        focus_sentence = "Confirm import coverage before treating this run as a no-risk result."
    return (
        f"This run analyzed {total_findings} {finding_word} from {filename}. "
        f"{open_phrase}, {kev_phrase}, {accepted_phrase}, {vex_phrase} and {fixed_phrase}. "
        f"{focus_sentence}"
    )


def _html_business_services_prose_helper(findings: Sequence[MarkdownReportFinding]) -> str:
    """Html business services prose helper function."""
    if not findings:
        return "<p class='empty-state'>No business services at risk recorded.</p>"

    services: dict[str, list[MarkdownReportFinding]] = {}
    for finding in findings:
        service = finding.business_service or "Infrastructure / Shared Services"
        services.setdefault(service, []).append(finding)

    service_open_counts = {
        service: _count_findings(f_list, _is_actionable_finding)
        for service, f_list in services.items()
    }

    sorted_services = sorted(service_open_counts.items(), key=lambda x: -x[1])
    highest_services = [s for s, count in sorted_services if count > 0]

    internet_prod_services = []
    for service, f_list in services.items():
        has_internet_prod = any(
            _is_actionable_finding(f)
            and (f.exposure or "").lower() in {"internet-facing", "external"}
            and (f.environment or "").lower() in {"prod", "production"}
            for f in f_list
        )
        if has_internet_prod:
            internet_prod_services.append(service)

    accepted_services = []
    for service, f_list in services.items():
        has_accepted = any(_finding_actionability_bucket(f) == "accepted" for f in f_list)
        if has_accepted:
            accepted_services.append(service)

    all_owners = set()
    for service, f_list in services.items():
        if _count_findings(f_list, _is_actionable_finding) > 0:
            for f in f_list:
                if f.owner and f.owner.strip():
                    all_owners.add(f.owner.strip())
    owners_list = sorted(all_owners)

    prose_parts = []

    if highest_services:
        top_services_str = _short_list(highest_services, limit=3, noun="service")
        prose_parts.append(
            "Vulnerability exposure is concentrated in "
            f"{top_services_str} with active actionable findings."
        )
    else:
        prose_parts.append(
            "There are no active open actionable findings across the business services."
        )

    if internet_prod_services:
        internet_services_str = _short_list(internet_prod_services, limit=3, noun="service")
        prose_parts.append(
            f"Critical internet-facing production exposure is present in: {internet_services_str}."
        )

    if accepted_services:
        accepted_services_str = _short_list(accepted_services, limit=3, noun="service")
        prose_parts.append(
            "Active accepted risk exceptions or waiver debt are currently recorded for: "
            f"{accepted_services_str}."
        )

    if owners_list:
        owners_str = _short_list(owners_list, limit=3, noun="owner")
        prose_parts.append(
            f"Assigned service owners who must prioritize remediation include: {owners_str}."
        )
    else:
        prose_parts.append("No active owners are assigned to the currently open findings.")

    if internet_prod_services:
        prose_parts.append(
            "Management decision: Approve emergency patch windows for internet-facing "
            "production assets, review governance exceptions for internal hosts, "
            "and require clean re-import validation."
        )
    elif highest_services:
        prose_parts.append(
            "Management decision: Schedule standard remediation cycles and assign owners "
            "for all unassigned findings."
        )
    else:
        prose_parts.append(
            "Management decision: Monitor remaining exceptions and ensure evidence records "
            "are preserved."
        )

    return f"<p class='lede business-impact-lede'>{_safe_html(' '.join(prose_parts))}</p>"


def _html_business_impact_table_helper(
    findings: Sequence[MarkdownReportFinding], project_name: str | None = None
) -> str:
    """Html business impact table helper function."""
    prose = _html_business_services_prose_helper(findings)
    if not findings:
        return prose + (
            '<p class="empty-state">No business service risk can be derived because no '
            "findings were recorded.</p>"
        )

    services: dict[str, list[MarkdownReportFinding]] = {}
    for finding in findings:
        service = finding.business_service or "Infrastructure / Shared Services"
        services.setdefault(service, []).append(finding)
    campaigns = _get_remediation_campaigns_helper(findings, project_name=project_name)

    def campaigns_for_service(service_name: str) -> list[RemediationCampaign]:
        """Campaigns for service function."""
        return [
            campaign
            for campaign in campaigns
            if (
                service_name in campaign.services
                or (not campaign.services and service_name == "Infrastructure / Shared Services")
            )
        ]

    rows = []
    for service, service_findings in sorted(
        services.items(),
        key=lambda item: (
            -_count_findings(item[1], _is_actionable_finding),
            -_count_findings(item[1], lambda finding: finding.in_kev),
            item[0],
        ),
    ):
        owners = _unique_values(service_findings, lambda finding: finding.owner)
        owner_str = _counted_or_full_list(owners, noun="owner") if owners else "Unassigned"
        exposures = _unique_values(service_findings, lambda finding: finding.exposure)
        exposure_str = _counted_or_full_list(
            [_normalized_context_label(exposure) for exposure in exposures],
            noun="exposure",
        )
        environments = _unique_values(service_findings, lambda finding: finding.environment)
        environment_str = _counted_or_full_list(
            [_normalized_context_label(environment) for environment in environments],
            noun="environment",
        )
        service_campaigns = campaigns_for_service(service)
        open_campaign_count = sum(
            1 for campaign in service_campaigns if campaign.actionable_count > 0
        )
        emergency_campaign_count = sum(
            1 for campaign in service_campaigns if _campaign_requires_emergency(campaign)
        )

        open_count = _count_findings(service_findings, _is_actionable_finding)
        accepted_count = _count_findings(
            service_findings,
            lambda finding: _finding_actionability_bucket(finding) == "accepted",
        )
        suppressed_count = _count_findings(
            service_findings,
            lambda finding: _finding_actionability_bucket(finding) == "suppressed",
        )
        fixed_count = _fixed_finding_count(service_findings)

        governed_risk_parts = []
        if accepted_count:
            governed_risk_parts.append(_pluralize(accepted_count, "accepted risk"))
        if suppressed_count:
            governed_risk_parts.append(_pluralize(suppressed_count, "VEX suppressed"))
        if fixed_count:
            governed_risk_parts.append(_pluralize(fixed_count, "fixed evidence"))
        governed_risk_str = ", ".join(governed_risk_parts) or "0 accepted, 0 VEX suppressed"

        if emergency_campaign_count:
            decision = "Emergency remediation"
            badge_class = "badge-critical"
            validation = "Clean re-import and fixed evidence before closure"
        elif open_campaign_count:
            decision = "Remediation scheduling"
            badge_class = "badge-high"
            validation = "Owner validation and clean re-import"
        elif accepted_count:
            decision = "Governance review"
            badge_class = "badge-warning"
            validation = "Risk owner review record"
        elif suppressed_count or fixed_count:
            decision = "Evidence validation"
            badge_class = "badge-success"
            validation = "Retain VEX or fixed evidence in bundle"
        else:
            decision = "Monitor"
            badge_class = "badge-neutral"
            validation = "No active validation request"

        rows.append(
            f"            <tr>"
            f"<td><strong>{_safe_html(service)}</strong></td>"
            f"<td>{_safe_html(str(open_campaign_count))} campaigns / "
            f"{_safe_html(str(open_count))} findings</td>"
            f"<td>{_safe_html(governed_risk_str)}</td>"
            f"<td>{_safe_html(str(emergency_campaign_count))}</td>"
            f"<td>{_safe_html(environment_str)} / {_safe_html(exposure_str)}</td>"
            f"<td>{_safe_html(owner_str)}</td>"
            f"<td><span class='badge {badge_class}'>{_safe_html(decision)}</span></td>"
            f"<td>{_safe_html(validation)}</td>"
            f"</tr>"
        )

    return (
        prose + "\n"
        '      <div class="table-wrap">\n'
        "        <table>\n"
        "          <thead>\n"
        "            <tr><th>Service</th><th>Open Actionable</th><th>Governed Risk</th>"
        "<th>Emergency Campaigns</th><th>Environment / Exposure</th><th>Owner</th>"
        "<th>Decision Needed</th><th>Validation Evidence</th></tr>\n"
        "          </thead>\n"
        "          <tbody>\n"
        f"{chr(10).join(rows)}\n"
        "          </tbody>\n"
        "        </table>\n"
        "      </div>"
    )


def _html_remediation_campaigns_helper(
    findings: Sequence[MarkdownReportFinding], project_name: str | None = None
) -> str:
    """Html remediation campaigns helper function."""
    campaigns = _get_remediation_campaigns_helper(findings, project_name=project_name)
    if not campaigns:
        return '<p class="empty-state">No remediation campaigns are available for this run.</p>'

    rows = []
    for campaign in campaigns[:10]:
        owners = (
            _compact_campaign_list(campaign.owners, limit=2, noun="owner")
            if campaign.owners
            else "Unassigned"
        )
        services = (
            _compact_campaign_list(campaign.services, limit=2, noun="service")
            if campaign.services
            else "Unknown service"
        )
        actionability = _actionability_summary_helper(campaign.findings)

        priority_class = (
            "badge-critical"
            if campaign.priority_label == "P1"
            else "badge-high"
            if campaign.priority_label in {"P2", "P3"}
            else "badge-neutral"
        )
        actionability_class = (
            "badge-critical"
            if _campaign_requires_emergency(campaign)
            else "badge-high"
            if campaign.actionable_count > 0
            else "badge-neutral"
        )

        decision_stmt = _campaign_decision_statement(campaign)
        decision_html = f"{_safe_html(decision_stmt)}"
        cluster_html = _campaign_cluster_cell(campaign)

        rows.append(
            "        <tr>"
            f"<td><span class='badge {priority_class}'>{campaign.priority_label}</span></td>"
            f"<td>{cluster_html}</td>"
            f"<td><span class='badge {actionability_class}'>"
            f"{_safe_html(actionability)}</span></td>"
            f"<td>{_safe_html(_campaign_scope_summary(campaign))}</td>"
            f"<td>{_safe_html(services)}</td>"
            f"<td>{_safe_html(owners)}</td>"
            f"<td>{_html_evidence_signals_badges(campaign)}</td>"
            f"<td>{decision_html}</td>"
            "</tr>"
        )

    return (
        '<div class="table-wrap">\n'
        "  <table class='campaign-table'>\n"
        "    <thead>\n"
        "      <tr><th>Priority</th><th>Risk Cluster</th><th>Actionability</th>"
        "<th>Scope</th><th>Business Services</th><th>Owners</th>"
        "<th>Evidence Signals</th><th>Decision Statement</th></tr>\n"
        "    </thead>\n"
        f"    <tbody>\n{chr(10).join(rows)}\n    </tbody>\n"
        "  </table>\n"
        "</div>"
    )


def _campaign_cluster_cell(campaign: RemediationCampaign) -> str:
    """Render campaign title and CVE separately so the table does not over-wrap."""
    title = campaign.alias or campaign.campaign_name
    if title == campaign.cve_id:
        return f"<strong>{_safe_html(campaign.cve_id)}</strong>"
    return (
        f"<strong class='campaign-cluster-title'>{_safe_html(title)}</strong>"
        f"<span class='mono-dim campaign-cluster-cve'>{_safe_html(campaign.cve_id)}</span>"
    )


def _compact_campaign_list(
    values: Sequence[str],
    *,
    limit: int,
    noun: str,
) -> str:
    """Return compact service/owner copy for dense executive tables."""
    shown = [str(value) for value in values[:limit] if value]
    if not shown:
        return "N/A"
    remaining = max(0, len(values) - len(shown))
    if not remaining:
        return ", ".join(shown)
    suffix = noun if remaining == 1 else f"{noun}s"
    return f"{', '.join(shown)} +{remaining} {suffix}"


def _html_deduplicated_recommendations_helper(
    findings: Sequence[MarkdownReportFinding], project_name: str | None = None
) -> str:
    """Html deduplicated recommendations helper function."""
    campaigns = _get_remediation_campaigns_helper(findings, project_name=project_name)
    if not campaigns:
        return "<li>No remediation recommendations are available for this run.</li>"

    titles_map = {
        "CVE-2021-44228": "CVE-2021-44228 / Log4Shell remediation campaign",
        "CVE-2022-22965": "CVE-2022-22965 / Spring4Shell remediation campaign",
        "CVE-2023-34362": "CVE-2023-34362 / MOVEit transfer campaign",
        "CVE-2024-4577": "CVE-2024-4577 / PHP CGI campaign",
        "CVE-2023-44487": "CVE-2023-44487 / Edge HTTP/2 campaign",
        "CVE-2020-1472": "CVE-2020-1472 / Identity controller campaign",
        "CVE-2024-3094": "CVE-2024-3094 / XZ Utils campaign",
    }

    items = []
    for campaign in campaigns:
        cve_id = campaign.cve_id
        alias = campaign.alias

        campaign_title = titles_map.get(
            cve_id,
            (
                f"{cve_id} / {alias} remediation campaign"
                if alias
                else f"{cve_id} remediation campaign"
            ),
        )

        owners = (
            _short_list(campaign.owners, limit=3, noun="owner") if campaign.owners else "Unassigned"
        )
        services = (
            _short_list(campaign.services, limit=3, noun="service")
            if campaign.services
            else "Unknown service"
        )
        action_str = (
            campaign.actions[0] if campaign.actions else (_campaign_decision_statement(campaign))
        )
        if campaign.slas:
            sla_str = _executive_sla_label(campaign.slas[0])
        elif _campaign_requires_emergency(campaign):
            sla_str = "Emergency / 24h"
        else:
            sla_str = "Standard patch cycle"
        prose = (
            f"Scope: {_campaign_scope_summary(campaign)}; services: {services}. "
            f"Status: {_actionability_summary_helper(campaign.findings)}. "
            f"Recommended action: {action_str}. SLA: {sla_str}. Owners: {owners}. "
            f"Evidence basis: {_evidence_signal_summary(campaign)}."
        )

        items.append(
            f"<li><strong>{_safe_html(campaign_title)}</strong>"
            f"<span>{render_safe_text_with_links(prose)}</span></li>"
        )

    return "\n".join(items)


def _html_top_critical_risks_helper(
    findings: Sequence[MarkdownReportFinding], project_name: str | None = None
) -> str:
    """Render the lead-with-these top critical risk cards."""
    campaigns = _get_remediation_campaigns_helper(findings, project_name=project_name)
    top_candidates = [campaign for campaign in campaigns if campaign.actionable_count > 0]
    top_candidates.sort(
        key=lambda campaign: (
            0 if _campaign_requires_emergency(campaign) else 1,
            campaign.rank,
        )
    )
    top = top_candidates[:3]
    if not top:
        return (
            '<p class="empty-state">No open actionable critical risks to highlight for this run.'
            "</p>"
        )

    cards = []
    for position, campaign in enumerate(top, start=1):
        priority_class = (
            "badge-critical"
            if campaign.priority_label == "P1"
            else "badge-high"
            if campaign.priority_label in {"P2", "P3"}
            else "badge-neutral"
        )
        title = campaign.alias or campaign.campaign_name
        action = _campaign_decision_statement(campaign)
        scope = _safe_html(_campaign_scope_summary(campaign))
        cards.append(
            '    <article class="risk-card">\n'
            '      <div class="risk-card-head">'
            f'<span class="risk-card-rank">Priority {position:02d}</span>'
            f"<span class='badge {priority_class}'>{_safe_html(campaign.priority_label)}</span>"
            "</div>\n"
            f'      <p class="risk-card-cve">{_safe_html(campaign.cve_id)}</p>\n'
            f'      <h3 class="risk-card-name">{_safe_html(title)}</h3>\n'
            f'      <p class="risk-card-scope">{scope}</p>\n'
            f"      {_html_evidence_signals_badges(campaign)}\n"
            '      <p class="risk-card-action"><span class="status-label">Action</span>'
            f"{render_safe_text_with_links(action)}</p>\n"
            "    </article>"
        )
    return '<div class="risk-cards">\n' + "\n".join(cards) + "\n  </div>"


def _recommendation_sla_label(campaign: RemediationCampaign) -> tuple[str, str]:
    """Return the executive-facing SLA label and badge class for a campaign row."""
    if campaign.actionable_count > 0:
        if campaign.slas:
            sla = _executive_sla_label(campaign.slas[0])
        elif _campaign_requires_emergency(campaign):
            sla = "Emergency / 24h"
        else:
            sla = "Standard patch cycle"
        badge_class = "badge-critical" if _campaign_requires_emergency(campaign) else "badge-high"
        return sla, badge_class
    if campaign.accepted_count:
        return "Governance review", "badge-warning"
    if campaign.vex_count:
        return "Evidence", "badge-success"
    if campaign.fixed_count:
        return "Retain evidence", "badge-success"
    return "Evidence", "badge-neutral"


def _recommendation_status_label(campaign: RemediationCampaign) -> tuple[str, str]:
    """Return the actionability status label and badge class for a recommendation row."""
    if campaign.actionable_count > 0:
        badge_class = "badge-critical" if _campaign_requires_emergency(campaign) else "badge-high"
        return _actionability_summary_helper(campaign.findings), badge_class
    if campaign.accepted_count:
        return _actionability_summary_helper(campaign.findings), "badge-warning"
    if campaign.vex_count or campaign.fixed_count:
        return _actionability_summary_helper(campaign.findings), "badge-success"
    return _actionability_summary_helper(campaign.findings), "badge-neutral"


def _html_recommendations_table_helper(
    findings: Sequence[MarkdownReportFinding], project_name: str | None = None
) -> str:
    """Render decision-ready recommendations as a scannable table."""
    campaigns = _get_remediation_campaigns_helper(findings, project_name=project_name)
    if not campaigns:
        return (
            '<p class="empty-state">No remediation recommendations are available for this run.</p>'
        )

    rows = []
    for campaign in campaigns:
        sla, sla_class = _recommendation_sla_label(campaign)
        status, status_class = _recommendation_status_label(campaign)
        action = campaign.actions[0] if campaign.actions else _campaign_decision_statement(campaign)
        owners = (
            _short_list(campaign.owners, limit=3, noun="owner") if campaign.owners else "Unassigned"
        )
        title = campaign.alias or campaign.campaign_name
        rows.append(
            "        <tr>"
            f"<td><span class='badge {sla_class}'>{_safe_html(sla)}</span></td>"
            f"<td><strong>{_safe_html(title)}</strong><br>"
            f"<span class='mono-dim'>{_safe_html(campaign.cve_id)}</span></td>"
            f"<td><span class='badge {status_class}'>{_safe_html(status)}</span></td>"
            f"<td>{_safe_html(_campaign_scope_summary(campaign))}</td>"
            f"<td>{render_safe_text_with_links(action)}</td>"
            f"<td>{_safe_html(owners)}</td>"
            f"<td>{_html_evidence_signals_badges(campaign)}</td>"
            "</tr>"
        )
    return (
        '<div class="table-wrap">\n'
        "  <table class='recommendation-table'>\n"
        "    <thead>\n"
        "      <tr><th>SLA</th><th>CVE / Campaign</th><th>Status</th><th>Scope</th>"
        "<th>Recommended Fix</th><th>Owners</th><th>Signals</th></tr>\n"
        "    </thead>\n"
        f"    <tbody>\n{chr(10).join(rows)}\n    </tbody>\n"
        "  </table>\n"
        "</div>"
    )


__all__ = [
    "_html_evidence_signals_badges",
    "_executive_verdict_summary_helper",
    "_html_business_services_prose_helper",
    "_html_business_impact_table_helper",
    "_html_remediation_campaigns_helper",
    "_html_top_critical_risks_helper",
    "_html_recommendations_table_helper",
    "_recommendation_sla_label",
    "_recommendation_status_label",
    "_executive_sla_label",
    "_html_deduplicated_recommendations_helper",
]
