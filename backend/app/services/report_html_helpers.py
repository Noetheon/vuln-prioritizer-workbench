"""HTML report rendering helper functions and data grouping logic."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from app.services.report_formatting import format_number as _format_number
from app.services.report_formatting import safe_html as _safe_html
from app.services.report_models import (
    MarkdownProviderSnapshot,
    MarkdownReportFinding,
    MarkdownReportPayload,
)
from app.services.report_renderer_common import _boolish_signal, _list_value, _priority_label

CVE_ALIASES = {
    "CVE-2021-44228": "Log4Shell",
    "CVE-2022-22965": "Spring4Shell",
    "CVE-2024-3094": "XZ Utils Backdoor",
    "CVE-2024-4577": "PHP CGI Argument Injection",
    "CVE-2024-21626": "runc Container Breakout",
}


def _is_overdue_helper(date_str: str | None, ref_date: datetime) -> bool:
    if not date_str:
        return False
    try:
        dt = datetime.strptime(date_str.split("T")[0], "%Y-%m-%d")
        return dt.date() < ref_date.date()
    except ValueError:
        return False


def _finding_sort_key(finding: MarkdownReportFinding) -> tuple[int, int, str]:
    return (
        int(finding.operational_rank or 999_999),
        int(finding.priority_rank or 999_999),
        finding.cve_id,
    )


def _is_actionable_finding(finding: MarkdownReportFinding) -> bool:
    status = str(finding.status or "").split(".", maxsplit=1)[-1].strip().lower()
    return (
        not finding.waived
        and not finding.suppressed_by_vex
        and status not in {"accepted", "fixed", "suppressed"}
    )


def _occurrence_count(finding: MarkdownReportFinding) -> int:
    return max(1, len(finding.occurrences))


def _count_findings(
    findings: list[MarkdownReportFinding],
    predicate: Callable[[MarkdownReportFinding], bool],
) -> int:
    return sum(1 for finding in findings if predicate(finding))


def _unique_values(
    findings: list[MarkdownReportFinding],
    value_for_finding: Callable[[MarkdownReportFinding], str | None],
) -> list[str]:
    values = {
        value.strip()
        for finding in findings
        if (value := value_for_finding(finding)) is not None and value.strip()
    }
    return sorted(values)


def _short_list(values: list[str], *, limit: int = 3, noun: str = "item") -> str:
    if not values:
        return "N/A"
    shown = values[:limit]
    if len(values) <= limit:
        return ", ".join(shown)
    hidden_count = len(values) - limit
    noun_text = noun if hidden_count == 1 else f"{noun}s"
    return ", ".join(shown) + f", and {hidden_count} additional {noun_text}"


def _actionable_findings(findings: list[MarkdownReportFinding]) -> list[MarkdownReportFinding]:
    return [finding for finding in findings if _is_actionable_finding(finding)]


def _finding_actionability_bucket(finding: MarkdownReportFinding) -> str:
    status = str(finding.status or "").split(".", maxsplit=1)[-1].strip().lower()
    if finding.suppressed_by_vex or status == "suppressed":
        return "suppressed"
    if finding.waived or status == "accepted":
        return "accepted"
    if status == "fixed":
        return "fixed"
    return "open"


def _actionability_counts_helper(
    findings: list[MarkdownReportFinding],
) -> Counter[str]:
    counts: Counter[str] = Counter()
    for finding in findings:
        counts[_finding_actionability_bucket(finding)] += 1
    return counts


def _actionability_summary_helper(findings: list[MarkdownReportFinding]) -> str:
    counts = _actionability_counts_helper(findings)
    parts = []
    for bucket in ("open", "accepted", "suppressed", "fixed"):
        count = counts.get(bucket, 0)
        if count:
            parts.append(f"{count} {bucket}")
    return ", ".join(parts) if parts else "No findings"


def _severity_open_count(findings: list[MarkdownReportFinding], severity: str) -> int:
    return _count_findings(
        findings,
        lambda finding: (
            _priority_label(finding.priority) == severity and _is_actionable_finding(finding)
        ),
    )


def _fixed_finding_count(findings: list[MarkdownReportFinding]) -> int:
    return _count_findings(
        findings,
        lambda finding: _finding_actionability_bucket(finding) == "fixed",
    )


def _technique_ids_for_findings(findings: list[MarkdownReportFinding]) -> list[str]:
    technique_ids: set[str] = set()
    for finding in findings:
        if not _boolish_signal(finding, "attack_mapped"):
            continue
        for value in _list_value(finding.explanation, "attack_techniques"):
            if isinstance(value, str) and value.strip():
                technique_ids.add(value.strip())
            elif isinstance(value, dict):
                candidate = value.get("technique_id") or value.get("attack_object_id")
                if isinstance(candidate, str) and candidate.strip():
                    technique_ids.add(candidate.strip())
        for key in ("attack_context", "attack"):
            value = finding.explanation.get(key)
            if not isinstance(value, dict):
                continue
            for nested in _list_value(value, "techniques"):
                if isinstance(nested, dict):
                    candidate = nested.get("technique_id") or nested.get("attack_object_id")
                    if isinstance(candidate, str) and candidate.strip():
                        technique_ids.add(candidate.strip())
                elif isinstance(nested, str) and nested.strip():
                    technique_ids.add(nested.strip())
    return sorted(technique_ids)


def _campaign_scope_summary(campaign: dict[str, Any]) -> str:
    asset_count = len(campaign["assets"])
    occurrence_count = campaign["total_occurrences"]
    return (
        f"{asset_count} asset{'s' if asset_count != 1 else ''}; "
        f"{occurrence_count} occurrence{'s' if occurrence_count != 1 else ''}"
    )


def _evidence_signal_summary(campaign: dict[str, Any]) -> str:
    signals = []
    if campaign["in_kev"]:
        signals.append("KEV")
    if campaign["max_epss"] is not None:
        signals.append(f"EPSS {_format_number(campaign['max_epss'])}")
    if campaign["max_cvss"] is not None:
        signals.append(f"CVSS {_format_number(campaign['max_cvss'])}")
    technique_ids = campaign.get("attack_techniques") or []
    if technique_ids:
        signals.append(f"ATT&CK {_short_list(technique_ids, limit=2, noun='technique')}")
    return ", ".join(signals) if signals else "Local finding evidence"


def _campaign_decision_statement(campaign: dict[str, Any]) -> str:
    actionability = _actionability_counts_helper(campaign["findings"])
    open_count = actionability.get("open", 0)
    accepted_count = actionability.get("accepted", 0)
    suppressed_count = actionability.get("suppressed", 0)
    fixed_count = actionability.get("fixed", 0)
    if open_count and campaign["in_kev"]:
        return "Approve emergency patch and validation window within 24h."
    if open_count:
        return "Approve remediation window and validate clean re-import after patching."
    if accepted_count:
        return "Review accepted-risk exception and keep evidence visible for audit."
    if suppressed_count:
        return "Retain VEX evidence and validate suppressed scope remains accurate."
    if fixed_count:
        return "Retain fixed evidence and verify closure in the evidence bundle."
    return "No immediate management action."


def _first_available_owner(campaigns: list[dict[str, Any]]) -> str:
    owners: list[str] = []
    for campaign in campaigns:
        owners.extend(str(owner) for owner in campaign["owners"] if owner)
    return _short_list(sorted(set(owners)), limit=3, noun="owner") if owners else "Unassigned"


def _executive_verdict_summary_helper(payload: MarkdownReportPayload) -> str:
    total_findings = len(payload.findings)
    open_actionable = _count_findings(payload.findings, _is_actionable_finding)
    kev_backed = _count_findings(payload.findings, lambda finding: finding.in_kev)
    accepted_risk = _count_findings(payload.findings, lambda finding: finding.waived)
    vex_suppressed = _count_findings(
        payload.findings,
        lambda finding: finding.suppressed_by_vex,
    )
    fixed_findings = _fixed_finding_count(payload.findings)

    waiver_debt = payload.governance_rollups.get("waiver_debt", {})
    waiver_items = waiver_debt.get("items", [])
    overdue_count = sum(
        1
        for item in waiver_items
        if isinstance(item, dict)
        and _is_overdue_helper(item.get("review_at"), payload.generated_at)
    )

    campaigns = [
        campaign
        for campaign in _get_remediation_campaigns_helper(payload.findings)
        if campaign["actionable_count"] > 0
    ]
    campaign_names = _short_list(
        [str(campaign["campaign_name"]) for campaign in campaigns],
        limit=2,
        noun="campaign",
    )
    filename = payload.filename or "source input"

    if total_findings == 0:
        return (
            f"This run analyzed 0 findings from {filename}. "
            "No findings were recorded for this analysis run. Confirm import coverage "
            "before treating this as a no-risk result."
        )

    verdict = (
        f"This run analyzed {total_findings} finding(s) from {filename}; "
        f"{open_actionable} are open and actionable, and {kev_backed} are KEV-backed. "
    )
    if campaigns:
        verdict += (
            f"First focus: {campaign_names} remediation cluster(s). "
            "Management decision needed: approve the remediation window, assign owners, "
            "and require clean validation evidence after re-import. "
        )
    else:
        verdict += (
            "There are no open actionable findings requiring immediate remediation; review "
            "accepted-risk, VEX, and fixed-state evidence before closure. "
        )

    gov_parts = []
    if accepted_risk > 0:
        gov_parts.append(f"{accepted_risk} finding(s) accepted risk")
    if vex_suppressed > 0:
        gov_parts.append(f"{vex_suppressed} VEX suppressed")
    if fixed_findings > 0:
        gov_parts.append(f"{fixed_findings} fixed finding(s) retained as evidence")
    if overdue_count > 0:
        gov_parts.append(f"{overdue_count} waiver review(s) overdue")

    verdict += (
        "Governance review: " + ", ".join(gov_parts) + ". "
        if gov_parts
        else "Governance review: no active accepted-risk, VEX, fixed, or overdue waiver items. "
    )

    if payload.provider_snapshot:
        provider_status = _provider_freshness_status_helper(
            payload.provider_snapshot, payload.generated_at
        )
        verdict += (
            f"Provider freshness status is {provider_status}; validate freshness before formal "
            "risk sign-off."
        )
    return verdict


def _html_business_impact_table_helper(findings: list[MarkdownReportFinding]) -> str:
    if not findings:
        return (
            '<p class="empty-state">No business service risk can be derived because no '
            "findings were recorded.</p>"
        )

    services: dict[str, list[MarkdownReportFinding]] = {}
    for finding in findings:
        service = finding.business_service or "Infrastructure / Shared Services"
        services.setdefault(service, []).append(finding)

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
        owner_str = _short_list(owners, limit=3, noun="owner") if owners else "Unassigned"
        exposures = _unique_values(service_findings, lambda finding: finding.exposure)
        exposure_str = _short_list(exposures, limit=3, noun="exposure") if exposures else "Unknown"
        environments = _unique_values(service_findings, lambda finding: finding.environment)
        environment_str = (
            _short_list(environments, limit=3, noun="environment") if environments else "Unknown"
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
        kev_count = _count_findings(service_findings, lambda finding: finding.in_kev)

        if open_count and kev_count:
            decision = "Emergency remediation"
            badge_class = "badge-critical"
        elif open_count:
            decision = "Remediation scheduling"
            badge_class = "badge-high"
        elif accepted_count:
            decision = "Governance review"
            badge_class = "badge-warning-alt"
        elif suppressed_count or fixed_count:
            decision = "Evidence validation"
            badge_class = "badge-low"
        else:
            decision = "Monitor"
            badge_class = "badge-low"

        rows.append(
            f"<tr>"
            f"<td><strong>{_safe_html(service)}</strong></td>"
            f"<td>{_safe_html(str(open_count))}</td>"
            f"<td>{_safe_html(str(accepted_count))}</td>"
            f"<td>{_safe_html(str(suppressed_count + fixed_count))}</td>"
            f"<td>{_safe_html(owner_str)}</td>"
            f"<td>{_safe_html(environment_str)} / {_safe_html(exposure_str)}</td>"
            f"<td><span class='badge {badge_class}'>{_safe_html(decision)}</span></td>"
            f"</tr>"
        )

    return (
        '<div class="table-wrap">\n'
        "  <table>\n"
        "    <thead>\n"
        "      <tr><th>Service</th><th>Open Actionable</th><th>Accepted Risk</th>"
        "<th>Suppressed / Fixed</th><th>Owners</th><th>Environment / Exposure</th>"
        "<th>Decision Needed</th></tr>\n"
        "    </thead>\n"
        "    <tbody>\n"
        f"      {chr(10).join(rows)}\n"
        "    </tbody>\n"
        "  </table>\n"
        "</div>"
    )


def _get_remediation_campaigns_helper(
    findings: list[MarkdownReportFinding],
) -> list[dict[str, Any]]:
    groups: dict[str, list[MarkdownReportFinding]] = {}
    for finding in sorted(findings, key=_finding_sort_key):
        groups.setdefault(finding.cve_id, []).append(finding)

    campaigns: list[dict[str, Any]] = []
    for cve_id, grouped_findings in groups.items():
        actionable = _actionable_findings(grouped_findings)
        assets = _unique_values(grouped_findings, lambda finding: finding.asset)
        services = _unique_values(grouped_findings, lambda finding: finding.business_service)
        owners = _unique_values(grouped_findings, lambda finding: finding.owner)
        actions = _unique_values(
            actionable or grouped_findings,
            lambda finding: finding.recommended_action or finding.decision_statement,
        )
        slas = _unique_values(actionable or grouped_findings, lambda finding: finding.decision_sla)

        cvss_values = [
            finding.cvss_base_score
            for finding in grouped_findings
            if finding.cvss_base_score is not None
        ]
        epss_values = [finding.epss for finding in grouped_findings if finding.epss is not None]
        max_cvss = max(cvss_values) if cvss_values else None
        max_epss = max(epss_values) if epss_values else None
        in_kev = any(finding.in_kev for finding in grouped_findings)

        waived_count = _count_findings(grouped_findings, lambda finding: finding.waived)
        vex_count = _count_findings(grouped_findings, lambda finding: finding.suppressed_by_vex)
        fixed_count = _fixed_finding_count(grouped_findings)
        alias = CVE_ALIASES.get(cve_id, "")
        campaign_name = f"{cve_id} / {alias}" if alias else cve_id

        campaigns.append(
            {
                "rank": 0,
                "sort_rank": min(_finding_sort_key(finding)[0] for finding in grouped_findings),
                "cve_id": cve_id,
                "alias": alias,
                "campaign_name": campaign_name,
                "findings": grouped_findings,
                "actionable_findings": actionable,
                "assets": assets,
                "services": services,
                "owners": owners,
                "actions": actions,
                "slas": slas,
                "max_cvss": max_cvss,
                "max_epss": max_epss,
                "in_kev": in_kev,
                "attack_techniques": _technique_ids_for_findings(grouped_findings),
                "total_occurrences": sum(
                    _occurrence_count(finding) for finding in grouped_findings
                ),
                "actionable_count": len(actionable),
                "actionable_occurrences": sum(_occurrence_count(finding) for finding in actionable),
                "waived_count": waived_count,
                "vex_count": vex_count,
                "fixed_count": fixed_count,
            }
        )
    campaigns.sort(
        key=lambda campaign: (
            0 if campaign["actionable_count"] > 0 else 1,
            campaign["sort_rank"],
            -float(campaign["max_epss"] or 0.0),
            str(campaign["cve_id"]),
        )
    )
    for rank, campaign in enumerate(campaigns, start=1):
        campaign["rank"] = rank
    return campaigns


def _html_remediation_campaigns_helper(findings: list[MarkdownReportFinding]) -> str:
    campaigns = _get_remediation_campaigns_helper(findings)
    if not campaigns:
        return '<p class="empty-state">No remediation campaigns are available for this run.</p>'

    rows = []
    for campaign in campaigns[:10]:
        owners = (
            _short_list(campaign["owners"], limit=3, noun="owner")
            if campaign["owners"]
            else "Unassigned"
        )
        services = (
            _short_list(campaign["services"], limit=3, noun="service")
            if campaign["services"]
            else "Unknown service"
        )
        actionability = _actionability_summary_helper(campaign["findings"])
        actionability_class = (
            "badge-critical"
            if campaign["actionable_count"] > 0 and campaign["in_kev"]
            else "badge-high"
            if campaign["actionable_count"] > 0
            else "badge-low"
        )
        rows.append(
            "        <tr>"
            f"<td><span class='badge badge-critical'>P{campaign['rank']}</span></td>"
            f"<td><strong>{_safe_html(campaign['campaign_name'])}</strong></td>"
            f"<td><span class='badge {actionability_class}'>"
            f"{_safe_html(actionability)}</span></td>"
            f"<td>{_safe_html(_campaign_scope_summary(campaign))}</td>"
            f"<td>{_safe_html(services)}</td>"
            f"<td>{_safe_html(owners)}</td>"
            f"<td>{_safe_html(_evidence_signal_summary(campaign))}</td>"
            f"<td>{_safe_html(_campaign_decision_statement(campaign))}</td>"
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


def _html_deduplicated_recommendations_helper(findings: list[MarkdownReportFinding]) -> str:
    campaigns = _get_remediation_campaigns_helper(findings)
    if not campaigns:
        return "<li>No remediation recommendations are available for this run.</li>"

    items = []
    for campaign in campaigns:
        cve_id = campaign["cve_id"]
        alias = campaign["alias"]
        campaign_title = (
            f"{cve_id} / {alias} remediation campaign"
            if alias
            else f"{cve_id} remediation campaign"
        )
        owners = (
            _short_list(campaign["owners"], limit=3, noun="owner")
            if campaign["owners"]
            else "Unassigned"
        )
        services = (
            _short_list(campaign["services"], limit=3, noun="service")
            if campaign["services"]
            else "Unknown service"
        )
        action_str = (
            campaign["actions"][0]
            if campaign["actions"]
            else _campaign_decision_statement(campaign)
        )
        if campaign["slas"]:
            sla_str = campaign["slas"][0]
        elif campaign["actionable_count"] > 0 and campaign["in_kev"]:
            sla_str = "24h"
        else:
            sla_str = "Standard patch cycle"

        gov_notes = []
        if campaign["vex_count"] > 0:
            gov_notes.append(f"{campaign['vex_count']} finding(s) VEX-suppressed")
        if campaign["waived_count"] > 0:
            gov_notes.append(f"{campaign['waived_count']} finding(s) accepted risk")
        if campaign["fixed_count"] > 0:
            gov_notes.append(f"{campaign['fixed_count']} fixed finding(s) retained as evidence")

        gov_note_str = (
            f"<br><small class='text-muted'>Governance note: {', '.join(gov_notes)}</small>"
            if gov_notes
            else ""
        )

        items.append(
            f"<li>\n"
            f"  <strong>{_safe_html(campaign_title)}</strong>\n"
            f"  <span>\n"
            f"    Scope: {_safe_html(_campaign_scope_summary(campaign))}; "
            f"services: {_safe_html(services)}<br>\n"
            f"    Status: {_safe_html(_actionability_summary_helper(campaign['findings']))}<br>\n"
            f"    Recommended action: {_safe_html(action_str)}<br>\n"
            f"    SLA: {_safe_html(sla_str)}<br>\n"
            f"    Owner: {_safe_html(owners)}<br>\n"
            f"    Evidence basis: {_safe_html(_evidence_signal_summary(campaign))}\n"
            f"    {gov_note_str}\n"
            f"  </span>\n"
            f"</li>\n"
        )

    return "\n".join(items)


def _campaigns_label(campaigns: list[dict[str, Any]], *, limit: int = 2) -> str:
    names = [str(campaign["campaign_name"]) for campaign in campaigns]
    return _short_list(names, limit=limit, noun="campaign")


def _campaign_evidence_label(campaigns: list[dict[str, Any]]) -> str:
    signals = []
    for campaign in campaigns[:2]:
        signals.append(_evidence_signal_summary(campaign))
    return "; ".join(signals) if signals else "Run evidence and provider snapshot"


def _html_action_plan_table_helper(payload: MarkdownReportPayload) -> str:
    campaigns = _get_remediation_campaigns_helper(payload.findings)
    open_campaigns = [campaign for campaign in campaigns if campaign["actionable_count"] > 0]
    emergency_campaigns = [
        campaign
        for campaign in open_campaigns
        if campaign["in_kev"]
        or (campaign["max_cvss"] is not None and campaign["max_cvss"] >= 9.0)
        or (campaign["max_epss"] is not None and campaign["max_epss"] >= 0.9)
    ]
    remaining_campaigns = [
        campaign for campaign in open_campaigns if campaign not in emergency_campaigns
    ]
    waiver_debt = payload.governance_rollups.get("waiver_debt", {})
    waiver_items = waiver_debt.get("items", [])
    overdue_count = sum(
        1
        for item in waiver_items
        if isinstance(item, dict)
        and _is_overdue_helper(item.get("review_at"), payload.generated_at)
    )
    review_due = int(waiver_debt.get("review_due_count") or 0)
    accepted_count = _count_findings(payload.findings, lambda finding: finding.waived)
    vex_count = _count_findings(payload.findings, lambda finding: finding.suppressed_by_vex)
    fixed_count = _fixed_finding_count(payload.findings)

    if emergency_campaigns:
        first_scope = _campaigns_label(emergency_campaigns)
        first_action = "Approve emergency remediation and validation window."
        first_owner = _first_available_owner(emergency_campaigns)
        first_evidence = _campaign_evidence_label(emergency_campaigns)
    else:
        first_scope = "No emergency campaign"
        first_action = "Confirm no 24h emergency campaign is required."
        first_owner = "Security owner"
        first_evidence = "Grouped campaign analysis"

    if remaining_campaigns:
        seventy_two_scope = _campaigns_label(remaining_campaigns, limit=3)
        seventy_two_action = "Schedule remediation for remaining open campaigns."
        seventy_two_owner = _first_available_owner(remaining_campaigns)
        seventy_two_evidence = _campaign_evidence_label(remaining_campaigns)
    else:
        seventy_two_scope = "No additional open campaign"
        seventy_two_action = "Track validation for completed or governed findings."
        seventy_two_owner = _first_available_owner(campaigns) if campaigns else "Security owner"
        seventy_two_evidence = "Actionability and governance status"

    if open_campaigns:
        seven_day_scope = _campaigns_label(open_campaigns, limit=3)
        seven_day_action = "Confirm clean re-import and preserve evidence bundle."
        seven_day_owner = _first_available_owner(open_campaigns)
    else:
        seven_day_scope = "Evidence closure"
        seven_day_action = "Verify accepted, suppressed, and fixed evidence before closure."
        seven_day_owner = _first_available_owner(campaigns) if campaigns else "Security owner"

    governance_scope_parts = []
    if overdue_count:
        governance_scope_parts.append(f"{overdue_count} overdue review")
    if review_due:
        governance_scope_parts.append(f"{review_due} due review")
    if accepted_count:
        governance_scope_parts.append(f"{accepted_count} accepted risk")
    if vex_count:
        governance_scope_parts.append(f"{vex_count} VEX suppressed")
    if fixed_count:
        governance_scope_parts.append(f"{fixed_count} fixed evidence")
    governance_scope = (
        ", ".join(governance_scope_parts) if governance_scope_parts else "No active exceptions"
    )
    governance_action = (
        "Review exceptions and record management decision."
        if governance_scope_parts
        else "No governance action required."
    )

    action_rows = [
        ("24h", first_action, first_scope, first_owner, first_evidence),
        ("72h", seventy_two_action, seventy_two_scope, seventy_two_owner, seventy_two_evidence),
        (
            "7d",
            seven_day_action,
            seven_day_scope,
            seven_day_owner,
            "Technical Markdown, analysis JSON, and provider snapshot",
        ),
        (
            "Governance review",
            governance_action,
            governance_scope,
            "Risk owner / security owner",
            "Waiver, VEX, and fixed-state evidence",
        ),
    ]
    rows = [
        "<tr>"
        f"<td><strong>{_safe_html(window)}</strong></td>"
        f"<td>{_safe_html(action)}</td>"
        f"<td>{_safe_html(scope)}</td>"
        f"<td>{_safe_html(owner)}</td>"
        f"<td>{_safe_html(evidence)}</td>"
        "</tr>"
        for window, action, scope, owner, evidence in action_rows
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


def _calculate_age_and_verdict_helper(
    date_str: str | None, generated_at: datetime | None
) -> tuple[str, str, str]:
    if not date_str or not generated_at:
        return "N/A", "Unknown", "badge-low"
    try:
        clean_date_str = date_str.split("T")[0]
        dt = datetime.strptime(clean_date_str, "%Y-%m-%d")
        report_dt = generated_at.astimezone(UTC) if generated_at.tzinfo else generated_at
        delta = (report_dt.date() - dt.date()).days
        if delta < 0:
            delta = 0
        age_str = f"{delta} day{'s' if delta != 1 else ''}"
        if delta <= 7:
            return age_str, "Fresh", "badge-fresh"
        elif delta <= 30:
            return age_str, "Warning", "badge-warning-alt"
        else:
            return age_str, "Stale / demo snapshot", "badge-stale"
    except ValueError:
        return "N/A", "Version semantics unclear", "badge-warning-alt"


def _provider_status_class(status: str) -> str:
    return {
        "Fresh": "badge-fresh",
        "Warning": "badge-warning-alt",
        "Stale": "badge-stale",
        "Reproducible": "badge-success",
        "Recorded": "badge-success",
        "Not available": "badge-low",
        "Unknown": "badge-low",
        "Version semantics unclear": "badge-warning-alt",
    }.get(status, "badge-low")


def _provider_freshness_rows_helper(
    snapshot: MarkdownProviderSnapshot | None,
    generated_at: datetime | None = None,
) -> list[dict[str, str]]:
    from app.services.report_formatting import metadata_bool as _metadata_bool

    if snapshot is None:
        return [
            {
                "signal": "Provider snapshot",
                "value": "Not available",
                "status": "Not available",
                "meaning": "No provider snapshot was linked to this analysis run.",
            }
        ]

    ref_date = generated_at or datetime.now(UTC)
    locked_provider_data = _metadata_bool(snapshot.source_metadata, "locked_provider_data")

    def dated_row(signal: str, value: str | None) -> dict[str, str]:
        age, verdict, _class_name = _calculate_age_and_verdict_helper(value, ref_date)
        if verdict == "Stale / demo snapshot":
            status = "Stale"
        else:
            status = verdict
        meaning = (
            f"Source data is {age} old at report generation time."
            if age != "N/A"
            else "Date could not be interpreted with the report freshness thresholds."
        )
        if status == "Stale":
            meaning += " Refresh provider data before formal risk sign-off."
        elif status == "Warning":
            meaning += " Review freshness before executive approval."
        elif status == "Fresh":
            meaning += " Suitable for current operational decision support."
        return {
            "signal": signal,
            "value": value or "N/A",
            "status": status,
            "meaning": meaning,
        }

    rows = [
        {
            "signal": "Snapshot locked",
            "value": locked_provider_data,
            "status": "Reproducible" if locked_provider_data == "Yes" else "Warning",
            "meaning": (
                "Provider data replay is deterministic for audit and demo."
                if locked_provider_data == "Yes"
                else "Provider replay lock was not recorded; verify reproducibility."
            ),
        },
        dated_row("NVD last sync", snapshot.nvd_last_sync),
        dated_row("EPSS date", snapshot.epss_date),
        dated_row("KEV catalog version", snapshot.kev_catalog_version),
        {
            "signal": "Content hash",
            "value": snapshot.content_hash or "Missing",
            "status": "Recorded" if snapshot.content_hash else "Warning",
            "meaning": (
                "Evidence can be verified against the bundle manifest."
                if snapshot.content_hash
                else "Snapshot hash is missing; bundle verification is weaker."
            ),
        },
    ]
    return rows


def _provider_freshness_status_helper(
    snapshot: MarkdownProviderSnapshot | None,
    generated_at: datetime | None = None,
) -> str:
    rows = _provider_freshness_rows_helper(snapshot, generated_at)
    statuses = {row["status"] for row in rows}
    if statuses == {"Not available"}:
        return "Not available"
    if "Stale" in statuses:
        return "Stale"
    if {"Warning", "Unknown", "Version semantics unclear", "Not available"} & statuses:
        return "Warning"
    return "Fresh"


def _html_provider_snapshot_helper(
    snapshot: MarkdownProviderSnapshot | None, generated_at: datetime | None = None
) -> str:
    from app.services.report_formatting import metadata_bool as _metadata_bool
    from app.services.report_formatting import metadata_list as _metadata_list

    if snapshot is None:
        return "<p>No provider snapshot was linked to this analysis run.</p>"

    freshness_rows = _provider_freshness_rows_helper(snapshot, generated_at)
    overall_status = _provider_freshness_status_helper(snapshot, generated_at)
    rows = []
    for row in freshness_rows:
        value = row["value"]
        value_html = (
            f"<code>{_safe_html(value)}</code>"
            if row["signal"] == "Content hash"
            else _safe_html(value)
        )
        status_class = _provider_status_class(row["status"])
        rows.append(
            f"<tr>"
            f"<td><strong>{_safe_html(row['signal'])}</strong></td>"
            f"<td>{value_html}</td>"
            f"<td><span class='badge {status_class}'>{_safe_html(row['status'])}</span></td>"
            f"<td>{_safe_html(row['meaning'])}</td>"
            f"</tr>"
        )

    alert_text = (
        "Provider data is deterministic evidence for this run. "
        "Refresh stale or warning sources before treating the report as current "
        "external vulnerability intelligence for formal sign-off."
        if overall_status in {"Stale", "Warning"}
        else "Provider data is fresh enough for current operational decision support."
    )

    table_html = (
        "<div class='verdict-banner'><p><strong>Evidence Confidence:</strong> "
        f"{alert_text}</p></div>\n"
        f"<div class='table-wrap'>\n"
        f"  <table>\n"
        f"    <thead>\n"
        f"      <tr><th>Signal</th><th>Value</th><th>Status</th><th>Meaning</th></tr>\n"
        f"    </thead>\n"
        f"    <tbody>\n"
        f"      {chr(10).join(rows)}\n"
        f"    </tbody>\n"
        f"  </table>\n"
        f"</div>"
    )

    selected_sources = _metadata_list(snapshot.source_metadata, "selected_sources")
    locked_provider_data = _metadata_bool(snapshot.source_metadata, "locked_provider_data")
    cells = [
        ("Snapshot ID", snapshot.id),
        ("Content Hash", snapshot.content_hash),
        ("Locked Provider Data", locked_provider_data),
        ("Selected Sources", selected_sources),
    ]
    for key, value in sorted(snapshot.source_hashes.items()):
        cells.append((f"Source Hash: {key}", value))
    for key in ("source_path", "item_count", "missing", "validation_error"):
        if key in snapshot.source_metadata:
            cells.append((f"Metadata: {key}", snapshot.source_metadata[key]))

    items = "\n".join(
        f"        <div><dt>{_safe_html(label)}</dt><dd>{_safe_html(value)}</dd></div>"
        for label, value in cells
    )
    return (
        f"{table_html}\n"
        f"      <h3>Raw Provider Metadata</h3>\n"
        f'      <dl class="provider-grid">\n{items}\n      </dl>'
    )


def _html_evidence_package_table_helper(
    *,
    has_attack_layer: bool,
    has_governance: bool,
) -> str:
    evidence_package_rows = [
        ("manifest.json", "Manifest and artifact hash verification", "Yes"),
        ("executive.html", "Executive HTML decision brief", "Yes"),
        ("technical.md", "Technical Markdown finding explanation", "Yes"),
        ("analysis.json", "Machine-readable run result", "Yes"),
        ("findings.csv", "Findings CSV (spreadsheet review)", "Yes"),
        ("results.sarif", "SARIF toolchain integration", "Yes"),
        ("provider-snapshot.json", "Provider snapshot replay / reproducibility", "Yes"),
        (
            "attack-navigator-layer.json",
            "ATT&CK Navigator defensive TTP context",
            "Yes" if has_attack_layer else "Optional",
        ),
        (
            "governance/*.json",
            "Accepted risk, VEX, rollup, and asset-context evidence",
            "Yes" if has_governance else "Optional",
        ),
    ]
    evidence_package_rows_html = []
    for artifact, purpose, included in evidence_package_rows:
        included_badge = (
            f"<span class='badge badge-fresh'>{included}</span>"
            if included == "Yes"
            else f"<span class='badge badge-low'>{included}</span>"
        )
        evidence_package_rows_html.append(
            f"<tr><td><code>{_safe_html(artifact)}</code></td>"
            f"<td>{_safe_html(purpose)}</td><td>{included_badge}</td></tr>"
        )

    return (
        "      <h3>Evidence Package Contents</h3>\n"
        "      <div class='table-wrap'>\n"
        "        <table>\n"
        "          <thead>\n"
        "            <tr><th>Artifact File</th><th>Purpose / Description</th><th>Status</th></tr>\n"
        "          </thead>\n"
        "          <tbody>\n"
        f"            {chr(10).join(evidence_package_rows_html)}\n"
        "          </tbody>\n"
        "        </table>\n"
        "      </div>"
    )


def _html_attack_context_table_helper(findings: list[MarkdownReportFinding]) -> str:
    mapped_count = sum(1 for finding in findings if _boolish_signal(finding, "attack_mapped"))
    unmapped_count = len(findings) - mapped_count
    navigator_layer_status = (
        "Included in Evidence ZIP" if mapped_count > 0 else "Optional / not generated"
    )
    attack_rows = [
        ("Mapped findings", str(mapped_count)),
        ("Unmapped findings", str(unmapped_count)),
        ("Mapping source", "CTID JSON / curated local mapping"),
        ("Navigator layer", navigator_layer_status),
    ]
    attack_rows_html = []
    for context, status in attack_rows:
        attack_rows_html.append(
            f"<tr><td><strong>{_safe_html(context)}</strong></td><td>{_safe_html(status)}</td></tr>"
        )

    return (
        "      <div class='table-wrap'>\n"
        "        <table class='compact-table'>\n"
        "          <thead>\n"
        "            <tr><th>ATT&CK/TTP Context</th><th>Status</th></tr>\n"
        "          </thead>\n"
        "          <tbody>\n"
        f"            {chr(10).join(attack_rows_html)}\n"
        "          </tbody>\n"
        "        </table>\n"
        "      </div>"
    )


def render_html_executive_report_helper(payload: MarkdownReportPayload) -> str:
    from app.services.report_formatting import iso_datetime as _iso_datetime
    from app.services.report_formatting import safe_html as _safe_html
    from app.services.report_html_components import _html_metric
    from app.services.report_html_findings import (
        _html_deduplicated_recommendations,
        _html_remediation_campaigns,
    )
    from app.services.report_html_governance import _html_governance_rollups
    from app.services.report_html_narrative import (
        _executive_verdict_summary,
        _html_business_impact_table,
    )
    from app.services.report_html_styles import EXECUTIVE_REPORT_CSS as _EXECUTIVE_REPORT_CSS
    from app.services.report_renderer_common import _redacted_bundle_payload

    payload, _redactions = _redacted_bundle_payload(payload)
    finding_count = len(payload.findings)
    occurrence_count = sum(_occurrence_count(finding) for finding in payload.findings)

    generated_at_dt = payload.generated_at
    generated_at = _safe_html(_iso_datetime(generated_at_dt))
    snapshot = payload.provider_snapshot

    waiver_debt = payload.governance_rollups.get("waiver_debt", {})
    waiver_items = waiver_debt.get("items", [])
    overdue_count = sum(
        1
        for item in waiver_items
        if isinstance(item, dict) and _is_overdue_helper(item.get("review_at"), generated_at_dt)
    )
    review_due_or_expiring = int(waiver_debt.get("review_due_count") or 0) + int(
        waiver_debt.get("expiring_soon_count") or 0
    )
    review_due_or_expiring = max(review_due_or_expiring, overdue_count)

    unique_cves = len({finding.cve_id for finding in payload.findings})
    open_actionable = _count_findings(payload.findings, _is_actionable_finding)
    critical_open = _severity_open_count(payload.findings, "Critical")
    kev_listed = _count_findings(payload.findings, lambda finding: finding.in_kev)
    internet_facing = _count_findings(
        payload.findings,
        lambda finding: (
            _is_actionable_finding(finding)
            and (finding.exposure or "").lower() in {"internet-facing", "external"}
            and (finding.environment or "").lower() in {"prod", "production"}
        ),
    )
    accepted_risk = _count_findings(payload.findings, lambda finding: finding.waived)
    vex_suppressed = _count_findings(
        payload.findings,
        lambda finding: finding.suppressed_by_vex,
    )
    fixed_findings = _fixed_finding_count(payload.findings)
    emergency_sla = _count_findings(
        payload.findings,
        lambda finding: (
            _is_actionable_finding(finding) and "emergency" in (finding.decision_sla or "").lower()
        ),
    )
    provider_freshness_status = _provider_freshness_status_helper(snapshot, generated_at_dt)

    input_file_hash_val = getattr(payload, "input_file_hash", None) or "N/A"
    verdict_text = _executive_verdict_summary(payload)
    action_plan_table = _html_action_plan_table_helper(payload)
    campaigns_section = _html_remediation_campaigns(payload.findings)
    business_impact_table = _html_business_impact_table(payload.findings)
    governance_section = (
        _html_governance_rollups(
            payload.governance_rollups,
            payload.findings,
            generated_at_dt,
        )
        + "\n\n"
    )
    has_attack_layer = any(
        _boolish_signal(finding, "attack_mapped") for finding in payload.findings
    )
    evidence_package_table = _html_evidence_package_table_helper(
        has_attack_layer=has_attack_layer,
        has_governance=bool(payload.governance_rollups),
    )
    attack_context_table = _html_attack_context_table_helper(payload.findings)
    recommendations_list = _html_deduplicated_recommendations(payload.findings)

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
        "      <h1>Executive Vulnerability Report</h1>\n"
        f'      <p class="lede">Decision-oriented evidence brief for '
        f"{_safe_html(payload.project_name)}.</p>\n"
        '      <dl class="meta-grid">\n'
        f"        <div><dt>Project Name</dt><dd>{_safe_html(payload.project_name)}</dd></div>\n"
        f"        <div><dt>Project ID</dt><dd>{_safe_html(payload.project_id)}</dd></div>\n"
        f"        <div><dt>Analysis Run ID</dt><dd>{_safe_html(payload.run_id)}</dd></div>\n"
        f"        <div><dt>Generated At</dt><dd>{generated_at}</dd></div>\n"
        f"        <div><dt>Run Status</dt><dd>{_safe_html(payload.run_status)}</dd></div>\n"
        f"        <div><dt>Input Type</dt><dd>{_safe_html(payload.input_type)}</dd></div>\n"
        f"        <div><dt>Input File</dt><dd>{_safe_html(payload.filename)}</dd></div>\n"
        f"        <div><dt>Input File Hash</dt><dd>{_safe_html(input_file_hash_val)}</dd></div>\n"
        "        <div><dt>Provider Snapshot ID</dt><dd>"
        f"{_safe_html(snapshot.id if snapshot else 'N/A')}</dd></div>\n"
        f"        <div><dt>Generator Version</dt><dd>v1.0.0</dd></div>\n"
        "      </dl>\n"
        "    </header>\n"
        "\n"
        '    <section aria-labelledby="decision-brief">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Executive Summary</p>\n'
        '        <h2 id="decision-brief">Decision Brief</h2>\n'
        "      </div>\n"
        f'      <div class="verdict-banner"><p>{_safe_html(verdict_text)}</p></div>\n'
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="risk-posture">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Risk Posture</p>\n'
        '        <h2 id="risk-posture">Risk Posture Cards</h2>\n'
        "      </div>\n"
        '      <div class="metric-grid">\n'
        f"        {_html_metric('Total Findings', finding_count)}\n"
        f"        {_html_metric('Open Actionable', open_actionable)}\n"
        f"        {_html_metric('Critical Open', critical_open)}\n"
        f"        {_html_metric('KEV Backed', kev_listed)}\n"
        f"        {_html_metric('Internet-facing Prod', internet_facing)}\n"
        f"        {_html_metric('Accepted Risk', accepted_risk)}\n"
        f"        {_html_metric('VEX Suppressed', vex_suppressed)}\n"
        f"        {_html_metric('Fixed Evidence', fixed_findings)}\n"
        f"        {_html_metric('Review Due / Expiring', review_due_or_expiring)}\n"
        f"        {_html_metric('Emergency SLA', emergency_sla)}\n"
        f"        {_html_metric('Unique CVEs', unique_cves)}\n"
        f"        {_html_metric('Occurrences', occurrence_count)}\n"
        f"        {_html_metric('Provider Freshness', provider_freshness_status)}\n"
        "      </div>\n"
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="action-plan">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Action Plan</p>\n'
        '        <h2 id="action-plan">First 24h and 7d Action Plan</h2>\n'
        "      </div>\n"
        f"      {action_plan_table}\n"
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="remediation-campaigns">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Remediation</p>\n'
        '        <h2 id="remediation-campaigns">Top Remediation Campaigns</h2>\n'
        "      </div>\n"
        f"      {campaigns_section}\n"
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="business-services-risk">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Business Impact</p>\n'
        '        <h2 id="business-services-risk">Business Services at Risk</h2>\n'
        "      </div>\n"
        f"      {business_impact_table}\n"
        "    </section>\n"
        "\n"
        f"{governance_section}"
        "\n"
        '    <section aria-labelledby="provider-freshness">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Evidence</p>\n'
        '        <h2 id="provider-freshness">Evidence Confidence and Provider Freshness</h2>\n'
        "      </div>\n"
        f"{_html_provider_snapshot_helper(snapshot, generated_at_dt)}\n"
        f"      {evidence_package_table}\n"
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="recommendations">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Recommendations</p>\n'
        '        <h2 id="recommendations">Recommendations</h2>\n'
        "      </div>\n"
        f'      <ol class="recommendation-list">\n{recommendations_list}\n      </ol>\n'
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="attack-context">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">SOC Context</p>\n'
        '        <h2 id="attack-context">ATT&CK/TTP Context</h2>\n'
        "      </div>\n"
        f"      {attack_context_table}\n"
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="technical-appendix">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Appendix</p>\n'
        '        <h2 id="technical-appendix">Technical Markdown Separation</h2>\n'
        "      </div>\n"
        '      <p class="empty-state">Detailed finding rows, component versions, long '
        "rationale, and per-finding actions remain in the Technical Markdown report, "
        "Analysis JSON, Findings CSV, SARIF, and Evidence ZIP.</p>\n"
        "    </section>\n"
        "  </main>\n"
        "</body>\n"
        "</html>\n"
    )
