"""HTML report rendering helper functions and data grouping logic."""

from __future__ import annotations

import html
import re
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
    "CVE-2023-34362": "MOVEit Transfer",
    "CVE-2023-44487": "HTTP/2 Rapid Reset",
    "CVE-2020-1472": "Identity Domain Controller Risk",
    "CVE-2024-3094": "XZ Utils Backdoor",
    "CVE-2024-4577": "PHP CGI",
    "CVE-2024-21626": "runc Container Breakout",
}


def _html_evidence_signals_badges(campaign: dict[str, Any]) -> str:
    badges = []
    if campaign["in_kev"]:
        badges.append("<span class='badge badge-critical'>KEV</span>")
    if campaign["max_epss"] is not None:
        epss_val = campaign["max_epss"]
        tone = (
            "badge-critical"
            if epss_val >= 0.1
            else "badge-high"
            if epss_val >= 0.01
            else "badge-neutral"
        )
        badges.append(f"<span class='badge {tone}'>EPSS {_format_number(epss_val)}</span>")
    if campaign["max_cvss"] is not None:
        cvss_val = campaign["max_cvss"]
        if cvss_val >= 9.0:
            tone = "badge-critical"
        elif cvss_val >= 7.0:
            tone = "badge-high"
        else:
            tone = "badge-neutral"
        badges.append(f"<span class='badge {tone}'>CVSS {_format_number(cvss_val)}</span>")
    technique_ids = campaign.get("attack_techniques") or []
    for tech_id in technique_ids[:2]:
        badges.append(f"<span class='badge badge-info'>ATT&CK {tech_id}</span>")
    if not campaign["in_kev"]:
        badges.append("<span class='badge badge-neutral'>No KEV</span>")
    return f'<div class="signal-row">{"".join(badges)}</div>'


def render_safe_text_with_links(text: str | None) -> str:
    """Escape HTML characters and format safe markdown-style links."""
    if not text:
        return "N/A"

    def escape_preserve_spaces(val: str) -> str:
        return html.escape(re.sub(r"\s+", " ", val), quote=True)

    pattern = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
    last_idx = 0
    parts = []

    for match in pattern.finditer(text):
        before = text[last_idx : match.start()]
        parts.append(escape_preserve_spaces(before))

        label = match.group(1)
        url = match.group(2)

        clean_url = url.strip().lower()
        if (clean_url.startswith("http://") or clean_url.startswith("https://")) and not any(
            c in clean_url for c in "\r\n\t\"'"
        ):
            safe_url = html.escape(url.strip(), quote=True)
            safe_label = escape_preserve_spaces(label)
            parts.append(
                f'<a href="{safe_url}" target="_blank" rel="noopener noreferrer">{safe_label}</a>'
            )
        else:
            parts.append(escape_preserve_spaces(match.group(0)))

        last_idx = match.end()

    parts.append(escape_preserve_spaces(text[last_idx:]))
    return "".join(parts)


def _campaign_ranking_rationale(campaign: dict[str, Any]) -> str:
    """Generate a stakeholder-friendly ranking rationale based on context."""
    findings = campaign["findings"]
    has_internet = any(
        _is_actionable_finding(f)
        and (f.exposure or "").lower() in {"internet-facing", "external"}
        and (f.environment or "").lower() in {"prod", "production"}
        for f in findings
    )
    has_prod = any(
        _is_actionable_finding(f) and (f.environment or "").lower() in {"prod", "production"}
        for f in findings
    )
    has_critical_asset = any(
        _is_actionable_finding(f) and (f.criticality or "").lower() == "critical" for f in findings
    )
    has_kev = campaign["in_kev"]
    max_epss = campaign["max_epss"]
    max_cvss = campaign["max_cvss"]

    reasons = []
    if has_internet:
        reasons.append("internet-facing production exposure")
    elif has_prod:
        reasons.append("internal production exposure")

    if has_critical_asset:
        reasons.append("critical asset class")

    if has_kev:
        reasons.append("active CISA KEV exploit threat")

    if max_epss is not None and max_epss >= 0.9:
        reasons.append(f"critical EPSS ({_format_number(max_epss)})")
    elif max_epss is not None and max_epss >= 0.1:
        reasons.append(f"high EPSS ({_format_number(max_epss)})")

    if max_cvss is not None and max_cvss >= 9.0:
        reasons.append(f"critical CVSS ({_format_number(max_cvss)})")

    if reasons:
        text = ", ".join(reasons)
        return text[0].upper() + text[1:] + "."
    return "Standard operational queue priority."


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


def _pluralize(count: int, singular: str, plural: str | None = None) -> str:
    label = singular if count == 1 else plural or f"{singular}s"
    return f"{count} {label}"


def _normalized_context_label(value: str) -> str:
    normalized = value.strip().lower().replace("_", "-")
    replacements = {
        "prod": "production",
        "internet-facing": "internet facing",
        "external": "external",
        "dmz": "DMZ",
        "dr": "DR",
    }
    return replacements.get(normalized, normalized.replace("-", " "))


def _joined_context(values: list[str], *, limit: int = 3, noun: str = "value") -> str:
    normalized = [_normalized_context_label(value) for value in values if value]
    return _short_list(sorted(set(normalized)), limit=limit, noun=noun) if normalized else "Unknown"


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
    findings = campaign["findings"]
    environments = _unique_values(findings, lambda finding: finding.environment)
    exposures = _unique_values(findings, lambda finding: finding.exposure)
    parts = [_pluralize(asset_count, "asset")]
    if environments:
        parts.append(_joined_context(environments, limit=3, noun="environment"))
    if exposures:
        exposure_text = _joined_context(exposures, limit=3, noun="exposure")
        parts.append(f"{exposure_text} exposure")
    return "; ".join(parts)


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


def _campaign_requires_emergency(campaign: dict[str, Any]) -> bool:
    return bool(
        campaign["actionable_count"] > 0
        and (
            campaign["in_kev"]
            or (campaign["max_cvss"] is not None and campaign["max_cvss"] >= 9.0)
            or (campaign["max_epss"] is not None and campaign["max_epss"] >= 0.9)
        )
    )


def _campaign_decision_statement(campaign: dict[str, Any]) -> str:
    actionability = _actionability_counts_helper(campaign["findings"])
    open_count = actionability.get("open", 0)
    accepted_count = actionability.get("accepted", 0)
    suppressed_count = actionability.get("suppressed", 0)
    fixed_count = actionability.get("fixed", 0)

    statements = []
    if open_count:
        if campaign["in_kev"]:
            statements.append("Approve emergency patch and validation window within 24h.")
        elif campaign["max_cvss"] is not None and campaign["max_cvss"] >= 9.0:
            statements.append("Approve prioritized remediation and validation window.")
        else:
            statements.append("Approve remediation window and validate clean re-import.")
    if accepted_count:
        statements.append("Review accepted-risk exception before sign-off.")
    if suppressed_count:
        statements.append("Retain VEX evidence for suppressed scope.")
    if fixed_count:
        statements.append("Keep fixed evidence visible for audit closure.")
    return " ".join(statements) if statements else "No immediate management action."


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
    open_campaigns = [campaign for campaign in campaigns if campaign["actionable_count"] > 0]
    top_campaigns = _campaigns_label(open_campaigns or campaigns, limit=5)
    focus_sentence = (
        f"Immediate focus should be {top_campaigns} before governance exceptions are signed off."
        if campaigns
        else "Confirm import coverage before treating this run as a no-risk result."
    )
    return (
        f"This run analyzed {total_findings} {finding_word} from {filename}. "
        f"{open_phrase}, {kev_phrase}, {accepted_phrase}, {vex_phrase} and {fixed_phrase}. "
        f"{focus_sentence}"
    )


def _html_business_services_prose_helper(findings: list[MarkdownReportFinding]) -> str:
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
    findings: list[MarkdownReportFinding], project_name: str | None = None
) -> str:
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
        exposure_str = _joined_context(exposures, limit=3, noun="exposure")
        environments = _unique_values(service_findings, lambda finding: finding.environment)
        environment_str = _joined_context(environments, limit=3, noun="environment")

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

        governed_risk_parts = []
        if accepted_count:
            governed_risk_parts.append(_pluralize(accepted_count, "accepted risk"))
        if suppressed_count:
            governed_risk_parts.append(_pluralize(suppressed_count, "VEX suppressed"))
        if fixed_count:
            governed_risk_parts.append(_pluralize(fixed_count, "fixed evidence"))
        governed_risk_str = ", ".join(governed_risk_parts) or "0 accepted, 0 VEX suppressed"

        if open_count and kev_count:
            decision = "Emergency remediation"
            badge_class = "badge-critical"
        elif open_count:
            decision = "Remediation scheduling"
            badge_class = "badge-high"
        elif accepted_count:
            decision = "Governance review"
            badge_class = "badge-warning"
        elif suppressed_count or fixed_count:
            decision = "Evidence validation"
            badge_class = "badge-success"
        else:
            decision = "Monitor"
            badge_class = "badge-neutral"

        rows.append(
            f"            <tr>"
            f"<td><strong>{_safe_html(service)}</strong></td>"
            f"<td>{_safe_html(str(open_count))}</td>"
            f"<td>{_safe_html(governed_risk_str)}</td>"
            f"<td>{_safe_html(environment_str)} / {_safe_html(exposure_str)}</td>"
            f"<td>{_safe_html(owner_str)}</td>"
            f"<td><span class='badge {badge_class}'>{_safe_html(decision)}</span></td>"
            f"</tr>"
        )

    return (
        prose + "\n"
        '      <div class="table-wrap">\n'
        "        <table>\n"
        "          <thead>\n"
        "            <tr><th>Service</th><th>Open Actionable</th><th>Governed Risk</th>"
        "<th>Environment / Exposure</th><th>Owner</th><th>Decision Needed</th></tr>\n"
        "          </thead>\n"
        "          <tbody>\n"
        f"{chr(10).join(rows)}\n"
        "          </tbody>\n"
        "        </table>\n"
        "      </div>"
    )


def _get_remediation_campaigns_helper(
    findings: list[MarkdownReportFinding], project_name: str | None = None
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
                "project_name": project_name,
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


def _html_remediation_campaigns_helper(
    findings: list[MarkdownReportFinding], project_name: str | None = None
) -> str:
    campaigns = _get_remediation_campaigns_helper(findings, project_name=project_name)
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

        priority_class = (
            "badge-critical" if _campaign_requires_emergency(campaign) else "badge-high"
        )
        actionability_class = (
            "badge-critical"
            if _campaign_requires_emergency(campaign)
            else "badge-high"
            if campaign["actionable_count"] > 0
            else "badge-neutral"
        )

        decision_stmt = _campaign_decision_statement(campaign)
        decision_html = f"{_safe_html(decision_stmt)}"

        rows.append(
            "        <tr>"
            f"<td><span class='badge {priority_class}'>P{campaign['rank']}</span></td>"
            f"<td><strong>{_safe_html(campaign['campaign_name'])}</strong></td>"
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


def _html_deduplicated_recommendations_helper(
    findings: list[MarkdownReportFinding], project_name: str | None = None
) -> str:
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
        cve_id = campaign["cve_id"]
        alias = campaign["alias"]

        campaign_title = titles_map.get(
            cve_id,
            (
                f"{cve_id} / {alias} remediation campaign"
                if alias
                else f"{cve_id} remediation campaign"
            ),
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
            else (_campaign_decision_statement(campaign))
        )
        if campaign["slas"]:
            sla_str = campaign["slas"][0]
        elif _campaign_requires_emergency(campaign):
            sla_str = "Emergency / 24h"
        else:
            sla_str = "Standard patch cycle"
        prose = (
            f"Scope: {_campaign_scope_summary(campaign)}; services: {services}. "
            f"Status: {_actionability_summary_helper(campaign['findings'])}. "
            f"Recommended action: {action_str}. SLA: {sla_str}. Owners: {owners}. "
            f"Evidence basis: {_evidence_signal_summary(campaign)}."
        )

        items.append(
            f"<li><strong>{_safe_html(campaign_title)}</strong>"
            f"<span>{render_safe_text_with_links(prose)}</span></li>"
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
        campaign for campaign in open_campaigns if _campaign_requires_emergency(campaign)
    ]
    waiver_debt = payload.governance_rollups.get("waiver_debt", {})
    waiver_items = waiver_debt.get("items", [])
    review_due = int(waiver_debt.get("review_due_count") or 0)
    expiring_soon = int(waiver_debt.get("expiring_soon_count") or 0)
    accepted_count = _count_findings(payload.findings, lambda finding: finding.waived)

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
            lambda finding: finding.suppressed_by_vex,
        )
        if vex_count:
            governed_context.append(_pluralize(vex_count, "VEX suppressed finding"))
        if governed_context:
            governance_scope = f"{governance_scope}; {', '.join(governed_context)}."
    else:
        vex_count = _count_findings(
            payload.findings,
            lambda finding: finding.suppressed_by_vex,
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

    action_rows = [
        ("24h", first_action, first_scope, first_owner, first_evidence),
        ("72h", seventy_two_action, seventy_two_scope, seventy_two_owner, seventy_two_evidence),
        ("7d", seven_day_action, seven_day_scope, seven_day_owner, seven_day_evidence),
        (
            "Governance review",
            governance_action,
            governance_scope,
            governance_owner,
            governance_evidence,
        ),
    ]
    rows = [
        "<tr>"
        f"<td><strong>{_safe_html(window)}</strong></td>"
        f"<td>{render_safe_text_with_links(action)}</td>"
        f"<td>{_safe_html(scope)}</td>"
        f"<td>{_safe_html(owner)}</td>"
        f"<td>{render_safe_text_with_links(evidence)}</td>"
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
    # Deterministic freshness thresholds:
    # 1. Fresh: age is <= 7 days
    # 2. Warning: age is > 7 days and <= 30 days
    # 3. Stale: age is > 30 days
    # 4. Unknown: date is missing or invalid
    if not date_str or not generated_at:
        return "N/A", "Unknown", "badge-neutral"
    try:
        clean_date_str = date_str.split("T")[0]
        dt = datetime.strptime(clean_date_str, "%Y-%m-%d")
        report_dt = generated_at.astimezone(UTC) if generated_at.tzinfo else generated_at
        delta = (report_dt.date() - dt.date()).days
        if delta < 0:
            delta = 0
        age_str = f"{delta} day{'s' if delta != 1 else ''}"
        if delta <= 7:
            return age_str, "Fresh", "badge-success"
        if delta <= 30:
            return age_str, "Warning", "badge-warning"
        return age_str, "Stale", "badge-stale"
    except ValueError:
        return "N/A", "Unknown", "badge-neutral"


def _provider_status_class(status: str) -> str:
    return {
        "Fresh": "badge-success",
        "Warning": "badge-warning",
        "Stale": "badge-stale",
        "Reproducible": "badge-success",
        "Recorded": "badge-success",
        "Controlled": "badge-success",
        "Not available": "badge-neutral",
        "Unknown": "badge-neutral",
    }.get(status, "badge-neutral")


def _provider_freshness_rows_helper(
    snapshot: MarkdownProviderSnapshot | None,
    generated_at: datetime | None = None,
) -> list[dict[str, str]]:
    from app.services.report_formatting import metadata_bool as _metadata_bool
    from app.services.report_formatting import metadata_list as _metadata_list

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
        status = verdict
        meaning = (
            f"Source data is {age} old at report generation time."
            if age != "N/A"
            else "Date is missing or invalid, freshness cannot be determined."
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
                "Provider data replay is deterministic for audit and demo. "
                "Note: locked provider data guarantees reproducibility "
                "but does not automatically mean the data is fresh."
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
        {
            "signal": "Selected sources",
            "value": _metadata_list(snapshot.source_metadata, "selected_sources"),
            "status": "Recorded"
            if (snapshot.source_metadata and snapshot.source_metadata.get("selected_sources"))
            else "Warning",
            "meaning": "Vulnerability intelligence sources selected for data enrichment.",
        },
        {
            "signal": "Evidence bundle manifest",
            "value": "manifest.json",
            "status": "Fresh",
            "meaning": "Evidence package manifest is available for validation.",
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
    if {"Warning", "Unknown", "Not available"} & statuses:
        return "Warning"
    return "Fresh"


def _html_provider_snapshot_helper(
    snapshot: MarkdownProviderSnapshot | None,
    generated_at: datetime | None = None,
    project_name: str | None = None,
) -> str:
    from app.services.report_formatting import metadata_bool as _metadata_bool
    from app.services.report_formatting import metadata_list as _metadata_list

    _ = project_name

    if snapshot is None:
        return "<p>No provider snapshot was linked to this analysis run.</p>"

    freshness_rows = _provider_freshness_rows_helper(snapshot, generated_at)
    freshness_rows.append(
        {
            "signal": "Static HTML safety",
            "value": "No scripts, no external assets, escaped recommendation text",
            "status": "Controlled",
            "meaning": "Report is suitable for local review and evidence package distribution.",
        }
    )
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
            f"            <tr>"
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
        "      <div class='verdict-banner'><p><strong>Evidence confidence:</strong> "
        f"{alert_text}</p></div>\n"
        f"      <div class='table-wrap'>\n"
        f"        <table>\n"
        f"          <thead>\n"
        f"            <tr><th>Signal</th><th>Value</th><th>Status</th><th>Meaning</th></tr>\n"
        f"          </thead>\n"
        f"          <tbody>\n"
        f"      {chr(10).join(rows)}\n"
        f"          </tbody>\n"
        f"        </table>\n"
        f"      </div>"
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
        ("manifest.json", "Bundle manifest and artifact hash verification.", "included"),
        ("executive.html", "Decision oriented executive brief.", "included"),
        ("technical.md", "Detailed analyst handoff with finding rows and rationale.", "included"),
        ("analysis.json", "Machine readable analysis export.", "included"),
        ("findings.csv", "Spreadsheet review of findings and owner scope.", "included"),
        ("results.sarif", "SARIF 2.1.0 integration output.", "included"),
        ("provider-snapshot.json", "Provider snapshot replay for reproducibility.", "included"),
        (
            "attack-navigator-layer.json",
            "Defensive ATT&CK Navigator layer for mapped findings.",
            "included" if has_attack_layer else "optional",
        ),
        (
            "governance/*.json",
            "Accepted risk, VEX and asset context evidence.",
            "included" if has_governance else "optional",
        ),
    ]
    evidence_package_rows_html = []
    for artifact, purpose, included in evidence_package_rows:
        included_badge = (
            f"<span class='badge badge-success'>{included}</span>"
            if included == "included"
            else f"<span class='badge badge-info'>{included}</span>"
        )
        evidence_package_rows_html.append(
            f"<tr><td><code>{_safe_html(artifact)}</code></td>"
            f"<td>{_safe_html(purpose)}</td><td>{included_badge}</td></tr>"
        )

    return (
        "      <h3>Evidence Package Contents</h3>\n"
        "      <div class='table-wrap'>\n"
        "        <table class='compact-table'>\n"
        "          <thead>\n"
        "            <tr><th>Artifact File</th><th>Purpose</th><th>Status</th></tr>\n"
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
    technique_ids = _technique_ids_for_findings(findings)
    technique_status = (
        _short_list(technique_ids, limit=6, noun="technique")
        if technique_ids
        else "No reviewed techniques recorded."
    )
    attack_rows = [
        ("Mapped findings", f"{mapped_count} reviewed mapping records available."),
        ("Common techniques", technique_status),
        ("Navigator layer", navigator_layer_status),
        ("Unmapped CVEs", f"{unmapped_count} remain unmapped. No LLM inferred mappings are used."),
    ]
    attack_rows_html = []
    for context, status in attack_rows:
        attack_rows_html.append(
            f"<tr><td><strong>{_safe_html(context)}</strong></td><td>{_safe_html(status)}</td></tr>"
        )

    return (
        "      <div class='note-box'>\n"
        "        <p>ATT&amp;CK context is shown as reviewed defensive context only. "
        "It supports SOC validation and telemetry review, but it does not prove "
        "compromise and does not override the transparent base priority from CVSS, "
        "EPSS, KEV and asset context.</p>\n"
        "      </div>\n"
        "      <div class='table-wrap'>\n"
        "        <table class='compact-table'>\n"
        "          <thead>\n"
        "            <tr><th>Context</th><th>Status</th></tr>\n"
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
    from app.services.report_html_styles import EXECUTIVE_REPORT_CSS as _EXECUTIVE_REPORT_CSS
    from app.services.report_renderer_common import _redacted_bundle_payload

    payload, _redactions = _redacted_bundle_payload(payload)
    finding_count = len(payload.findings)

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

    if finding_count == 0:
        verdict_banner = (
            '      <div class="verdict-banner">\n'
            "        <p>No findings were recorded for this analysis run.</p>\n"
            "        <p>Confirm import coverage before treating this as a no-risk result.</p>\n"
            "      </div>"
        )
        decision_grid = ""
    else:
        campaigns = _get_remediation_campaigns_helper(payload.findings)
        emergency_campaigns = [
            campaign for campaign in campaigns if _campaign_requires_emergency(campaign)
        ]
        decision_needed_str = (
            "approve emergency remediation for open KEV backed production findings"
            if emergency_campaigns
            else "approve owners and remediation windows for open actionable findings"
        )
        verdict_text_2 = _executive_verdict_summary_helper(payload)
        caution_text = (
            f"Provider snapshot freshness is {provider_freshness_status.lower()} for "
            "formal sign off."
        )

        verdict_banner = (
            '      <div class="verdict-banner">\n'
            "        <p><strong>Decision needed:</strong> "
            f"{_safe_html(decision_needed_str)}, assign owners for top campaigns and "
            "require clean validation evidence after re import.</p>\n"
            f"        <p>{_safe_html(verdict_text_2)}</p>\n"
            "      </div>"
        )

        decision_grid = (
            '      <div class="decision-grid">\n'
            '        <div class="decision-card">\n'
            '          <span class="status-label">What management should approve</span>\n'
            "          <ul>\n"
            "            <li>Remediation window for open production campaigns.</li>\n"
            "            <li>Named owners for each remediation cluster.</li>\n"
            "            <li>Validation evidence after clean re import.</li>\n"
            "          </ul>\n"
            "        </div>\n"
            '        <div class="decision-card">\n'
            '          <span class="status-label">What requires caution</span>\n'
            "          <ul>\n"
            f"            <li>{_safe_html(caution_text)}</li>\n"
            "            <li>Accepted and VEX suppressed findings remain visible "
            "as evidence.</li>\n"
            "          </ul>\n"
            "        </div>\n"
            "      </div>"
        )

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
    has_attack_layer = any(
        _boolish_signal(finding, "attack_mapped") for finding in payload.findings
    )
    evidence_package_table = _html_evidence_package_table_helper(
        has_attack_layer=has_attack_layer,
        has_governance=bool(payload.governance_rollups),
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
    provider_snapshot_id = snapshot.id if snapshot else "N/A"
    provider_snapshot_html = _html_provider_snapshot_helper(
        snapshot,
        generated_at_dt,
        project_name=payload.project_name,
    )
    appendix_note = (
        "Detailed finding rows, component versions, long remediation text, input "
        "provenance, full rationale and per finding actions remain in the Technical "
        "Markdown report, Analysis JSON, Findings CSV, SARIF and Evidence ZIP. "
        "This Executive HTML report intentionally summarizes the decision path for "
        "stakeholder review."
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
        f"      <h1>{_safe_html(payload.project_name)}</h1>\n"
        f'      <p class="lede">{_safe_html(header_lede)}</p>\n'
        '      <dl class="meta-grid">\n'
        f"        <div><dt>Report Type</dt><dd>Executive HTML</dd></div>\n"
        f"        <div><dt>Project ID</dt><dd>{_safe_html(payload.project_id)}</dd></div>\n"
        f"        <div><dt>Analysis Run ID</dt><dd>{_safe_html(payload.run_id)}</dd></div>\n"
        f"        <div><dt>Generated At</dt><dd>{generated_at}</dd></div>\n"
        f"        <div><dt>Run Status</dt><dd>{_safe_html(payload.run_status)}</dd></div>\n"
        f"        <div><dt>Input Type</dt><dd>{_safe_html(payload.input_type)}</dd></div>\n"
        f"        <div><dt>Input File</dt><dd>{_safe_html(payload.filename)}</dd></div>\n"
        "        <div><dt>Provider Snapshot</dt><dd>"
        f"{_safe_html(provider_snapshot_id)}</dd></div>\n"
        "      </dl>\n"
        "    </header>\n"
        "\n"
        '    <section aria-labelledby="decision-brief">\n'
        '      <p class="eyebrow">Executive Summary</p>\n'
        '      <h2 id="decision-brief">Decision Brief</h2>\n'
        f"{verdict_banner}\n"
        f"{decision_grid}\n"
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="risk-posture">\n'
        '      <p class="eyebrow">Risk Posture</p>\n'
        '      <h2 id="risk-posture">Executive Risk Posture</h2>\n'
        '      <div class="metric-grid">\n'
        f"        {_html_metric('Total Findings', finding_count)}\n"
        f"        {_html_metric('Open Actionable', open_actionable)}\n"
        f"        {_html_metric('KEV Backed', kev_listed)}\n"
        f"        {_html_metric('Emergency SLA', emergency_sla)}\n"
        f"        {_html_metric('Accepted Risk', accepted_risk)}\n"
        f"        {_html_metric('VEX Suppressed', vex_suppressed)}\n"
        f"        {_html_metric('Fixed Evidence', fixed_findings)}\n"
        f"        {_html_metric('Review Due / Expiring', review_due_or_expiring)}\n"
        f"        {_html_metric('Internet Facing Prod', internet_facing)}\n"
        f"        {_html_metric('Unique CVEs', unique_cves)}\n"
        f"        {_html_metric('Provider Freshness', provider_freshness_status)}\n"
        f"        {_html_metric('Evidence Bundle', 'Ready')}\n"
        "      </div>\n"
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
        '      <h2 id="appendix">Technical Markdown Separation</h2>\n'
        f'      <p class="footer-note">{_safe_html(appendix_note)}</p>\n'
        "    </section>\n"
        "  </main>\n"
        "</body>\n"
        "</html>\n"
    )
