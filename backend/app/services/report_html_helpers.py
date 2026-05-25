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
    EvidencePackageContext,
    ExecutiveReportViewModel,
    MarkdownProviderSnapshot,
    MarkdownReportFinding,
    MarkdownReportPayload,
)
from app.services.report_renderer_common import (
    _boolish_signal,
    _dict_list,
    _list_value,
    _priority_label,
)

PROVIDER_FRESHNESS_THRESHOLDS = {
    "epss": {"warning_days": 7, "stale_days": 30},
    "nvd": {"stale_days": 30},
    "kev": {"stale_days": 30},
}

REVIEWED_ATTACK_SOURCES = {
    "ctid-json",
    "ctid",
    "ctid-mappings-explorer",
    "local-curated",
    "curated",
    "imported-reviewed",
}

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
    """Html evidence signals badges function."""
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
        """Escape preserve spaces function."""
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
    """Is overdue helper function."""
    if not date_str:
        return False
    try:
        dt = datetime.strptime(date_str.split("T")[0], "%Y-%m-%d")
        return dt.date() < ref_date.date()
    except ValueError:
        return False


def _finding_sort_key(finding: MarkdownReportFinding) -> tuple[int, int, str]:
    """Finding sort key function."""
    return (
        int(finding.operational_rank or 999_999),
        int(finding.priority_rank or 999_999),
        finding.cve_id,
    )


def _status_value(finding: MarkdownReportFinding) -> str:
    """Status value function."""
    return str(finding.status or "").split(".", maxsplit=1)[-1].strip().lower()


def _is_under_investigation_finding(finding: MarkdownReportFinding) -> bool:
    """Is under investigation finding function."""
    if finding.under_investigation:
        return True
    status_counts = finding.explanation.get("vex_statuses")
    if isinstance(status_counts, dict) and "under_investigation" in status_counts:
        return True
    status = finding.explanation.get("vex_status")
    return isinstance(status, str) and status.strip().lower() == "under_investigation"


def _is_fixed_evidence_finding(finding: MarkdownReportFinding) -> bool:
    """Is fixed evidence finding function."""
    return _status_value(finding) == "fixed"


def _is_actionable_finding(finding: MarkdownReportFinding) -> bool:
    """Is actionable finding function."""
    return _finding_actionability_bucket(finding) == "open"


def _is_suppressed_finding(finding: MarkdownReportFinding) -> bool:
    """Is suppressed finding function."""
    status = str(finding.status or "").split(".", maxsplit=1)[-1].strip().lower()
    return finding.suppressed_by_vex or status == "suppressed"


def _is_accepted_risk_finding(finding: MarkdownReportFinding) -> bool:
    """Is accepted risk finding function."""
    status = _status_value(finding)
    return finding.waived or status == "accepted"


def _has_governance_exception(finding: MarkdownReportFinding) -> bool:
    """Has governance exception function."""
    return (
        _is_accepted_risk_finding(finding)
        or _is_suppressed_finding(finding)
        or _is_fixed_evidence_finding(finding)
        or _is_under_investigation_finding(finding)
    )


def _occurrence_count(finding: MarkdownReportFinding) -> int:
    """Occurrence count function."""
    return max(1, len(finding.occurrences))


def _count_findings(
    findings: list[MarkdownReportFinding],
    predicate: Callable[[MarkdownReportFinding], bool],
) -> int:
    """Count findings function."""
    return sum(1 for finding in findings if predicate(finding))


def _unique_values(
    findings: list[MarkdownReportFinding],
    value_for_finding: Callable[[MarkdownReportFinding], str | None],
) -> list[str]:
    """Unique values function."""
    values = {
        value.strip()
        for finding in findings
        if (value := value_for_finding(finding)) is not None and value.strip()
    }
    return sorted(values)


def _pluralize(count: int, singular: str, plural: str | None = None) -> str:
    """Pluralize function."""
    label = singular if count == 1 else plural or f"{singular}s"
    return f"{count} {label}"


def _normalized_context_label(value: str) -> str:
    """Normalized context label function."""
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
    """Joined context function."""
    normalized = [_normalized_context_label(value) for value in values if value]
    return _short_list(sorted(set(normalized)), limit=limit, noun=noun) if normalized else "Unknown"


def _short_list(values: list[str], *, limit: int = 3, noun: str = "item") -> str:
    """Short list function."""
    if not values:
        return "N/A"
    shown = values[:limit]
    if len(values) <= limit:
        return ", ".join(shown)
    hidden_count = len(values) - limit
    noun_text = noun if hidden_count == 1 else f"{noun}s"
    return ", ".join(shown) + f", and {hidden_count} additional {noun_text}"


def _counted_or_full_list(values: list[str], *, noun: str) -> str:
    """Counted or full list function."""
    unique_values = sorted({value for value in values if value})
    if not unique_values:
        return "N/A"
    noun_text = noun if len(unique_values) == 1 else f"{noun}s"
    return f"{len(unique_values)} {noun_text}: {', '.join(unique_values)}"


def _actionable_findings(findings: list[MarkdownReportFinding]) -> list[MarkdownReportFinding]:
    """Actionable findings function."""
    return [finding for finding in findings if _is_actionable_finding(finding)]


def _finding_actionability_bucket(finding: MarkdownReportFinding) -> str:
    """Finding actionability bucket function."""
    if _is_fixed_evidence_finding(finding):
        return "fixed"
    if _is_accepted_risk_finding(finding):
        return "accepted"
    if _is_under_investigation_finding(finding):
        return "open"
    if _is_suppressed_finding(finding):
        return "suppressed"
    return "open"


def _actionability_counts_helper(
    findings: list[MarkdownReportFinding],
) -> Counter[str]:
    """Actionability counts helper function."""
    counts: Counter[str] = Counter()
    for finding in findings:
        counts[_finding_actionability_bucket(finding)] += 1
    return counts


def _actionability_summary_helper(findings: list[MarkdownReportFinding]) -> str:
    """Actionability summary helper function."""
    counts = _actionability_counts_helper(findings)
    parts = []
    for bucket in ("open", "accepted", "suppressed", "fixed"):
        count = counts.get(bucket, 0)
        if count:
            parts.append(f"{count} {bucket}")
    return ", ".join(parts) if parts else "No findings"


def _severity_open_count(findings: list[MarkdownReportFinding], severity: str) -> int:
    """Severity open count function."""
    return _count_findings(
        findings,
        lambda finding: (
            _priority_label(finding.priority) == severity and _is_actionable_finding(finding)
        ),
    )


def _fixed_finding_count(findings: list[MarkdownReportFinding]) -> int:
    """Fixed finding count function."""
    return _count_findings(
        findings,
        lambda finding: _finding_actionability_bucket(finding) == "fixed",
    )


def _technique_ids_for_findings(findings: list[MarkdownReportFinding]) -> list[str]:
    """Technique ids for findings function."""
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


def _attack_context_value(finding: MarkdownReportFinding) -> dict[str, Any]:
    """Attack context value function."""
    value = finding.explanation.get("attack_context")
    return dict(value) if isinstance(value, dict) else {}


def _is_reviewed_attack_context(finding: MarkdownReportFinding) -> bool:
    """Is reviewed attack context function."""
    context = _attack_context_value(finding)
    source = str(context.get("source") or "").strip().lower()
    review_status = str(context.get("review_status") or "").strip().lower()
    return (
        bool(context.get("mapped"))
        and source in REVIEWED_ATTACK_SOURCES
        and review_status == "reviewed"
    )


def _reviewed_attack_mapping_rows_for_findings(
    findings: list[MarkdownReportFinding],
) -> list[dict[str, str]]:
    """Reviewed attack mapping rows for findings function."""
    rows: dict[tuple[str, str], dict[str, str]] = {}
    for finding in findings:
        if not _is_reviewed_attack_context(finding):
            continue
        context = _attack_context_value(finding)
        source = str(context.get("source") or "reviewed mapping")
        mappings = _list_value(context, "mappings")
        technique_ids = _list_value(context, "technique_ids")
        if not mappings and technique_ids:
            mappings = [{"technique_id": technique_id} for technique_id in technique_ids]
        for mapping in mappings:
            if not isinstance(mapping, dict):
                continue
            technique_id = (
                mapping.get("technique_id") or mapping.get("attack_object_id") or mapping.get("id")
            )
            if not isinstance(technique_id, str) or not technique_id.strip():
                continue
            name = mapping.get("technique_name") or mapping.get("attack_object_name") or ""
            key = (technique_id.strip(), source)
            rows[key] = {
                "technique_id": technique_id.strip(),
                "name": str(name).strip(),
                "source": source,
            }
    return [rows[key] for key in sorted(rows)]


def _reviewed_attack_technique_ids_for_findings(
    findings: list[MarkdownReportFinding],
) -> list[str]:
    """Reviewed attack technique ids for findings function."""
    return [row["technique_id"] for row in _reviewed_attack_mapping_rows_for_findings(findings)]


def _campaign_scope_summary(campaign: dict[str, Any]) -> str:
    """Campaign scope summary function."""
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
    """Evidence signal summary function."""
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
    """Campaign requires emergency function."""
    return bool(
        campaign["actionable_count"] > 0
        and (
            campaign["in_kev"]
            or (campaign["max_cvss"] is not None and campaign["max_cvss"] >= 9.0)
            or (campaign["max_epss"] is not None and campaign["max_epss"] >= 0.9)
        )
    )


def _campaign_decision_statement(campaign: dict[str, Any]) -> str:
    """Campaign decision statement function."""
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
    """First available owner function."""
    owners: list[str] = []
    for campaign in campaigns:
        owners.extend(str(owner) for owner in campaign["owners"] if owner)
    return _short_list(sorted(set(owners)), limit=3, noun="owner") if owners else "Unassigned"


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
    findings: list[MarkdownReportFinding], project_name: str | None = None
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

    def campaigns_for_service(service_name: str) -> list[dict[str, Any]]:
        """Campaigns for service function."""
        return [
            campaign
            for campaign in campaigns
            if (
                service_name in campaign["services"]
                or (not campaign["services"] and service_name == "Infrastructure / Shared Services")
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
            1 for campaign in service_campaigns if campaign["actionable_count"] > 0
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


def _normalized_campaign_action(value: str | None) -> str:
    """Normalized campaign action function."""
    if not value:
        return "review-and-remediate"
    text = re.sub(r"\bCVE-\d{4}-\d{4,}\b", "cve", value, flags=re.IGNORECASE)
    text = re.sub(r"\s+", " ", text).strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return text[:96] or "review-and-remediate"


def _component_family(finding: MarkdownReportFinding) -> str:
    """Component family function."""
    if finding.component_purl:
        package_part = finding.component_purl.rsplit("/", maxsplit=1)[-1].split("@", maxsplit=1)[0]
        if package_part:
            return package_part.lower()
    component = str(finding.component or "").strip()
    if not component:
        return "unknown-component"
    parts = component.split()
    if len(parts) > 1 and re.match(r"^v?\d", parts[-1]):
        parts = parts[:-1]
    return re.sub(r"[^a-z0-9]+", "-", " ".join(parts).lower()).strip("-") or "unknown-component"


def _campaign_base_key(finding: MarkdownReportFinding) -> tuple[str, str, str]:
    """Campaign base key function."""
    return (finding.cve_id, _priority_label(finding.priority), _component_family(finding))


def _campaign_group_key(
    finding: MarkdownReportFinding,
    base_action_counts: dict[tuple[str, str, str], set[str]],
) -> tuple[str, str, str, str]:
    """Campaign group key function."""
    base_key = _campaign_base_key(finding)
    action = _normalized_campaign_action(finding.recommended_action or finding.decision_statement)
    open_actions = base_action_counts.get(base_key) or set()
    if len(open_actions) <= 1:
        action = next(iter(open_actions), action)
    elif not _is_actionable_finding(finding) and action not in open_actions:
        action = sorted(open_actions)[0]
    return (*base_key, action)


def _priority_class_for_campaign(campaign: dict[str, Any]) -> str:
    """Priority class for campaign function."""
    if _campaign_requires_emergency(campaign):
        return "P1"
    if campaign["actionable_count"] > 0 and (
        campaign["in_kev"]
        or (campaign["max_cvss"] is not None and campaign["max_cvss"] >= 7.0)
        or (campaign["max_epss"] is not None and campaign["max_epss"] >= 0.01)
    ):
        return "P2"
    if campaign["actionable_count"] > 0:
        return "P3"
    return "Evidence"


def _campaign_sort_key(campaign: dict[str, Any]) -> tuple[int, float, float, int, int, str]:
    """Campaign sort key function."""
    findings = campaign["findings"]
    internet_prod = any(
        _is_actionable_finding(finding)
        and (finding.exposure or "").lower() in {"internet-facing", "external"}
        and (finding.environment or "").lower() in {"prod", "production"}
        for finding in findings
    )
    critical_service = any(
        _is_actionable_finding(finding) and (finding.criticality or "").lower() == "critical"
        for finding in findings
    )
    governance_urgency = campaign["accepted_count"] + campaign["vex_count"]
    return (
        0 if campaign["actionable_count"] and campaign["in_kev"] and internet_prod else 1,
        -float(campaign["max_epss"] or 0.0),
        -float(campaign["max_cvss"] or 0.0),
        0 if critical_service else 1,
        -int(governance_urgency),
        str(campaign["cve_id"]),
    )


def _get_remediation_campaigns_helper(
    findings: list[MarkdownReportFinding], project_name: str | None = None
) -> list[dict[str, Any]]:
    """Get remediation campaigns helper function."""
    base_action_counts: dict[tuple[str, str, str], set[str]] = {}
    for finding in sorted(findings, key=_finding_sort_key):
        if _is_actionable_finding(finding):
            base_action_counts.setdefault(_campaign_base_key(finding), set()).add(
                _normalized_campaign_action(
                    finding.recommended_action or finding.decision_statement
                )
            )

    groups: dict[tuple[str, str, str, str], list[MarkdownReportFinding]] = {}
    for finding in sorted(findings, key=_finding_sort_key):
        groups.setdefault(_campaign_group_key(finding, base_action_counts), []).append(finding)

    campaigns: list[dict[str, Any]] = []
    for key, grouped_findings in groups.items():
        cve_id = key[0]
        actionable = _actionable_findings(grouped_findings)
        assets = _unique_values(grouped_findings, lambda finding: finding.asset)
        services = _unique_values(grouped_findings, lambda finding: finding.business_service)
        owners = _unique_values(grouped_findings, lambda finding: finding.owner)
        environments = _unique_values(grouped_findings, lambda finding: finding.environment)
        exposures = _unique_values(grouped_findings, lambda finding: finding.exposure)
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

        actionability_counts = _actionability_counts_helper(grouped_findings)
        waived_count = actionability_counts.get("accepted", 0)
        vex_count = actionability_counts.get("suppressed", 0)
        fixed_count = _fixed_finding_count(grouped_findings)
        alias = CVE_ALIASES.get(cve_id, "")
        campaign_name = f"{cve_id} / {alias}" if alias else cve_id
        internet_facing = any(
            (finding.exposure or "").lower() in {"internet-facing", "external"}
            for finding in grouped_findings
        )

        campaigns.append(
            {
                "rank": 0,
                "sort_rank": min(_finding_sort_key(finding)[0] for finding in grouped_findings),
                "cve_id": cve_id,
                "group_key": "|".join(key),
                "project_name": project_name,
                "alias": alias,
                "campaign_name": campaign_name,
                "findings": grouped_findings,
                "actionable_findings": actionable,
                "assets": assets,
                "services": services,
                "owners": owners,
                "environments": environments,
                "exposures": exposures,
                "actions": actions,
                "slas": slas,
                "max_cvss": max_cvss,
                "max_epss": max_epss,
                "in_kev": in_kev,
                "attack_techniques": _reviewed_attack_technique_ids_for_findings(grouped_findings),
                "attack_mappings": _reviewed_attack_mapping_rows_for_findings(grouped_findings),
                "total_occurrences": sum(
                    _occurrence_count(finding) for finding in grouped_findings
                ),
                "total_assets": len(assets),
                "affected_assets": assets,
                "business_services": services,
                "internet_facing_exposure": internet_facing,
                "actionable_count": len(actionable),
                "actionable_occurrences": sum(_occurrence_count(finding) for finding in actionable),
                "accepted_count": waived_count,
                "waived_count": waived_count,
                "vex_count": vex_count,
                "fixed_count": fixed_count,
                "open_actionable_count": len(actionable),
            }
        )
    campaigns.sort(key=_campaign_sort_key)
    for rank, campaign in enumerate(campaigns, start=1):
        campaign["rank"] = rank
        campaign["priority_label"] = _priority_class_for_campaign(campaign)
        campaign["decision_statement"] = _campaign_decision_statement(campaign)
        campaign["evidence_signals"] = _evidence_signal_summary(campaign)
    return campaigns


def _html_remediation_campaigns_helper(
    findings: list[MarkdownReportFinding], project_name: str | None = None
) -> str:
    """Html remediation campaigns helper function."""
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
            "badge-critical"
            if campaign["priority_label"] == "P1"
            else "badge-high"
            if campaign["priority_label"] in {"P2", "P3"}
            else "badge-neutral"
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
            f"<td><span class='badge {priority_class}'>{campaign['priority_label']}</span></td>"
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
    """Campaigns label function."""
    names = [str(campaign["campaign_name"]) for campaign in campaigns]
    return _short_list(names, limit=limit, noun="campaign")


def _campaign_evidence_label(campaigns: list[dict[str, Any]]) -> str:
    """Campaign evidence label function."""
    signals = []
    for campaign in campaigns[:2]:
        signals.append(_evidence_signal_summary(campaign))
    return "; ".join(signals) if signals else "Run evidence and provider snapshot"


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


def _calculate_age_and_verdict_helper(
    date_str: str | None,
    generated_at: datetime | None,
    *,
    source: str = "epss",
) -> tuple[str, str, str]:
    """Calculate age and verdict helper function."""
    thresholds = PROVIDER_FRESHNESS_THRESHOLDS.get(
        source,
        PROVIDER_FRESHNESS_THRESHOLDS["epss"],
    )
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
        stale_days = int(thresholds["stale_days"])
        warning_days = thresholds.get("warning_days")
        if warning_days is not None and delta > int(warning_days) and delta <= stale_days:
            return age_str, "Warning", "badge-warning"
        if delta > stale_days:
            return age_str, "Stale", "badge-stale"
        return age_str, "Fresh", "badge-success"
    except ValueError:
        if source == "kev" and date_str:
            return "N/A", "Needs Review", "badge-warning"
        return "N/A", "Unknown", "badge-neutral"


def _provider_status_class(status: str) -> str:
    """Provider status class function."""
    return {
        "Fresh": "badge-success",
        "Warning": "badge-warning",
        "Stale": "badge-stale",
        "Reproducible": "badge-success",
        "Included": "badge-success",
        "Expected": "badge-info",
        "Recorded": "badge-success",
        "Controlled": "badge-success",
        "Needs Review": "badge-warning",
        "Not available": "badge-neutral",
        "Unknown": "badge-neutral",
    }.get(status, "badge-neutral")


def _evidence_bundle_manifest_row_helper(
    evidence_package_context: EvidencePackageContext | None,
) -> dict[str, str]:
    """Evidence bundle manifest row helper function."""
    if evidence_package_context is not None and evidence_package_context.mode == "bundle":
        return {
            "signal": "Evidence bundle manifest",
            "value": evidence_package_context.manifest_path,
            "status": "Included",
            "meaning": (
                "Evidence package rows are derived from the generated bundle artifact list; "
                "the final manifest records artifact hashes."
            ),
        }
    return {
        "signal": "Evidence bundle manifest",
        "value": "manifest.json",
        "status": "Expected",
        "meaning": (
            "Standalone HTML shows expected bundle contents. Generate the Evidence ZIP "
            "to record final manifest hashes."
        ),
    }


def _provider_freshness_rows_helper(
    snapshot: MarkdownProviderSnapshot | None,
    generated_at: datetime | None = None,
    evidence_package_context: EvidencePackageContext | None = None,
) -> list[dict[str, str]]:
    """Provider freshness rows helper function."""
    from app.services.report_formatting import metadata_bool as _metadata_bool
    from app.services.report_formatting import metadata_list as _metadata_list

    if snapshot is None:
        return [
            {
                "signal": "Snapshot locked",
                "value": "Not available",
                "status": "Not available",
                "meaning": "No provider snapshot was linked to this analysis run.",
            },
            {
                "signal": "NVD last sync",
                "value": "N/A",
                "status": "Unknown",
                "meaning": "Date is missing; freshness cannot be determined.",
            },
            {
                "signal": "EPSS date",
                "value": "N/A",
                "status": "Unknown",
                "meaning": "Date is missing; freshness cannot be determined.",
            },
            {
                "signal": "KEV catalog version",
                "value": "N/A",
                "status": "Unknown",
                "meaning": "Date is missing; freshness cannot be determined.",
            },
            {
                "signal": "Content hash",
                "value": "Missing",
                "status": "Warning",
                "meaning": "Snapshot hash is missing; bundle verification is weaker.",
            },
            {
                "signal": "Source hashes",
                "value": "N/A",
                "status": "Warning",
                "meaning": "Provider source hashes are missing from this snapshot.",
            },
            {
                "signal": "Selected sources",
                "value": "N/A",
                "status": "Warning",
                "meaning": "Vulnerability intelligence sources were not recorded.",
            },
            {
                "signal": "Static HTML safety",
                "value": "No scripts, no external assets, escaped recommendation text",
                "status": "Controlled",
                "meaning": "Report is suitable for local review and evidence package distribution.",
            },
            _evidence_bundle_manifest_row_helper(evidence_package_context),
        ]

    ref_date = generated_at or datetime.now(UTC)
    locked_provider_data = _metadata_bool(snapshot.source_metadata, "locked_provider_data")

    def dated_row(signal: str, value: str | None, source: str) -> dict[str, str]:
        """Dated row function."""
        age, verdict, _class_name = _calculate_age_and_verdict_helper(
            value,
            ref_date,
            source=source,
        )
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
        elif status == "Needs Review":
            meaning = (
                "Stored KEV value is not a clear sync timestamp; verify catalog "
                "version semantics before making a freshness claim."
            )
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
        dated_row("NVD last sync", snapshot.nvd_last_sync, "nvd"),
        dated_row("EPSS date", snapshot.epss_date, "epss"),
        dated_row("KEV catalog version", snapshot.kev_catalog_version, "kev"),
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
            "signal": "Source hashes",
            "value": ", ".join(
                f"{key}: {value}" for key, value in sorted(snapshot.source_hashes.items())
            )
            if snapshot.source_hashes
            else "N/A",
            "status": "Recorded" if snapshot.source_hashes else "Warning",
            "meaning": (
                "Provider source hash entries are available for replay comparison."
                if snapshot.source_hashes
                else "Provider source hashes are missing from this snapshot."
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
        _evidence_bundle_manifest_row_helper(evidence_package_context),
        {
            "signal": "Static HTML safety",
            "value": "No scripts, no external assets, escaped recommendation text",
            "status": "Controlled",
            "meaning": "Report is suitable for local review and evidence package distribution.",
        },
    ]
    return rows


def _provider_freshness_status_helper(
    snapshot: MarkdownProviderSnapshot | None,
    generated_at: datetime | None = None,
    evidence_package_context: EvidencePackageContext | None = None,
) -> str:
    """Provider freshness status helper function."""
    rows = _provider_freshness_rows_helper(snapshot, generated_at, evidence_package_context)
    statuses = {row["status"] for row in rows}
    if "Not available" in statuses and len(statuses) == 1:
        return "Not available"
    if "Stale" in statuses:
        return "Stale"
    if {"Warning", "Unknown", "Not available", "Needs Review"} & statuses:
        return "Warning"
    return "Fresh"


def _html_provider_snapshot_helper(
    snapshot: MarkdownProviderSnapshot | None,
    generated_at: datetime | None = None,
    project_name: str | None = None,
    evidence_package_context: EvidencePackageContext | None = None,
) -> str:
    """Html provider snapshot helper function."""
    from app.services.report_formatting import metadata_bool as _metadata_bool
    from app.services.report_formatting import metadata_list as _metadata_list

    _ = project_name

    if snapshot is None:
        freshness_rows = _provider_freshness_rows_helper(
            None,
            generated_at,
            evidence_package_context,
        )
        rows_html = "\n".join(
            f"            <tr>"
            f"<td><strong>{_safe_html(row['signal'])}</strong></td>"
            f"<td>{_safe_html(row['value'])}</td>"
            f"<td><span class='badge {_provider_status_class(row['status'])}'>"
            f"{_safe_html(row['status'])}</span></td>"
            f"<td>{_safe_html(row['meaning'])}</td>"
            f"</tr>"
            for row in freshness_rows
        )
        return (
            "<p>No provider snapshot was linked to this analysis run.</p>\n"
            "      <div class='table-wrap'>\n"
            "        <table>\n"
            "          <thead>\n"
            "            <tr><th>Signal</th><th>Value</th><th>Status</th>"
            "<th>Meaning</th></tr>\n"
            "          </thead>\n"
            f"          <tbody>\n{rows_html}\n          </tbody>\n"
            "        </table>\n"
            "      </div>"
        )

    freshness_rows = _provider_freshness_rows_helper(
        snapshot,
        generated_at,
        evidence_package_context,
    )
    overall_status = _provider_freshness_status_helper(
        snapshot,
        generated_at,
        evidence_package_context,
    )
    rows: list[str] = []
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
    evidence_package_context: EvidencePackageContext | None = None,
) -> str:
    """Html evidence package table helper function."""
    evidence_package_rows = _evidence_package_rows_helper(
        has_attack_layer=has_attack_layer,
        has_governance=has_governance,
        evidence_package_context=evidence_package_context,
    )
    evidence_package_rows_html = []
    for row in evidence_package_rows:
        status = str(row["status"])
        if status == "included":
            badge_class = "badge-success"
        elif status == "expected":
            badge_class = "badge-info"
        else:
            badge_class = "badge-neutral"
        included_badge = f"<span class='badge {badge_class}'>{_safe_html(status)}</span>"
        sha256 = row.get("sha256") or "N/A"
        size_or_note = (
            f"{int(row['size_bytes']):,} bytes"
            if row.get("size_bytes") is not None
            else row.get("note") or "N/A"
        )
        evidence_package_rows_html.append(
            f"<tr><td><code>{_safe_html(row['artifact'])}</code></td>"
            f"<td>{_safe_html(row['purpose'])}</td><td>{included_badge}</td>"
            f"<td><code>{_safe_html(sha256)}</code></td>"
            f"<td>{_safe_html(size_or_note)}</td></tr>"
        )

    return (
        "      <div class='table-wrap'>\n"
        "        <table class='compact-table evidence-package-table'>\n"
        "          <thead>\n"
        "            <tr><th>Artifact File</th><th>Purpose</th><th>Status</th>"
        "<th>SHA256</th><th>Size / Note</th></tr>\n"
        "          </thead>\n"
        "          <tbody>\n"
        f"            {chr(10).join(evidence_package_rows_html)}\n"
        "          </tbody>\n"
        "        </table>\n"
        "      </div>"
    )


def _evidence_package_rows_helper(
    *,
    has_attack_layer: bool,
    has_governance: bool,
    evidence_package_context: EvidencePackageContext | None = None,
) -> list[dict[str, Any]]:
    """Evidence package rows helper function."""
    if evidence_package_context is not None and evidence_package_context.artifacts:
        return [
            {
                "artifact": artifact.artifact,
                "purpose": artifact.purpose,
                "status": artifact.status,
                "sha256": artifact.sha256,
                "size_bytes": artifact.size_bytes,
                "kind": artifact.kind,
                "note": artifact.note,
            }
            for artifact in evidence_package_context.artifacts
        ]
    base_status = "expected"
    base_note = "Expected when Evidence ZIP is generated."
    return [
        {
            "artifact": "manifest.json",
            "purpose": "Bundle manifest and artifact hash verification.",
            "status": base_status,
            "note": base_note,
        },
        {
            "artifact": "executive.html",
            "purpose": "Decision oriented executive brief.",
            "status": base_status,
            "note": base_note,
        },
        {
            "artifact": "technical.md",
            "purpose": "Detailed analyst handoff with finding rows and rationale.",
            "status": base_status,
            "note": base_note,
        },
        {
            "artifact": "analysis.json",
            "purpose": "Machine readable analysis export.",
            "status": base_status,
            "note": base_note,
        },
        {
            "artifact": "findings.csv",
            "purpose": "Spreadsheet review of findings and owner scope.",
            "status": base_status,
            "note": base_note,
        },
        {
            "artifact": "results.sarif",
            "purpose": "SARIF 2.1.0 integration output.",
            "status": base_status,
            "note": base_note,
        },
        {
            "artifact": "provider-snapshot.json",
            "purpose": "Provider snapshot replay for reproducibility.",
            "status": base_status,
            "note": base_note,
        },
        {
            "artifact": "attack-navigator-layer.json",
            "purpose": "Defensive ATT&CK Navigator layer for mapped findings.",
            "status": "included" if has_attack_layer else "optional",
            "note": "Generated only when reviewed ATT&CK mappings are available.",
        },
        {
            "artifact": "governance/*.json",
            "purpose": "Accepted risk, VEX and asset context evidence.",
            "status": "included" if has_governance else "optional",
            "note": "Generated only when governance artifacts are available.",
        },
    ]


def _html_attack_context_table_helper(findings: list[MarkdownReportFinding]) -> str:
    """Html attack context table helper function."""
    reviewed_mappings = _reviewed_attack_mapping_rows_for_findings(findings)
    mapped_count = sum(1 for finding in findings if _is_reviewed_attack_context(finding))
    raw_mapped_count = sum(1 for finding in findings if _boolish_signal(finding, "attack_mapped"))
    needs_source_review = max(0, raw_mapped_count - mapped_count)
    unmapped_count = len(findings) - mapped_count
    navigator_layer_status = (
        "Included in Evidence ZIP" if mapped_count > 0 else "Optional / not generated"
    )
    technique_ids = [row["technique_id"] for row in reviewed_mappings]
    mapping_sources = sorted({row["source"] for row in reviewed_mappings if row["source"]})
    technique_status = (
        _short_list(technique_ids, limit=6, noun="technique")
        if technique_ids
        else "No reviewed techniques recorded."
    )
    attack_rows = [
        ("Mapped findings", f"{mapped_count} reviewed mapping records available."),
        ("Common techniques", technique_status),
        (
            "Mapping source",
            _short_list(mapping_sources, limit=4, noun="source")
            if mapping_sources
            else "No reviewed mapping source recorded.",
        ),
        ("Navigator layer", navigator_layer_status),
        (
            "Mappings needing source review",
            f"{needs_source_review} mapping records are not shown as confirmed.",
        ),
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


def _evidence_bundle_status_label(
    evidence_package_context: EvidencePackageContext | None,
) -> str:
    """Evidence bundle status label function."""
    return (
        "Ready"
        if evidence_package_context is not None and evidence_package_context.mode == "bundle"
        else "Expected"
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


def build_executive_report_view_model(
    payload: MarkdownReportPayload,
    *,
    evidence_package_context: EvidencePackageContext | None = None,
) -> ExecutiveReportViewModel:
    """Prepare the decision-oriented executive report model before rendering."""
    generated_at = payload.generated_at
    snapshot = payload.provider_snapshot
    campaigns = _get_remediation_campaigns_helper(
        payload.findings, project_name=payload.project_name
    )
    actionability = _actionability_counts_helper(payload.findings)
    waiver_debt = payload.governance_rollups.get("waiver_debt", {})
    waiver_items = _dict_list(waiver_debt.get("items"))
    overdue_count = sum(
        1
        for item in waiver_items
        if _is_overdue_helper(str(item.get("review_at") or ""), generated_at)
    )
    review_due_or_expiring = max(
        int(waiver_debt.get("review_due_count") or 0)
        + int(waiver_debt.get("expiring_soon_count") or 0),
        overdue_count,
    )
    emergency_campaigns = [
        campaign for campaign in campaigns if _campaign_requires_emergency(campaign)
    ]
    provider_freshness = _provider_freshness_status_helper(
        snapshot,
        generated_at,
        evidence_package_context,
    )
    reviewed_attack_rows = _reviewed_attack_mapping_rows_for_findings(payload.findings)
    has_governance = bool(payload.governance_rollups)
    business_services = _business_service_view_rows(payload.findings, campaigns)
    recommendations = _recommendation_view_rows(campaigns)
    decision_needed = _decision_needed_statement_helper(
        campaigns,
        provider_freshness=provider_freshness,
        review_due_or_expiring=review_due_or_expiring,
    )
    open_campaigns = [campaign for campaign in campaigns if campaign["actionable_count"] > 0]
    owner_gap_count = sum(1 for campaign in open_campaigns if not campaign["owners"])
    evidence_bundle_status = _evidence_bundle_status_label(evidence_package_context)
    return ExecutiveReportViewModel(
        report_identity={
            "report_type": "Executive HTML",
            "project_id": payload.project_id,
            "project_name": payload.project_name,
            "analysis_run_id": payload.run_id,
            "generated_at": generated_at,
            "run_status": payload.run_status,
            "input_type": payload.input_type,
            "input_file": payload.filename,
            "provider_snapshot_id": snapshot.id if snapshot else None,
        },
        decision_brief={
            "decision_needed": decision_needed,
            "executive_summary": _executive_verdict_summary_helper(payload),
            "management_approval_items": [
                f"{_pluralize(len(emergency_campaigns), 'emergency remediation campaign')}."
                if emergency_campaigns
                else (
                    f"{_pluralize(len(open_campaigns), 'open remediation campaign')} "
                    "remediation window."
                ),
                "Named owners for each remediation cluster.",
                "Validation evidence after clean re import.",
            ],
            "caution_items": [
                f"Provider snapshot freshness is {provider_freshness.lower()} for formal sign off.",
                (
                    f"{_pluralize(owner_gap_count, 'open campaign')} "
                    f"{'has' if owner_gap_count == 1 else 'have'} no named owner."
                )
                if owner_gap_count
                else "Open campaigns have named owners in the evidence.",
                "Accepted risk, VEX suppressed and fixed findings remain visible as evidence.",
            ],
            "validation_items": [
                "Clean re import after remediation.",
                "Updated fixed evidence for closed findings.",
                "Evidence ZIP manifest and hashes retained for audit review.",
            ],
        },
        risk_posture={
            "total_findings": len(payload.findings),
            "open_actionable_findings": actionability.get("open", 0),
            "kev_backed_findings": _count_findings(
                payload.findings, lambda finding: finding.in_kev
            ),
            "emergency_sla_count": len(emergency_campaigns),
            "accepted_risk_findings": actionability.get("accepted", 0),
            "vex_suppressed_findings": actionability.get("suppressed", 0),
            "fixed_evidence_findings": actionability.get("fixed", 0),
            "review_due_or_expiring_count": review_due_or_expiring,
            "internet_facing_prod_count": _count_findings(
                payload.findings,
                lambda finding: (
                    _is_actionable_finding(finding)
                    and (finding.exposure or "").lower() in {"internet-facing", "external"}
                    and (finding.environment or "").lower() in {"prod", "production"}
                ),
            ),
            "unique_cves_count": len({finding.cve_id for finding in payload.findings}),
            "provider_freshness_verdict": provider_freshness,
            "evidence_bundle_status": evidence_bundle_status,
        },
        action_plan=_action_plan_rows_helper(payload),
        remediation_campaigns=campaigns,
        business_services=business_services,
        governance_exceptions={
            "waiver_rows": waiver_items,
            "waivers": int(waiver_debt.get("waiver_count") or 0),
            "expired": int(waiver_debt.get("expired_count") or 0),
            "review_due": int(waiver_debt.get("review_due_count") or 0),
            "expiring_soon": int(waiver_debt.get("expiring_soon_count") or 0),
            "accepted_findings": actionability.get("accepted", 0),
            "vex_suppressed": actionability.get("suppressed", 0),
            "fixed_findings": actionability.get("fixed", 0),
            "under_investigation": _count_findings(
                payload.findings,
                _is_under_investigation_finding,
            ),
        },
        evidence_confidence={
            "provider_freshness_verdict": provider_freshness,
            "provider_rows": _provider_freshness_rows_helper(
                snapshot,
                generated_at,
                evidence_package_context,
            ),
            "snapshot_replay_status": "Reproducible" if snapshot else "Not available",
            "source_hashes": dict(snapshot.source_hashes) if snapshot else {},
            "static_html_safety_status": "Controlled",
        },
        evidence_package=_evidence_package_rows_helper(
            has_attack_layer=bool(reviewed_attack_rows),
            has_governance=has_governance,
            evidence_package_context=evidence_package_context,
        ),
        recommendations=recommendations,
        attack_context={
            "mapped_techniques": reviewed_attack_rows,
            "mapping_source": sorted({row["source"] for row in reviewed_attack_rows}),
            "navigator_layer_status": "Included in Evidence ZIP"
            if reviewed_attack_rows
            else "Optional / not generated",
            "unmapped_handling_note": "Unmapped CVEs remain unmapped.",
            "no_llm_inference_note": "No LLM inferred mappings are used.",
        },
        technical_appendix={
            "note": (
                "Detailed finding rows, component versions, long remediation text, input "
                "provenance, full rationale and per finding actions remain in the Technical "
                "Markdown report, Analysis JSON, Findings CSV, SARIF and Evidence ZIP."
            )
        },
    )


def _business_service_view_rows(
    findings: list[MarkdownReportFinding],
    campaigns: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Business service view rows function."""
    services: dict[str, list[MarkdownReportFinding]] = {}
    for finding in findings:
        service = finding.business_service or "Infrastructure / Shared Services"
        services.setdefault(service, []).append(finding)
    campaign_rows = campaigns or _get_remediation_campaigns_helper(findings)
    rows = []
    for service, service_findings in sorted(services.items()):
        service_campaigns = [
            campaign
            for campaign in campaign_rows
            if (
                service in campaign["services"]
                or (not campaign["services"] and service == "Infrastructure / Shared Services")
            )
        ]
        open_campaigns = [
            campaign for campaign in service_campaigns if campaign["actionable_count"] > 0
        ]
        emergency_campaigns = [
            campaign for campaign in service_campaigns if _campaign_requires_emergency(campaign)
        ]
        governed_risk = _actionability_summary_helper(
            [finding for finding in service_findings if _has_governance_exception(finding)]
        )
        decision_needed = (
            "Emergency remediation"
            if emergency_campaigns
            else "Remediation scheduling"
            if open_campaigns
            else "Governance review"
            if governed_risk != "No findings"
            else "Monitor"
        )
        rows.append(
            {
                "service": service,
                "open_actionable_count": _count_findings(
                    service_findings,
                    _is_actionable_finding,
                ),
                "open_actionable_campaigns": len(open_campaigns),
                "emergency_campaigns": len(emergency_campaigns),
                "governed_risk": governed_risk,
                "environment": _counted_or_full_list(
                    [
                        _normalized_context_label(environment)
                        for environment in _unique_values(
                            service_findings,
                            lambda finding: finding.environment,
                        )
                    ],
                    noun="environment",
                ),
                "exposure": _counted_or_full_list(
                    [
                        _normalized_context_label(exposure)
                        for exposure in _unique_values(
                            service_findings,
                            lambda finding: finding.exposure,
                        )
                    ],
                    noun="exposure",
                ),
                "owner": _counted_or_full_list(
                    _unique_values(service_findings, lambda finding: finding.owner),
                    noun="owner",
                ),
                "decision_needed": decision_needed,
                "validation_evidence": "Clean re-import or retained governance evidence.",
            }
        )
    return rows


def _recommendation_view_rows(campaigns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Recommendation view rows function."""
    rows = []
    for campaign in campaigns:
        rows.append(
            {
                "campaign_name": campaign["campaign_name"],
                "scope": _campaign_scope_summary(campaign),
                "action": campaign["actions"][0]
                if campaign["actions"]
                else _campaign_decision_statement(campaign),
                "sla": campaign["slas"][0]
                if campaign["slas"]
                else (
                    "Emergency / 24h"
                    if _campaign_requires_emergency(campaign)
                    else "Standard patch cycle"
                ),
                "owners": campaign["owners"],
                "evidence_basis": _evidence_signal_summary(campaign),
            }
        )
    return rows


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
