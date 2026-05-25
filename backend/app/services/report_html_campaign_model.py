"""Remediation campaign grouping model helpers for executive HTML reports."""

from __future__ import annotations

import re
from typing import Any

from app.services.report_formatting import format_number as _format_number
from app.services.report_html_attack_context import (
    _reviewed_attack_mapping_rows_for_findings,
    _reviewed_attack_technique_ids_for_findings,
)
from app.services.report_html_common import (
    _actionability_counts_helper,
    _actionability_summary_helper,
    _actionable_findings,
    _count_findings,
    _counted_or_full_list,
    _finding_sort_key,
    _fixed_finding_count,
    _has_governance_exception,
    _is_actionable_finding,
    _joined_context,
    _normalized_context_label,
    _occurrence_count,
    _pluralize,
    _short_list,
    _unique_values,
)
from app.services.report_models import MarkdownReportFinding
from app.services.report_renderer_common import _priority_label

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


__all__ = [
    "CVE_ALIASES",
    "_campaign_ranking_rationale",
    "_campaign_scope_summary",
    "_evidence_signal_summary",
    "_campaign_requires_emergency",
    "_campaign_decision_statement",
    "_first_available_owner",
    "_normalized_campaign_action",
    "_component_family",
    "_campaign_base_key",
    "_campaign_group_key",
    "_priority_class_for_campaign",
    "_campaign_sort_key",
    "_get_remediation_campaigns_helper",
    "_campaigns_label",
    "_campaign_evidence_label",
    "_business_service_view_rows",
    "_recommendation_view_rows",
]
