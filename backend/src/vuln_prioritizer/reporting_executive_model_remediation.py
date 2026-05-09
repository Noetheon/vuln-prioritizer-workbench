"""Executive report remediation and governance model builders."""
# ruff: noqa: F401,F403,F405,I001,E501

from __future__ import annotations

from collections import Counter
from typing import Any

from vuln_prioritizer.reporting_executive_constants import (
    PRIORITY_ORDER,
    PRIORITY_TONES,
    SECTION_NAV,
)
from vuln_prioritizer.reporting_executive_utils import (
    _attack_label,
    _attr,
    _baseline_delta_label,
    _basename,
    _dict_value,
    _float_value,
    _format_report_timestamp,
    _int_value,
    _list_first,
    _list_values,
    _pct,
    _positive_int,
    _priority_label,
    _provider_value,
    _report_period,
    _score,
    _sha_preview,
    _short_provider_date,
    _text,
    _truncate,
)

# ruff: noqa: F403,F405

from vuln_prioritizer.reporting_executive_model_helpers import *


def _remediation_model(findings: list[dict[str, Any]]) -> dict[str, Any]:
    open_count = sum(1 for item in findings if _status(item) == "open")
    accepted = sum(1 for item in findings if _status(item) == "accepted")
    suppressed = sum(1 for item in findings if _status(item) == "suppressed")
    kev_open = sum(1 for item in findings if item.get("in_kev") and _status(item) == "open")
    review_due = sum(
        1 for item in findings if _text(item.get("waiver_status"), default="") == "review_due"
    )
    total = max(len(findings), 1)
    return {
        "total": total,
        "open": open_count,
        "accepted": accepted,
        "suppressed": suppressed,
        "kev_open": kev_open,
        "review_due": review_due,
        "median_ttr": "not supplied",
        "projected_risk_reduction": "not supplied",
        "priority_status": _priority_status_rows(findings),
        "owner_rows": _counter_rows(_owner_counter(findings), len(findings)),
        "service_rows": _counter_rows(_service_counter(findings), len(findings)),
        "owner_action_rows": _owner_action_rows(findings),
        "next_steps": _next_step_rows(findings, kev_open, review_due),
        "focus_cards": _focus_cards(findings),
    }


def _owner_action_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        owner = _finding_owner(finding)
        if owner == "not supplied":
            owner = "Unassigned"
        grouped.setdefault(owner, []).append(finding)
    rows = []
    for owner, items in grouped.items():
        due_dates = [
            _kev_due_date(item)
            for item in items
            if item.get("in_kev") and _kev_due_date(item) != "not available"
        ]
        review_due = sum(
            1 for item in items if _text(item.get("waiver_status"), default="") == "review_due"
        )
        rows.append(
            {
                "owner": owner,
                "open": sum(1 for item in items if _status(item) == "open"),
                "critical": sum(1 for item in items if _priority_label(item) == "Critical"),
                "kev": sum(1 for item in items if item.get("in_kev")),
                "epss": sum(1 for item in items if _float_value(item.get("epss")) >= 0.5),
                "due": min(due_dates) if due_dates else "not supplied",
                "status": (
                    "Needs owner"
                    if owner == "Unassigned"
                    else "Review due"
                    if review_due
                    else "Ready"
                ),
            }
        )
    return sorted(rows, key=lambda item: (-item["critical"], -item["kev"], item["owner"]))


def _next_step_rows(
    findings: list[dict[str, Any]],
    kev_open: int,
    review_due: int,
) -> list[dict[str, str]]:
    internet_facing = sum(
        1 for item in findings if _finding_exposure(item).lower() == "internet-facing"
    )
    epss = sum(1 for item in findings if _float_value(item.get("epss")) >= 0.5)
    mapped = sum(1 for item in findings if item.get("attack_mapped"))
    return [
        {
            "title": "Eliminate KEV vulnerabilities first",
            "body": f"{kev_open} open KEV-listed finding(s) require urgent owner action.",
            "tone": "critical",
        },
        {
            "title": "Secure internet-facing assets",
            "body": f"{internet_facing} finding(s) include internet-facing exposure context.",
            "tone": "info",
        },
        {
            "title": "Reduce EPSS-elevated findings",
            "body": f"{epss} finding(s) have EPSS >= 0.5 and should be reviewed early.",
            "tone": "success",
        },
        {
            "title": "Review governance exceptions",
            "body": f"{review_due} waiver review(s) are due in the supplied governance data.",
            "tone": "high",
        },
        {
            "title": "Use ATT&CK context for sequencing",
            "body": f"{mapped} finding(s) have supplied ATT&CK context for attack-path review.",
            "tone": "accent",
        },
    ]


def _focus_cards(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        label = _finding_service(finding)
        if label == "not supplied":
            label = _finding_asset(finding)
        if label == "not supplied":
            label = "Missing asset context"
        grouped.setdefault(label, []).append(finding)
    cards = []
    for label, items in sorted(grouped.items(), key=lambda entry: (-len(entry[1]), entry[0]))[:3]:
        actions = []
        for finding in sorted(items, key=_finding_sort_key)[:3]:
            action = _finding_decision_statement(finding)
            actions.append(
                f"{_text(finding.get('cve_id'), default='CVE')}: {_truncate(action, 118)}"
            )
        tone = "critical" if any(item.get("in_kev") for item in items) else "info"
        cards.append(
            {
                "label": label,
                "body": f"{len(items)} finding(s) require remediation or governance review.",
                "actions": actions,
                "tone": tone,
            }
        )
    return cards


def _governance_model(metadata: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    suppressed = _int_value(metadata.get("suppressed_by_vex")) or sum(
        1 for item in findings if item.get("suppressed_by_vex")
    )
    under_investigation = _int_value(metadata.get("under_investigation_count")) or sum(
        1 for item in findings if item.get("under_investigation")
    )
    waived = _int_value(metadata.get("waived_count")) or sum(
        1 for item in findings if item.get("waived")
    )
    review_due = _int_value(metadata.get("waiver_review_due_count")) or sum(
        1 for item in findings if _text(item.get("waiver_status"), default="") == "review_due"
    )
    expired = _int_value(metadata.get("expired_waiver_count")) or sum(
        1 for item in findings if _text(item.get("waiver_status"), default="") == "expired"
    )
    return {
        "rows": [
            {
                "label": "Suppressed by VEX",
                "value": suppressed,
                "detail": "Not exploitable or otherwise suppressed by supplied VEX evidence.",
                "tone": "low",
            },
            {
                "label": "Under investigation",
                "value": under_investigation,
                "detail": "VEX or finding state still needs validation.",
                "tone": "medium",
            },
            {
                "label": "Waived findings",
                "value": waived,
                "detail": "Accepted risk remains visible for audit review.",
                "tone": "low",
            },
            {
                "label": "Waiver review due",
                "value": review_due,
                "detail": "Requires owner review before the next governance cycle.",
                "tone": "high",
            },
            {
                "label": "Expired waivers",
                "value": expired,
                "detail": "Accepted risk is no longer current.",
                "tone": "critical",
            },
        ],
        "waiver_file": _text(metadata.get("waiver_file"), default="not supplied"),
    }


def _missing_context_model(
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    attack_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    total = max(len(findings), 1)
    missing_cvss = sum(1 for item in findings if _float_value(item.get("cvss_base_score")) < 0)
    missing_epss = sum(1 for item in findings if _float_value(item.get("epss")) < 0)
    missing_attack = sum(1 for item in findings if not item.get("attack_mapped"))
    missing_asset = sum(1 for item in findings if _finding_asset(item) == "not supplied")
    missing_owner = sum(
        1
        for item in findings
        if _finding_owner(item) == "not supplied" and _finding_service(item) == "not supplied"
    )
    warnings = len([item for item in metadata.get("warnings", []) if item])
    if (
        not bool(metadata.get("attack_enabled"))
        and _int_value(attack_summary.get("mapped_cves")) == 0
    ):
        attack_detail = "ATT&CK source not supplied for this run."
    else:
        attack_detail = "No supplied ATT&CK mapping for these findings."
    return [
        {
            "label": "Missing CVSS",
            "value": missing_cvss,
            "pct": _pct(missing_cvss, total),
            "detail": "Provider severity was not available.",
            "tone": "critical",
        },
        {
            "label": "Missing EPSS",
            "value": missing_epss,
            "pct": _pct(missing_epss, total),
            "detail": "Exploit likelihood was not available.",
            "tone": "high",
        },
        {
            "label": "Without ATT&CK context",
            "value": missing_attack,
            "pct": _pct(missing_attack, total),
            "detail": attack_detail,
            "tone": "accent",
        },
        {
            "label": "Without asset context",
            "value": missing_asset,
            "pct": _pct(missing_asset, total),
            "detail": "No matching asset ID or occurrence metadata was supplied.",
            "tone": "medium",
        },
        {
            "label": "Without owner or service",
            "value": missing_owner,
            "pct": _pct(missing_owner, total),
            "detail": "Routing needs asset owner or business service data.",
            "tone": "low",
        },
        {
            "label": "Input warnings",
            "value": warnings,
            "pct": 100 if warnings else 0,
            "detail": "Warnings recorded during import or enrichment.",
            "tone": "high" if warnings else "low",
        },
    ]


def _priority_status_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for priority in PRIORITY_ORDER:
        priority_findings = [item for item in findings if _priority_label(item) == priority]
        rows.append(
            {
                "label": priority,
                "tone": PRIORITY_TONES[priority],
                "open": sum(1 for item in priority_findings if _status(item) == "open"),
                "accepted": sum(1 for item in priority_findings if _status(item) == "accepted"),
                "suppressed": sum(1 for item in priority_findings if _status(item) == "suppressed"),
                "total": len(priority_findings),
            }
        )
    return rows


__all__ = [
    "_focus_cards",
    "_governance_model",
    "_missing_context_model",
    "_next_step_rows",
    "_owner_action_rows",
    "_priority_status_rows",
    "_remediation_model",
]
