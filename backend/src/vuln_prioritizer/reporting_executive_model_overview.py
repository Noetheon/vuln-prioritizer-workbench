"""Executive report overview model builders."""
# ruff: noqa: F401,F403,F405,I001,E501

from __future__ import annotations

from typing import Any

from vuln_prioritizer.reporting_executive_constants import (
    PRIORITY_ORDER,
    PRIORITY_TONES,
)
from vuln_prioritizer.reporting_executive_utils import (
    _float_value,
    _int_value,
    _pct,
    _priority_label,
    _text,
)

# ruff: noqa: F403,F405

from vuln_prioritizer.reporting_executive_model_helpers import *


def _overview_metrics(
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    attack: dict[str, Any],
    remediation: dict[str, Any],
) -> list[dict[str, str]]:
    assets = len(_asset_counter(findings))
    asset_value = f"{assets:,}" if assets else "not supplied"
    asset_detail = "Asset context supplied" if assets else "Asset context not supplied"
    epss_elevated = sum(1 for item in findings if _float_value(item.get("epss")) >= 0.5)
    return [
        {"label": "Assets assessed", "value": asset_value, "detail": asset_detail, "tone": "info"},
        _kpi("Open findings", remediation["open"], "Actionable after VEX/waiver state", "info"),
        _kpi("KEV findings", _int_value(metadata.get("kev_hits")), "Known exploited", "critical"),
        _kpi("EPSS elevated", epss_elevated, "EPSS >= 0.5", "success"),
        _kpi("ATT&CK mapped", attack["mapped_cves"], "Supplied threat context", "accent"),
    ]


def _provider_cards(source_coverage: list[dict[str, Any]]) -> list[dict[str, Any]]:
    descriptions = {
        "NVD": "Standard vulnerability intelligence including CVSS, CPE, CWE, and references.",
        "FIRST EPSS": (
            "Predictive exploitation likelihood. Elevated EPSS highlights near-term risk."
        ),
        "CISA KEV": "Known Exploited Vulnerabilities observed being exploited in the wild.",
        "MITRE ATT&CK": "Maps findings to adversary techniques when source mappings are supplied.",
        "Asset context": (
            "Business routing, exposure, criticality, owner, service, and environment."
        ),
        "VEX": "Governance evidence for suppressed or under-investigation findings.",
    }
    tones = {
        "NVD": "info",
        "FIRST EPSS": "success",
        "CISA KEV": "critical",
        "MITRE ATT&CK": "accent",
        "Asset context": "high",
        "VEX": "low",
    }
    return [
        item
        | {
            "description": descriptions.get(item["label"], "Source coverage for this analysis."),
            "tone": tones.get(item["label"], "info"),
        }
        for item in source_coverage
    ]


def _severity_signal_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for label in PRIORITY_ORDER:
        scoped = [item for item in findings if _priority_label(item) == label]
        rows.append(
            {
                "label": label,
                "tone": PRIORITY_TONES[label],
                "total": len(scoped),
                "segments": [
                    {
                        "label": "NVD severity",
                        "count": sum(
                            1 for item in scoped if _float_value(item.get("cvss_base_score")) >= 0
                        ),
                        "tone": "info",
                    },
                    {
                        "label": "EPSS elevated",
                        "count": sum(1 for item in scoped if _float_value(item.get("epss")) >= 0.5),
                        "tone": "success",
                    },
                    {
                        "label": "KEV flagged",
                        "count": sum(1 for item in scoped if item.get("in_kev")),
                        "tone": "critical",
                    },
                    {
                        "label": "ATT&CK mapped",
                        "count": sum(1 for item in scoped if item.get("attack_mapped")),
                        "tone": "accent",
                    },
                ],
            }
        )
    return rows


def _asset_risk_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for finding in findings:
        label = _finding_service(finding)
        if label == "not supplied":
            label = _finding_asset(finding)
        if label == "not supplied":
            label = "Missing asset context"
        row = grouped.setdefault(label, {"label": label, "count": 0, "score": 0.0})
        row["count"] += 1
        row["score"] += _finding_signal_score(finding)
    max_score = max((item["score"] for item in grouped.values()), default=0.0)
    rows = []
    for item in grouped.values():
        rows.append(
            {
                "label": item["label"],
                "count": round(item["score"], 1),
                "findings": item["count"],
                "pct": _pct(round(item["score"] * 10), round(max_score * 10) or 1),
            }
        )
    return sorted(rows, key=lambda item: (-float(item["count"]), item["label"]))[:6]


def _priority_kpis(
    findings: list[dict[str, Any]],
    sorted_findings: list[dict[str, Any]],
    attack: dict[str, Any],
) -> list[dict[str, str]]:
    top_20 = sorted_findings[:20]
    internet_facing = sum(
        1 for item in findings if _finding_exposure(item).lower() == "internet-facing"
    )
    critical_assets = {
        _finding_asset(item)
        for item in findings
        if _finding_criticality(item).lower() in {"critical", "high"}
        and _finding_asset(item) != "not supplied"
    }
    return [
        _kpi(
            "Critical queue",
            sum(1 for item in findings if _priority_label(item) == "Critical"),
            "Highest urgency findings",
            "critical",
        ),
        _kpi(
            "KEV in top 20",
            sum(1 for item in top_20 if item.get("in_kev")),
            "Known exploited priority items",
            "critical",
        ),
        _kpi(
            "EPSS > 0.7",
            sum(1 for item in findings if _float_value(item.get("epss")) > 0.7),
            "High exploit likelihood",
            "success",
        ),
        _kpi(
            "Internet-facing assets",
            internet_facing,
            "Exposure supplied by asset context",
            "info",
        ),
        _kpi(
            "ATT&CK mapped findings",
            attack["mapped_cves"],
            "Adversary context available",
            "accent",
        ),
        _kpi(
            "Critical systems affected",
            len(critical_assets),
            "From supplied asset criticality",
            "high",
        ),
    ]


def _priority_interpretation(
    findings: list[dict[str, Any]],
    attack: dict[str, Any],
) -> list[dict[str, str]]:
    kev = sum(1 for item in findings if item.get("in_kev"))
    epss = sum(1 for item in findings if _float_value(item.get("epss")) >= 0.5)
    exposed = sum(1 for item in findings if _finding_exposure(item) != "not supplied")
    return [
        {
            "title": "KEV and EPSS move work forward",
            "body": (
                f"{kev} finding(s) are KEV-listed and {epss} finding(s) have EPSS >= 0.5. "
                "These signals can outweigh a CVSS-only ordering."
            ),
        },
        {
            "title": "Exposure and ATT&CK add context",
            "body": (
                f"{exposed} finding(s) include supplied exposure context and "
                f"{attack['mapped_cves']} finding(s) include supplied ATT&CK mappings."
            ),
        },
    ]


def _kpis(
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    counts_by_priority: dict[str, int],
    attack_summary: dict[str, Any],
) -> list[dict[str, str]]:
    epss_elevated = sum(1 for item in findings if _float_value(item.get("epss")) >= 0.5)
    attack_mapped = _int_value(attack_summary.get("mapped_cves"))
    if attack_mapped == 0:
        attack_mapped = sum(1 for item in findings if bool(item.get("attack_mapped")))
    return [
        _kpi("Findings", len(findings), "Imported and visible", "info"),
        _kpi("Critical", counts_by_priority.get("Critical", 0), "Highest priority", "critical"),
        _kpi("High", counts_by_priority.get("High", 0), "Elevated queue", "high"),
        _kpi("KEV", _int_value(metadata.get("kev_hits")), "Known exploited", "critical"),
        _kpi("EPSS ≥ 0.5", epss_elevated, "Elevated likelihood", "success"),
        _kpi("ATT&CK mapped", attack_mapped, "Context available", "accent"),
        _kpi("VEX suppressed", _int_value(metadata.get("suppressed_by_vex")), "Governed", "low"),
        _kpi(
            "Review due",
            _int_value(metadata.get("waiver_review_due_count")),
            "Waiver pressure",
            "high",
        ),
    ]


def _priority_distribution(
    counts_by_priority: dict[str, int],
    total_findings: int,
) -> list[dict[str, Any]]:
    total = max(total_findings, sum(counts_by_priority.values()), 1)
    return [
        {
            "label": label,
            "count": counts_by_priority.get(label, 0),
            "pct": _pct(counts_by_priority.get(label, 0), total),
            "tone": PRIORITY_TONES[label],
        }
        for label in PRIORITY_ORDER
    ]


def _source_coverage(
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    attack_summary: dict[str, Any],
    valid_input: int,
) -> list[dict[str, Any]]:
    finding_total = max(len(findings), 1)
    asset_hits = sum(1 for item in findings if _finding_asset(item) != "not supplied")
    vex_hits = sum(1 for item in findings if _vex_status(item) != "not supplied")
    attack_hits = _int_value(metadata.get("attack_hits")) or _int_value(
        attack_summary.get("mapped_cves")
    )
    rows = [
        ("NVD", _int_value(metadata.get("nvd_hits")), valid_input),
        ("FIRST EPSS", _int_value(metadata.get("epss_hits")), valid_input),
        ("CISA KEV", _int_value(metadata.get("kev_hits")), valid_input),
        ("MITRE ATT&CK", attack_hits, valid_input),
        ("Asset context", asset_hits, finding_total),
        ("VEX", vex_hits, finding_total),
    ]
    return [
        {"label": label, "count": count, "total": total, "pct": _pct(count, max(total, 1))}
        for label, count, total in rows
    ]


def _risk_driver_model(
    findings: list[dict[str, Any]],
    attack_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    mapped = _int_value(attack_summary.get("mapped_cves"))
    if mapped == 0:
        mapped = sum(1 for item in findings if bool(item.get("attack_mapped")))
    drivers: list[dict[str, Any]] = [
        {
            "label": "Severity",
            "count": sum(
                1 for item in findings if _float_value(item.get("cvss_base_score")) >= 7.0
            ),
            "tone": "critical",
        },
        {
            "label": "Exploit likelihood",
            "count": sum(1 for item in findings if _float_value(item.get("epss")) >= 0.5),
            "tone": "info",
        },
        {
            "label": "Known exploitation",
            "count": sum(1 for item in findings if item.get("in_kev")),
            "tone": "critical",
        },
        {
            "label": "Exposure",
            "count": sum(1 for item in findings if _finding_exposure(item) != "not supplied"),
            "tone": "high",
        },
        {"label": "ATT&CK context", "count": mapped, "tone": "accent"},
    ]
    total = max(sum(item["count"] for item in drivers), 1)
    return [item | {"pct": _pct(item["count"], total)} for item in drivers]


def _business_exposure_model(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    grouped: dict[str, dict[str, Any]] = {}
    for finding in findings:
        label = _finding_service(finding)
        if label == "not supplied":
            label = _finding_asset(finding)
        if label == "not supplied":
            continue
        row = grouped.setdefault(
            label,
            {
                "label": label,
                "count": 0,
                "criticality": "not supplied",
                "exposure": "not supplied",
            },
        )
        row["count"] += 1
        criticality = _finding_criticality(finding)
        exposure = _finding_exposure(finding)
        if _criticality_rank(criticality) > _criticality_rank(row["criticality"]):
            row["criticality"] = criticality
        if exposure != "not supplied":
            row["exposure"] = exposure
    total = max(len(findings), 1)
    for row in grouped.values():
        tone = "critical" if row["exposure"] == "internet-facing" else "success"
        if row["criticality"] in {"critical", "high"}:
            tone = "critical" if row["criticality"] == "critical" else "high"
        rows.append(row | {"pct": _pct(row["count"], total), "tone": tone})
    return sorted(rows, key=lambda item: (-item["count"], item["label"]))[:6]


def _scatter_points(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    points: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        cvss = _float_value(finding.get("cvss_base_score"))
        epss = _float_value(finding.get("epss"))
        if cvss < 0 or epss < 0:
            continue
        base_x = 6.0 + (cvss / 10.0) * 388.0
        base_y = 214.0 - epss * 208.0
        jitter_x = ((index % 3) - 1) * 12.0
        jitter_y = (((index // 3) % 3) - 1) * 10.0
        points.append(
            {
                "cve": _text(finding.get("cve_id"), default="CVE"),
                "cvss": cvss,
                "epss": epss,
                "x": max(8.0, min(392.0, base_x + jitter_x)),
                "y": max(8.0, min(212.0, base_y + jitter_y)),
                "tone": PRIORITY_TONES.get(_priority_label(finding), "low"),
                "kev": bool(finding.get("in_kev")),
            }
        )
    return points


__all__ = [
    "_asset_risk_rows",
    "_business_exposure_model",
    "_kpis",
    "_overview_metrics",
    "_priority_distribution",
    "_priority_interpretation",
    "_priority_kpis",
    "_provider_cards",
    "_risk_driver_model",
    "_scatter_points",
    "_severity_signal_rows",
    "_source_coverage",
]
