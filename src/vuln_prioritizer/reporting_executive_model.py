"""Executive report view model construction."""

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


def build_executive_report_model(
    report_payload: dict[str, Any],
    *,
    project_name: str | None = None,
    project_id: str | None = None,
    run_id: str | None = None,
    input_filename: str | None = None,
    reports: list[Any] | None = None,
    evidence_bundles: list[Any] | None = None,
    provider_snapshot: Any | None = None,
) -> dict[str, Any]:
    """Build a deterministic executive report view model from an analysis payload."""
    metadata = _dict_value(report_payload.get("metadata"))
    attack_summary = _dict_value(report_payload.get("attack_summary"))
    findings = [item for item in report_payload.get("findings", []) if isinstance(item, dict)]
    counts_by_priority = _priority_counts(metadata, findings)
    sorted_findings = sorted(findings, key=_finding_sort_key)
    valid_input = _positive_int(metadata.get("valid_input")) or len(findings)
    total_findings = _positive_int(metadata.get("findings_count")) or len(findings)
    title = project_name or _basename(metadata.get("input_path")) or "Vuln Prioritizer"
    generated_at = _text(metadata.get("generated_at"), default="not available")
    report_period = _report_period(metadata, generated_at)
    display_input = input_filename or _basename(metadata.get("input_path")) or "not available"
    source_coverage = _source_coverage(metadata, findings, attack_summary, valid_input)
    risk_drivers = _risk_driver_model(findings, attack_summary)
    business_exposure = _business_exposure_model(findings)
    attack = _attack_model(metadata, attack_summary, findings)
    remediation = _remediation_model(findings)
    evidence = _evidence_model(
        metadata,
        findings,
        reports or [],
        evidence_bundles or [],
        provider_snapshot,
    )

    return {
        "title": title,
        "subtitle": "Executive security overview",
        "run_id": run_id,
        "input_filename": display_input,
        "generated_at": generated_at,
        "generated_at_display": _format_report_timestamp(generated_at),
        "report_period": report_period,
        "report_period_display": _format_report_timestamp(report_period),
        "nav": [{"id": key, "label": label} for key, label in SECTION_NAV],
        "workspace_nav": _workspace_nav(project_id, run_id, title),
        "summary": _executive_summary(metadata, findings, counts_by_priority, attack_summary),
        "kpis": _kpis(metadata, findings, counts_by_priority, attack_summary),
        "overview_metrics": _overview_metrics(metadata, findings, attack, remediation),
        "priority_distribution": _priority_distribution(counts_by_priority, total_findings),
        "risk_drivers": risk_drivers,
        "source_coverage": source_coverage,
        "provider_cards": _provider_cards(source_coverage),
        "severity_signal_rows": _severity_signal_rows(findings),
        "scatter_points": _scatter_points(sorted_findings[:80]),
        "business_exposure": business_exposure,
        "top_services": _counter_rows(_service_counter(findings), total_findings),
        "top_owners": _counter_rows(_owner_counter(findings), total_findings),
        "top_assets": _counter_rows(_asset_counter(findings), total_findings),
        "asset_risk_rows": _asset_risk_rows(findings),
        "priority_kpis": _priority_kpis(findings, sorted_findings, attack),
        "priority_interpretation": _priority_interpretation(findings, attack),
        "priority_findings": [_finding_row(finding) for finding in sorted_findings[:15]],
        "finding_dossiers": [_finding_dossier_model(finding) for finding in sorted_findings[:8]],
        "attack": attack,
        "remediation": remediation,
        "governance": _governance_model(metadata, findings),
        "missing_context": _missing_context_model(metadata, findings, attack_summary),
        "evidence": evidence,
        "input_sources": _input_sources_model(metadata, findings),
        "provider_transparency": _provider_transparency_model(
            metadata, findings, provider_snapshot
        ),
        "methodology": _methodology_model(metadata),
        "compatibility_labels": [
            "How to Read This Report",
            "Key Signals",
            "Coverage & Context",
            "Decision & Action",
            "ATT&CK & Governance",
            "Priority Queue",
            "Finding Dossiers",
            "Provider transparency",
            "Action plan",
            "CVSS-only baseline delta",
            "Provider evidence",
            "Suppressed by VEX",
            "Known exploited",
            "Critical / KEV",
            "Known exploited (KEV)",
            "vuln-prioritizer analyze --attack-source ctid-json",
            "vuln-prioritizer analyze --waiver-file waivers.yml",
        ],
    }


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


def _kpi_value(model: dict[str, Any], label: str) -> str:
    for item in model["kpis"]:
        if item["label"] == label:
            return str(item["value"])
    return "0"


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


def _attack_model(
    metadata: dict[str, Any],
    attack_summary: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    technique_counter = _distribution_counter(attack_summary.get("technique_distribution"))
    tactic_counter = _distribution_counter(attack_summary.get("tactic_distribution"))
    if not technique_counter:
        for finding in findings:
            technique_counter.update(str(item) for item in finding.get("attack_techniques", []))
    if not tactic_counter:
        for finding in findings:
            tactic_counter.update(str(item) for item in finding.get("attack_tactics", []))
    mapped = _int_value(attack_summary.get("mapped_cves"))
    if mapped == 0:
        mapped = sum(1 for item in findings if bool(item.get("attack_mapped")))
    unmapped = _int_value(attack_summary.get("unmapped_cves"))
    if unmapped == 0 and findings:
        unmapped = max(len(findings) - mapped, 0)
    enabled = bool(metadata.get("attack_enabled"))
    asset_matrix = _attack_asset_matrix_model(findings, tactic_counter)
    return {
        "enabled": enabled,
        "mapped_cves": mapped,
        "unmapped_cves": unmapped,
        "technique_count": len(technique_counter),
        "tactic_count": len(tactic_counter),
        "top_techniques": _distribution_model(technique_counter),
        "top_tactics": _distribution_model(tactic_counter),
        "related_counts": [
            {
                "label": "Initial Access related",
                "value": _related_tactic_count(tactic_counter, "initial access"),
            },
            {
                "label": "Privilege Escalation related",
                "value": _related_tactic_count(tactic_counter, "privilege escalation"),
            },
            {
                "label": "Execution related",
                "value": _related_tactic_count(tactic_counter, "execution"),
            },
        ],
        "asset_matrix": asset_matrix,
        "top_mapped_findings": _attack_top_mapped_findings(findings),
        "technique_strip": _distribution_model(technique_counter, limit=5),
        "finding_notes": _attack_finding_notes(findings),
        "source": _text(metadata.get("attack_source"), default="not supplied"),
        "version": _text(metadata.get("attack_version"), default="not available"),
        "mapping_hash": _text(metadata.get("attack_mapping_file_sha256"), default="not available"),
        "note": (
            "ATT&CK context is enabled and shown as adversary behavior context only."
            if enabled
            else "ATT&CK context was not supplied for this run."
        ),
    }


def _related_tactic_count(counter: Counter[str], label: str) -> int:
    target = label.replace("-", " ").lower()
    return sum(count for key, count in counter.items() if key.replace("-", " ").lower() == target)


def _attack_asset_matrix_model(
    findings: list[dict[str, Any]],
    tactic_counter: Counter[str],
) -> dict[str, Any]:
    mapped_findings = [item for item in findings if item.get("attack_mapped")]
    groups: Counter[str] = Counter()
    tactic_labels = [label for label, _ in tactic_counter.most_common(8)]
    cell_counts: Counter[tuple[str, str]] = Counter()
    for finding in mapped_findings:
        group = _finding_service(finding)
        if group == "not supplied":
            group = _finding_asset(finding)
        if group == "not supplied":
            continue
        groups[group] += 1
        for tactic in _list_values(finding.get("attack_tactics"), limit=20):
            cell_counts[(tactic, group)] += 1
    columns = [label for label, _ in groups.most_common(4)]
    rows = []
    for tactic in tactic_labels:
        rows.append(
            {
                "label": tactic,
                "cells": [
                    {
                        "group": group,
                        "count": cell_counts[(tactic, group)],
                    }
                    for group in columns
                ],
            }
        )
    return {"columns": columns, "rows": rows}


def _attack_top_mapped_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for finding in sorted(findings, key=_finding_sort_key):
        if not finding.get("attack_mapped"):
            continue
        techniques = _list_values(finding.get("attack_techniques"), limit=1)
        tactics = _list_values(finding.get("attack_tactics"), limit=1)
        rows.append(
            {
                "cve": _text(finding.get("cve_id"), default="CVE"),
                "technique": techniques[0] if techniques else "not supplied",
                "tactic": tactics[0] if tactics else "not supplied",
                "route": _route_label(finding),
                "priority": _priority_label(finding),
                "tone": PRIORITY_TONES.get(_priority_label(finding), "low"),
            }
        )
        if len(rows) >= 6:
            break
    return rows


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
            action = _text(finding.get("recommended_action"), default="Review finding.")
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


def _evidence_model(
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    reports: list[Any],
    evidence_bundles: list[Any],
    provider_snapshot: Any | None,
) -> dict[str, Any]:
    freshness = [
        {"label": "Provider snapshot", "value": _text(metadata.get("provider_snapshot_file"))},
        {
            "label": "Locked provider data",
            "value": "yes" if metadata.get("locked_provider_data") else "no",
        },
        {"label": "NVD last sync", "value": _provider_value(provider_snapshot, "nvd_last_sync")},
        {"label": "EPSS date", "value": _provider_value(provider_snapshot, "epss_date")},
        {
            "label": "KEV catalog",
            "value": _provider_value(provider_snapshot, "kev_catalog_version"),
        },
    ]
    warnings = [str(item) for item in metadata.get("warnings", []) if item]
    provider_notes = _provider_evidence_notes(findings)
    source_formats = sorted(
        {
            str(source)
            for finding in findings
            for source in _dict_value(finding.get("provenance")).get("source_formats", [])
            if source
        }
    )
    quality_notes = warnings + [
        f"Duplicate CVEs collapsed: {_int_value(metadata.get('duplicate_cve_count'))}",
        f"Asset-context conflicts: {_int_value(metadata.get('asset_match_conflict_count'))}",
        f"VEX conflicts: {_int_value(metadata.get('vex_conflict_count'))}",
    ]
    if source_formats:
        quality_notes.append("Source formats: " + ", ".join(source_formats))
    quality_notes.extend(provider_notes)
    artifacts = _artifact_model(reports, evidence_bundles)
    return {
        "freshness": freshness,
        "quality_notes": quality_notes,
        "artifacts": artifacts,
        "provider_rows": _provider_freshness_rows(metadata, provider_snapshot),
        "quality_rows": _quality_rows(metadata, findings),
        "mapping_confidence": _mapping_confidence_model(findings),
        "bundle_contents": _bundle_contents_model(artifacts),
    }


def _provider_freshness_rows(
    metadata: dict[str, Any],
    provider_snapshot: Any | None,
) -> list[dict[str, str]]:
    locked = "locked" if metadata.get("locked_provider_data") else "not locked"
    return [
        {
            "provider": "NVD",
            "last_sync": _short_provider_date(_provider_value(provider_snapshot, "nvd_last_sync")),
            "source_status": locked,
            "freshness": "snapshot locked"
            if metadata.get("locked_provider_data")
            else "live source",
        },
        {
            "provider": "FIRST EPSS",
            "last_sync": _short_provider_date(_provider_value(provider_snapshot, "epss_date")),
            "source_status": locked,
            "freshness": "snapshot locked"
            if metadata.get("locked_provider_data")
            else "live source",
        },
        {
            "provider": "CISA KEV",
            "last_sync": _short_provider_date(
                _provider_value(provider_snapshot, "kev_catalog_version")
            ),
            "source_status": locked,
            "freshness": "snapshot locked"
            if metadata.get("locked_provider_data")
            else "live source",
        },
        {
            "provider": "MITRE ATT&CK",
            "last_sync": "ATT&CK " + _text(metadata.get("attack_version"), default="not supplied"),
            "source_status": "enabled" if metadata.get("attack_enabled") else "not supplied",
            "freshness": _text(metadata.get("attack_domain"), default="not supplied"),
        },
    ]


def _quality_rows(metadata: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    total = max(len(findings), 1)
    return [
        {
            "label": "Missing CVSS",
            "value": sum(1 for item in findings if _float_value(item.get("cvss_base_score")) < 0),
            "pct": _pct(
                sum(1 for item in findings if _float_value(item.get("cvss_base_score")) < 0),
                total,
            ),
        },
        {
            "label": "Missing EPSS",
            "value": sum(1 for item in findings if _float_value(item.get("epss")) < 0),
            "pct": _pct(sum(1 for item in findings if _float_value(item.get("epss")) < 0), total),
        },
        {
            "label": "Findings without ATT&CK",
            "value": sum(1 for item in findings if not item.get("attack_mapped")),
            "pct": _pct(sum(1 for item in findings if not item.get("attack_mapped")), total),
        },
        {
            "label": "Suppressed by VEX",
            "value": _int_value(metadata.get("suppressed_by_vex"))
            or sum(1 for item in findings if item.get("suppressed_by_vex")),
            "pct": _pct(
                _int_value(metadata.get("suppressed_by_vex"))
                or sum(1 for item in findings if item.get("suppressed_by_vex")),
                total,
            ),
        },
        {
            "label": "Active waivers",
            "value": _int_value(metadata.get("waived_count"))
            or sum(1 for item in findings if item.get("waived")),
            "pct": _pct(
                _int_value(metadata.get("waived_count"))
                or sum(1 for item in findings if item.get("waived")),
                total,
            ),
        },
        {
            "label": "Input warnings",
            "value": len([item for item in metadata.get("warnings", []) if item]),
            "pct": 100 if metadata.get("warnings") else 0,
        },
    ]


def _mapping_confidence_model(findings: list[dict[str, Any]]) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    for finding in findings:
        mappings = finding.get("attack_mappings")
        if not isinstance(mappings, list):
            continue
        for mapping in mappings:
            if not isinstance(mapping, dict):
                continue
            confidence = _text(mapping.get("confidence"), default="")
            if confidence:
                counts[confidence.title()] += 1
    if not counts:
        return {
            "available": False,
            "total": sum(1 for item in findings if item.get("attack_mapped")),
            "rows": [
                {
                    "label": "Confidence scoring",
                    "count": "not supplied",
                    "detail": "The supplied ATT&CK mappings did not include confidence buckets.",
                }
            ],
        }
    total = sum(counts.values())
    return {
        "available": True,
        "total": total,
        "rows": [
            {
                "label": label,
                "count": count,
                "pct": _pct(count, total),
                "detail": f"{count} reviewed mapping(s)",
            }
            for label, count in counts.most_common()
        ],
    }


def _bundle_contents_model(artifacts: list[dict[str, str]]) -> dict[str, Any]:
    if not artifacts:
        return {
            "generated": False,
            "items": [
                {
                    "name": "analysis.json",
                    "detail": "not generated for this run",
                    "size": "not supplied",
                },
                {
                    "name": "summary.md",
                    "detail": "not generated for this run",
                    "size": "not supplied",
                },
                {
                    "name": "provider-snapshot.json",
                    "detail": "not generated for this run",
                    "size": "not supplied",
                },
                {
                    "name": "sha256-manifest.txt",
                    "detail": "not generated for this run",
                    "size": "not supplied",
                },
            ],
        }
    return {
        "generated": True,
        "items": [
            {"name": item["label"], "detail": item["detail"], "size": "downloadable"}
            for item in artifacts
        ],
    }


def _input_sources_model(
    metadata: dict[str, Any], findings: list[dict[str, Any]]
) -> list[dict[str, str]]:
    sources = metadata.get("input_sources")
    rows: list[dict[str, str]] = []
    if isinstance(sources, list):
        for source in sources:
            if not isinstance(source, dict):
                continue
            rows.append(
                {
                    "input": _basename(source.get("input_path") or source.get("path")),
                    "format": _text(source.get("input_format") or source.get("format")),
                    "rows": _text(source.get("total_rows"), default="not supplied"),
                    "occurrences": _text(source.get("occurrence_count"), default="not supplied"),
                    "cves": _text(source.get("unique_cves"), default="not supplied"),
                }
            )
    if not rows:
        rows.append(
            {
                "input": _basename(metadata.get("input_path")) or "not supplied",
                "format": _text(metadata.get("input_format")),
                "rows": _text(metadata.get("total_input"), default="not supplied"),
                "occurrences": str(sum(len(_occurrences(item)) for item in findings)),
                "cves": _text(metadata.get("valid_input"), default=str(len(findings))),
            }
        )
    return rows


def _provider_transparency_model(
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    provider_snapshot: Any | None,
) -> dict[str, Any]:
    diagnostics = _dict_value(metadata.get("nvd_diagnostics"))
    sources = metadata.get("provider_snapshot_sources") or metadata.get("data_sources") or []
    source_text = (
        ", ".join(str(item) for item in sources if item) if isinstance(sources, list) else ""
    )
    nvd_diag = []
    for label, key in (
        ("Requested", "requested"),
        ("Cache hits", "cache_hits"),
        ("Network fetches", "network_fetches"),
        ("Failures", "failures"),
        ("Content hits", "content_hits"),
    ):
        if key in diagnostics:
            nvd_diag.append({"label": label, "value": str(_int_value(diagnostics.get(key)))})
    return {
        "facts": [
            {
                "label": "Selected sources",
                "value": source_text or "not supplied",
            },
            {
                "label": "Provider snapshot",
                "value": _text(metadata.get("provider_snapshot_file")),
            },
            {
                "label": "Locked provider data",
                "value": "yes" if metadata.get("locked_provider_data") else "no",
            },
            {
                "label": "NVD last sync",
                "value": _provider_value(provider_snapshot, "nvd_last_sync"),
            },
            {
                "label": "EPSS date",
                "value": _provider_value(provider_snapshot, "epss_date"),
            },
            {
                "label": "KEV catalog",
                "value": _provider_value(provider_snapshot, "kev_catalog_version"),
            },
        ],
        "diagnostics": nvd_diag,
        "notes": _provider_evidence_notes(findings),
        "commands": [
            "vuln-prioritizer analyze --attack-source ctid-json",
            "vuln-prioritizer analyze --waiver-file waivers.yml",
        ],
    }


def _methodology_model(metadata: dict[str, Any]) -> list[dict[str, str]]:
    policy = _dict_value(metadata.get("priority_policy"))
    profile = _text(metadata.get("policy_profile"), default="default")
    high_epss = _text(policy.get("high_epss_threshold"), default="0.50")
    critical_cvss = _text(policy.get("critical_cvss_threshold"), default="9.0")
    return [
        {
            "title": "Transparent priority rules",
            "body": (
                f"Policy profile {profile}; CVSS, EPSS, and KEV determine the base priority. "
                f"Critical CVSS threshold: {critical_cvss}; high EPSS threshold: {high_epss}."
            ),
        },
        {
            "title": "Locked provider evidence",
            "body": (
                "Provider snapshots and hashes document which NVD, EPSS, and KEV data "
                "powered the run."
            ),
        },
        {
            "title": "ATT&CK as context",
            "body": (
                "ATT&CK mappings are optional, source-controlled, and never generated "
                "heuristically."
            ),
        },
        {
            "title": "Reviewable governance",
            "body": (
                "VEX and waiver states are displayed separately so accepted risk stays auditable."
            ),
        },
    ]


def _finding_row(finding: dict[str, Any]) -> dict[str, Any]:
    service = _finding_service(finding)
    asset = _finding_asset(finding)
    if service != "not supplied" and asset != "not supplied":
        asset_service = f"{service} / {asset}"
    elif service != "not supplied":
        asset_service = service
    elif asset != "not supplied":
        asset_service = asset
    else:
        asset_service = "not supplied"
    return {
        "rank": _int_value(finding.get("operational_rank"))
        or _int_value(finding.get("priority_rank")),
        "cve": _text(finding.get("cve_id"), default="CVE"),
        "priority": _priority_label(finding),
        "tone": PRIORITY_TONES.get(_priority_label(finding), "low"),
        "kev": "Yes" if finding.get("in_kev") else "No",
        "epss": _score(finding.get("epss"), digits=3),
        "cvss": _score(finding.get("cvss_base_score"), digits=1),
        "attack": _attack_label(finding),
        "route": _route_label(finding),
        "asset_service": asset_service,
        "owner": _finding_owner(finding),
        "status": _status_label(finding),
        "baseline_delta": _baseline_delta_label(finding),
        "action": _text(finding.get("recommended_action"), default="Review finding."),
        "rationale": _text(finding.get("rationale"), default="No rationale supplied."),
    }


def _finding_dossier_model(finding: dict[str, Any]) -> dict[str, Any]:
    evidence = _dict_value(finding.get("provider_evidence"))
    nvd = _dict_value(evidence.get("nvd"))
    epss = _dict_value(evidence.get("epss"))
    kev = _dict_value(evidence.get("kev"))
    references = nvd.get("references")
    reference_count = len(references) if isinstance(references, list) else 0
    return {
        "cve": _text(finding.get("cve_id"), default="CVE"),
        "priority": _priority_label(finding),
        "tone": PRIORITY_TONES.get(_priority_label(finding), "low"),
        "cvss": _score(finding.get("cvss_base_score"), digits=1),
        "epss": _score(finding.get("epss"), digits=3),
        "kev": "Yes" if finding.get("in_kev") else "No",
        "route": _route_label(finding),
        "service": _finding_service(finding),
        "owner": _finding_owner(finding),
        "asset": _finding_asset(finding),
        "exposure": _finding_exposure(finding),
        "criticality": _finding_criticality(finding),
        "status": _status_label(finding),
        "vex": _vex_status(finding),
        "baseline_delta": _baseline_delta_label(finding),
        "action": _text(finding.get("recommended_action"), default="Review finding."),
        "rationale": _text(finding.get("rationale"), default="No rationale supplied."),
        "context_recommendation": _text(
            finding.get("context_recommendation"),
            default="No context-specific recommendation supplied.",
        ),
        "attack": _attack_label(finding),
        "techniques": _list_values(finding.get("attack_techniques")),
        "tactics": _list_values(finding.get("attack_tactics")),
        "provider": [
            {"label": "Published", "value": _text(nvd.get("published"), default="not available")},
            {
                "label": "Last modified",
                "value": _text(nvd.get("last_modified"), default="not available"),
            },
            {"label": "NVD references", "value": str(reference_count)},
            {"label": "Score date", "value": _text(epss.get("date"), default="not available")},
            {"label": "KEV due date", "value": _text(kev.get("due_date"), default="not available")},
            {
                "label": "KEV action",
                "value": _text(kev.get("required_action"), default="not available"),
            },
        ],
    }


def _finding_sort_key(finding: dict[str, Any]) -> tuple[int, int, int, float, float, str]:
    operational = _int_value(finding.get("operational_rank")) or 9999
    priority = _int_value(finding.get("priority_rank")) or 99
    kev_rank = 0 if finding.get("in_kev") else 1
    epss_rank = -_float_value(finding.get("epss"))
    cvss_rank = -_float_value(finding.get("cvss_base_score"))
    return (operational, priority, kev_rank, epss_rank, cvss_rank, _text(finding.get("cve_id")))


def _finding_signal_score(finding: dict[str, Any]) -> float:
    priority_weight = {"Critical": 4.0, "High": 3.0, "Medium": 2.0, "Low": 1.0}.get(
        _priority_label(finding),
        1.0,
    )
    cvss = max(_float_value(finding.get("cvss_base_score")), 0.0) / 10.0
    epss = max(_float_value(finding.get("epss")), 0.0)
    kev = 1.5 if finding.get("in_kev") else 0.0
    attack = 0.75 if finding.get("attack_mapped") else 0.0
    exposure = 0.75 if _finding_exposure(finding).lower() == "internet-facing" else 0.0
    criticality = 0.5 if _finding_criticality(finding).lower() in {"critical", "high"} else 0.0
    return round(priority_weight + cvss + epss + kev + attack + exposure + criticality, 2)


def _executive_summary(
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    counts_by_priority: dict[str, int],
    attack_summary: dict[str, Any],
) -> str:
    critical = counts_by_priority.get("Critical", 0)
    high = counts_by_priority.get("High", 0)
    kev = _int_value(metadata.get("kev_hits"))
    mapped = _int_value(attack_summary.get("mapped_cves"))
    if mapped == 0:
        mapped = sum(1 for item in findings if item.get("attack_mapped"))
    return (
        f"{len(findings)} visible finding(s) are included in this report, with {critical} Critical "
        f"and {high} High priority findings. {kev} findings are KEV-listed and should be "
        f"treated as urgent regardless of CVSS alone. ATT&CK context is available for "
        f"{mapped} mapped finding(s) where supplied."
    )


def _provider_evidence_notes(findings: list[dict[str, Any]]) -> list[str]:
    notes: list[str] = []
    for finding in findings[:1]:
        evidence = _dict_value(finding.get("provider_evidence"))
        nvd = _dict_value(evidence.get("nvd"))
        epss = _dict_value(evidence.get("epss"))
        kev = _dict_value(evidence.get("kev"))
        if nvd.get("published"):
            notes.append(f"Published: {nvd['published']}")
        if epss.get("date"):
            notes.append(f"Score date: {epss['date']}")
        if kev.get("due_date"):
            notes.append(f"Due date: {kev['due_date']}")
    return notes


def _kev_due_date(finding: dict[str, Any]) -> str:
    evidence = _dict_value(finding.get("provider_evidence"))
    kev = _dict_value(evidence.get("kev"))
    return _text(kev.get("due_date"), default="not available")


def _priority_counts(
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, int]:
    raw = metadata.get("counts_by_priority")
    counts: dict[str, int] = {}
    if isinstance(raw, dict):
        counts.update({str(key): _int_value(value) for key, value in raw.items()})
    if not counts:
        counter = Counter(_priority_label(finding) for finding in findings)
        counts.update(dict(counter))
    return {label: counts.get(label, 0) for label in PRIORITY_ORDER}


def _service_counter(findings: list[dict[str, Any]]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for finding in findings:
        value = _finding_service(finding)
        if value != "not supplied":
            counter[value] += 1
    return counter


def _owner_counter(findings: list[dict[str, Any]]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for finding in findings:
        value = _finding_owner(finding)
        if value != "not supplied":
            counter[value] += 1
    return counter


def _asset_counter(findings: list[dict[str, Any]]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for finding in findings:
        value = _finding_asset(finding)
        if value != "not supplied":
            counter[value] += 1
    return counter


def _finding_service(finding: dict[str, Any]) -> str:
    return _first_occurrence_field(finding, "asset_business_service")


def _finding_owner(finding: dict[str, Any]) -> str:
    return _first_occurrence_field(finding, "asset_owner")


def _finding_asset(finding: dict[str, Any]) -> str:
    direct = _list_first(_dict_value(finding.get("provenance")).get("asset_ids"))
    return direct or _first_occurrence_field(finding, "asset_id")


def _finding_exposure(finding: dict[str, Any]) -> str:
    provenance = _dict_value(finding.get("provenance"))
    direct = _text(provenance.get("highest_asset_exposure"), default="")
    if direct:
        return direct
    return _first_occurrence_field(finding, "asset_exposure")


def _finding_criticality(finding: dict[str, Any]) -> str:
    provenance = _dict_value(finding.get("provenance"))
    direct = _text(
        finding.get("highest_asset_criticality") or provenance.get("highest_asset_criticality"),
        default="",
    )
    if direct:
        return direct
    return _first_occurrence_field(finding, "asset_criticality")


def _criticality_rank(value: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(value.lower(), 0)


def _first_occurrence_field(finding: dict[str, Any], field: str) -> str:
    for occurrence in _occurrences(finding):
        value = _text(occurrence.get(field), default="")
        if value:
            return value
    return "not supplied"


def _occurrences(finding: dict[str, Any]) -> list[dict[str, Any]]:
    provenance = _dict_value(finding.get("provenance"))
    return [item for item in provenance.get("occurrences", []) if isinstance(item, dict)]


def _route_label(finding: dict[str, Any]) -> str:
    service = _finding_service(finding)
    owner = _finding_owner(finding)
    if service != "not supplied" and owner != "not supplied":
        return f"{service} / {owner}"
    if service != "not supplied":
        return service
    if owner != "not supplied":
        return owner
    return "not supplied"


def _status(finding: dict[str, Any]) -> str:
    if finding.get("suppressed_by_vex"):
        return "suppressed"
    if finding.get("waived"):
        return "accepted"
    return str(finding.get("status") or "open")


def _status_label(finding: dict[str, Any]) -> str:
    if finding.get("waiver_status"):
        label = "Waiver " + str(finding["waiver_status"]).replace("_", " ")
        if finding.get("waiver_owner"):
            label += f" owner={finding['waiver_owner']}"
        return label
    if finding.get("under_investigation"):
        return "Under investigation"
    return _status(finding).replace("_", " ").title()


def _attack_finding_notes(findings: list[dict[str, Any]]) -> list[str]:
    notes: list[str] = []
    for finding in findings:
        note = _text(finding.get("attack_note") or finding.get("attack_rationale"), default="")
        if note and note not in notes:
            notes.append(note)
        if len(notes) >= 3:
            break
    return notes


def _vex_status(finding: dict[str, Any]) -> str:
    provenance = _dict_value(finding.get("provenance"))
    raw = provenance.get("vex_statuses")
    if isinstance(raw, dict) and raw:
        return ", ".join(str(key) for key in raw)
    if finding.get("under_investigation"):
        return "under_investigation"
    if finding.get("suppressed_by_vex"):
        return "suppressed"
    return "not supplied"


def _counter_rows(counter: Counter[str], total: int, *, limit: int = 6) -> list[dict[str, Any]]:
    denominator = max(total, sum(counter.values()), 1)
    return [
        {"label": label, "count": count, "pct": _pct(count, denominator)}
        for label, count in counter.most_common(limit)
    ]


def _distribution_counter(value: Any) -> Counter[str]:
    counter: Counter[str] = Counter()
    if isinstance(value, dict):
        for key, raw_count in value.items():
            label = str(key).strip()
            if label:
                counter[label] = _int_value(raw_count)
    return counter


def _distribution_model(counter: Counter[str], *, limit: int = 6) -> list[dict[str, Any]]:
    total = max(sum(counter.values()), 1)
    return [
        {"label": label, "count": count, "pct": _pct(count, total)}
        for label, count in counter.most_common(limit)
    ]


def _artifact_model(reports: list[Any], bundles: list[Any]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for report in reports:
        report_id = _attr(report, "id")
        if not report_id:
            continue
        items.append(
            {
                "label": f"{_attr(report, 'kind') or 'report'} ({_attr(report, 'format')})",
                "url": f"/api/reports/{report_id}/download",
                "detail": _sha_preview(_attr(report, "sha256")),
            }
        )
    for bundle in bundles:
        bundle_id = _attr(bundle, "id")
        if not bundle_id:
            continue
        items.append(
            {
                "label": "Evidence ZIP",
                "url": f"/api/evidence-bundles/{bundle_id}/download",
                "detail": _sha_preview(_attr(bundle, "sha256")),
            }
        )
        items.append(
            {
                "label": "Verify evidence bundle",
                "url": f"/evidence-bundles/{bundle_id}/verify",
                "detail": "integrity check",
            }
        )
    return items


def _workspace_nav(
    project_id: str | None, run_id: str | None, project_name: str
) -> dict[str, Any] | None:
    if not project_id:
        return None
    project_base = f"/projects/{project_id}"
    groups = [
        {
            "label": "Analyze",
            "links": [
                {"label": "Dashboard", "href": f"{project_base}/dashboard", "active": False},
                {"label": "Import", "href": f"{project_base}/imports/new", "active": False},
                {"label": "Findings", "href": f"{project_base}/findings", "active": False},
                {
                    "label": "Intelligence",
                    "href": f"{project_base}/vulnerabilities",
                    "active": False,
                },
            ],
        },
        {
            "label": "Context",
            "links": [
                {"label": "Governance", "href": f"{project_base}/governance", "active": False},
                {"label": "Assets", "href": f"{project_base}/assets", "active": False},
                {"label": "Waivers", "href": f"{project_base}/waivers", "active": False},
                {"label": "Coverage", "href": f"{project_base}/coverage", "active": False},
            ],
        },
    ]
    if run_id:
        groups.append(
            {
                "label": "Run",
                "links": [
                    {
                        "label": "Run artifacts",
                        "href": f"/analysis-runs/{run_id}/reports",
                        "active": False,
                    },
                    {
                        "label": "Executive Report",
                        "href": f"/analysis-runs/{run_id}/executive-report",
                        "active": True,
                    },
                ],
            }
        )
    groups.append(
        {
            "label": "Operate",
            "links": [
                {"label": "Settings", "href": f"{project_base}/settings", "active": False},
            ],
        }
    )
    return {"project": project_name, "groups": groups}


def _kpi(label: str, value: int, detail: str, tone: str) -> dict[str, str]:
    return {"label": label, "value": f"{value:,}", "detail": detail, "tone": tone}
