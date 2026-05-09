"""Shared executive report model helpers."""
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


def _kpi_value(model: dict[str, Any], label: str) -> str:
    for item in model["kpis"]:
        if item["label"] == label:
            return str(item["value"])
    return "0"


def _finding_decision_guidance(finding: dict[str, Any]) -> dict[str, Any]:
    return _dict_value(finding.get("decision_guidance"))


def _finding_decision_template(finding: dict[str, Any]) -> str:
    guidance = _finding_decision_guidance(finding)
    return _text(guidance.get("template_label"), default="not supplied")


def _finding_sla_label(finding: dict[str, Any]) -> str:
    guidance = _finding_decision_guidance(finding)
    sla = _dict_value(guidance.get("sla"))
    label = _text(sla.get("label"), default="not supplied")
    target_hours = _int_value(sla.get("target_hours"))
    target_days = _int_value(sla.get("target_days"))
    if 0 < target_hours <= 48:
        return f"{label} ({target_hours}h)"
    if target_days:
        return f"{label} ({target_days}d)"
    return label


def _finding_decision_statement(finding: dict[str, Any]) -> str:
    guidance = _finding_decision_guidance(finding)
    return _text(
        guidance.get("decision_statement"),
        default=_text(finding.get("recommended_action"), default="Review finding."),
    )


def _finding_sort_key(finding: dict[str, Any]) -> tuple[int, int, int, int, float, float, str]:
    operational = _int_value(finding.get("operational_rank")) or 9999
    operational_score = -(_int_value(finding.get("operational_score")) or 0)
    priority = _int_value(finding.get("priority_rank")) or 99
    kev_rank = 0 if finding.get("in_kev") else 1
    epss_rank = -_float_value(finding.get("epss"))
    cvss_rank = -_float_value(finding.get("cvss_base_score"))
    return (
        operational,
        operational_score,
        priority,
        kev_rank,
        epss_rank,
        cvss_rank,
        _text(finding.get("cve_id")),
    )


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


def _kpi(label: str, value: int, detail: str, tone: str) -> dict[str, str]:
    return {"label": label, "value": f"{value:,}", "detail": detail, "tone": tone}


__all__ = [
    "_asset_counter",
    "_attack_finding_notes",
    "_counter_rows",
    "_criticality_rank",
    "_distribution_counter",
    "_distribution_model",
    "_executive_summary",
    "_finding_asset",
    "_finding_criticality",
    "_finding_decision_guidance",
    "_finding_decision_statement",
    "_finding_decision_template",
    "_finding_exposure",
    "_finding_owner",
    "_finding_service",
    "_finding_signal_score",
    "_finding_sla_label",
    "_finding_sort_key",
    "_first_occurrence_field",
    "_kev_due_date",
    "_kpi",
    "_kpi_value",
    "_occurrences",
    "_owner_counter",
    "_priority_counts",
    "_provider_evidence_notes",
    "_route_label",
    "_service_counter",
    "_status",
    "_status_label",
    "_vex_status",
]
