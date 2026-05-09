"""Executive report view model builder."""
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

from vuln_prioritizer.reporting_executive_model_attack import *
from vuln_prioritizer.reporting_executive_model_evidence import *
from vuln_prioritizer.reporting_executive_model_findings import *
from vuln_prioritizer.reporting_executive_model_helpers import *
from vuln_prioritizer.reporting_executive_model_overview import *
from vuln_prioritizer.reporting_executive_model_remediation import *


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
    attack["detection_coverage"] = _detection_coverage_model(report_payload)
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


__all__ = [
    "build_executive_report_model",
]
