"""Executive report ATT&CK model builders."""
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


def _detection_coverage_model(report_payload: dict[str, Any]) -> dict[str, Any]:
    coverage = _dict_value(report_payload.get("detection_coverage"))
    summary = _dict_value(coverage.get("summary"))
    items = [item for item in coverage.get("items", []) if isinstance(item, dict)]
    weak_statuses = {"partial", "not_covered", "unknown"}
    weak_items = [item for item in items if _text(item.get("coverage_level")) in weak_statuses]
    status_order = {"not_covered": 0, "unknown": 1, "partial": 2, "covered": 3}
    weak_items.sort(
        key=lambda item: (
            status_order.get(_text(item.get("coverage_level")), 9),
            -_int_value(item.get("critical_finding_count")),
            -_int_value(item.get("kev_finding_count")),
            -_int_value(item.get("finding_count")),
            _text(item.get("technique_id")),
        )
    )
    return {
        "summary": {
            "covered": _int_value(summary.get("covered")),
            "partial": _int_value(summary.get("partial")),
            "not_covered": _int_value(summary.get("not_covered")),
            "unknown": _int_value(summary.get("unknown")),
            "not_applicable": _int_value(summary.get("not_applicable")),
        },
        "total": len(items),
        "weak_total": len(weak_items),
        "weak_items": weak_items[:8],
        "note": _text(
            coverage.get("note"),
            default=(
                "Detection coverage is operator-supplied defensive review evidence, "
                "not proof of security or exploitation."
            ),
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


__all__ = [
    "_attack_asset_matrix_model",
    "_attack_model",
    "_attack_top_mapped_findings",
    "_detection_coverage_model",
    "_related_tactic_count",
]
