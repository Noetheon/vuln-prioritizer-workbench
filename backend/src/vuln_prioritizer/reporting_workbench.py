"""Workbench-style CSV and SARIF renderers for CLI analysis exports."""

from __future__ import annotations

import csv
import hashlib
import json
from io import StringIO
from typing import Any


def generate_findings_csv(report_payload: dict[str, Any]) -> str:
    """Render a spreadsheet-safe CSV export for Workbench findings."""
    output = StringIO()
    fieldnames = [
        "cve_id",
        "priority",
        "status",
        "kev",
        "epss",
        "cvss",
        "data_quality_confidence",
        "data_quality_flags",
        "component",
        "asset",
        "owner",
        "service",
        "vex_statuses",
        "suppressed_by_vex",
        "under_investigation",
        "waived",
        "waiver_status",
        "waiver_owner",
        "waiver_expires_on",
        "waiver_review_on",
        "attack_mapped",
        "attack_techniques",
        "defensive_context_sources",
        "decision_template",
        "decision_sla",
        "decision_statement",
        "business_impact",
        "recommended_action",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for finding in report_payload.get("findings", []):
        if not isinstance(finding, dict):
            continue
        raw_provenance = finding.get("provenance")
        provenance: dict[str, Any] = raw_provenance if isinstance(raw_provenance, dict) else {}
        defensive_contexts = [
            item for item in finding.get("defensive_contexts", []) if isinstance(item, dict)
        ]
        decision_guidance = _decision_guidance(finding)
        writer.writerow(
            {
                "cve_id": _csv_safe_cell(finding.get("cve_id")),
                "priority": _csv_safe_cell(finding.get("priority_label")),
                "status": _csv_safe_cell(_finding_status_label(finding)),
                "kev": "yes" if finding.get("in_kev") else "no",
                "epss": _csv_safe_cell(finding.get("epss")),
                "cvss": _csv_safe_cell(finding.get("cvss_base_score")),
                "data_quality_confidence": _csv_safe_cell(
                    finding.get("data_quality_confidence") or "high"
                ),
                "data_quality_flags": _csv_safe_cell(";".join(_data_quality_flag_codes(finding))),
                "component": _csv_safe_cell(_first_value(provenance.get("components"))),
                "asset": _csv_safe_cell(_first_value(provenance.get("asset_ids"))),
                "owner": _csv_safe_cell(_first_occurrence_value(provenance, "asset_owner")),
                "service": _csv_safe_cell(
                    _first_occurrence_value(provenance, "asset_business_service")
                ),
                "vex_statuses": _csv_safe_cell(_vex_statuses_label(provenance)),
                "suppressed_by_vex": "yes" if finding.get("suppressed_by_vex") else "no",
                "under_investigation": "yes" if finding.get("under_investigation") else "no",
                "waived": "yes" if finding.get("waived") else "no",
                "waiver_status": _csv_safe_cell(finding.get("waiver_status")),
                "waiver_owner": _csv_safe_cell(finding.get("waiver_owner")),
                "waiver_expires_on": _csv_safe_cell(finding.get("waiver_expires_on")),
                "waiver_review_on": _csv_safe_cell(finding.get("waiver_review_on")),
                "attack_mapped": "yes" if finding.get("attack_mapped") else "no",
                "attack_techniques": _csv_safe_cell(
                    ";".join(str(item) for item in finding.get("attack_techniques", []))
                ),
                "defensive_context_sources": _csv_safe_cell(
                    ";".join(
                        sorted(
                            {
                                str(item.get("source")).upper()
                                for item in defensive_contexts
                                if item.get("source")
                            }
                        )
                    )
                ),
                "decision_template": _csv_safe_cell(decision_guidance.get("template_label")),
                "decision_sla": _csv_safe_cell(_decision_sla_label(decision_guidance)),
                "decision_statement": _csv_safe_cell(decision_guidance.get("decision_statement")),
                "business_impact": _csv_safe_cell(_decision_business_impact(decision_guidance)),
                "recommended_action": _csv_safe_cell(finding.get("recommended_action")),
            }
        )
    return output.getvalue()


def generate_workbench_sarif(report_payload: dict[str, Any]) -> str:
    """Render SARIF from a stored Workbench analysis payload."""
    level_map = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
    }
    raw_metadata = report_payload.get("metadata")
    metadata: dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
    input_path = str(
        metadata.get("input_path") or metadata.get("input_format") or "workbench-input"
    )
    results: list[dict[str, Any]] = []
    rules_by_id: dict[str, dict[str, Any]] = {}
    for finding in report_payload.get("findings", []):
        if not isinstance(finding, dict):
            continue
        priority = str(finding.get("priority_label") or "Unprioritized")
        cve_id = str(finding.get("cve_id") or "CVE-UNKNOWN")
        provenance = (
            finding.get("provenance") if isinstance(finding.get("provenance"), dict) else {}
        )
        paths = provenance.get("affected_paths") if isinstance(provenance, dict) else []
        uri = str(paths[0]) if isinstance(paths, list) and paths else input_path
        defensive_contexts = [
            item for item in finding.get("defensive_contexts", []) if isinstance(item, dict)
        ]
        decision_guidance = _decision_guidance(finding)
        references = _workbench_sarif_reference_urls(cve_id, finding, defensive_contexts)
        rule_id = _workbench_sarif_rule_id(cve_id)
        rules_by_id.setdefault(
            rule_id,
            _workbench_sarif_rule(cve_id, priority, finding, references=references),
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": level_map.get(priority, "note"),
                "message": {
                    "text": (
                        f"{cve_id}: {priority} priority based on CVSS/EPSS/KEV, "
                        "asset context, and optional Workbench governance layers."
                    )
                },
                "properties": {
                    "cve": cve_id,
                    "priority": priority,
                    "cvss": finding.get("cvss_base_score"),
                    "epss": finding.get("epss"),
                    "in_kev": bool(finding.get("in_kev")),
                    "data_quality_flags": _data_quality_flags(finding),
                    "data_quality_flag_codes": _data_quality_flag_codes(finding),
                    "data_quality_confidence": str(
                        finding.get("data_quality_confidence") or "high"
                    ),
                    "references": references,
                    "cve_url": references[0],
                    "attack_relevance": finding.get("attack_relevance"),
                    "defensive_context_sources": sorted(
                        {
                            str(item.get("source"))
                            for item in defensive_contexts
                            if item.get("source")
                        }
                    ),
                    "defensive_context_count": len(defensive_contexts),
                    "suppressed_by_vex": bool(finding.get("suppressed_by_vex")),
                    "waived": bool(finding.get("waived")),
                    "waiver_status": finding.get("waiver_status"),
                    "status": _finding_status_label(finding),
                    "decision_template": decision_guidance.get("template"),
                    "decision_sla": decision_guidance.get("sla"),
                    "decision_statement": decision_guidance.get("decision_statement"),
                    "business_impact": decision_guidance.get("business_impact"),
                },
                "partialFingerprints": {
                    "vuln-prioritizer-workbench/v1": _workbench_sarif_fingerprint(
                        cve_id=cve_id,
                        uri=uri,
                        finding=finding,
                    ),
                },
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            }
        )
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vuln-prioritizer-workbench",
                        "version": str(metadata.get("schema_version") or "1.1.0"),
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _workbench_sarif_rule_id(cve_id: str) -> str:
    return f"vuln-prioritizer/{cve_id.lower()}"


def _workbench_sarif_rule(
    cve_id: str,
    priority: str,
    finding: dict[str, Any],
    *,
    references: list[str],
) -> dict[str, Any]:
    level_map = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
    }
    return {
        "id": _workbench_sarif_rule_id(cve_id),
        "name": f"{cve_id} prioritized vulnerability",
        "shortDescription": {"text": f"{cve_id}: {priority} Workbench priority."},
        "fullDescription": {
            "text": (
                "Known CVE prioritized from CVSS, EPSS, and CISA KEV with explicit "
                "Workbench context for assets, VEX, waivers, remediation, and ATT&CK."
            )
        },
        "defaultConfiguration": {"level": level_map.get(priority, "note")},
        "helpUri": references[0],
        "properties": {
            "cve": cve_id,
            "priority": priority,
            "precision": "very-high",
            "security-severity": _workbench_sarif_security_severity(priority, finding),
            "tags": ["security", "external/cve", f"priority/{priority.lower()}"],
            "references": references,
        },
    }


def _workbench_sarif_security_severity(priority: str, finding: dict[str, Any]) -> str:
    cvss_score = finding.get("cvss_base_score")
    if isinstance(cvss_score, int | float):
        return f"{min(max(float(cvss_score), 0.0), 10.0):.1f}"
    return {
        "Critical": "9.0",
        "High": "7.0",
        "Medium": "5.0",
        "Low": "3.0",
    }.get(priority, "0.0")


def _workbench_sarif_reference_urls(
    cve_id: str,
    finding: dict[str, Any],
    defensive_contexts: list[dict[str, Any]],
) -> list[str]:
    urls = [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]
    raw_provider_evidence = finding.get("provider_evidence")
    provider_evidence: dict[str, Any] = (
        raw_provider_evidence if isinstance(raw_provider_evidence, dict) else {}
    )
    raw_nvd_evidence = provider_evidence.get("nvd")
    nvd_evidence: dict[str, Any] = raw_nvd_evidence if isinstance(raw_nvd_evidence, dict) else {}
    references = nvd_evidence.get("references")
    if isinstance(references, list):
        urls.extend(str(reference) for reference in references if reference)
    for context in defensive_contexts:
        if context.get("url"):
            urls.append(str(context["url"]))
        context_references = context.get("references")
        if isinstance(context_references, list):
            urls.extend(str(reference) for reference in context_references if reference)
    return _dedupe_strings(urls)


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        normalized = str(value).strip()
        if normalized.startswith(("http://", "https://")) and normalized not in seen:
            seen.add(normalized)
            deduped.append(normalized)
    return deduped


def _workbench_sarif_fingerprint(
    *,
    cve_id: str,
    uri: str,
    finding: dict[str, Any],
) -> str:
    provenance = finding.get("provenance") if isinstance(finding.get("provenance"), dict) else {}
    components = provenance.get("components") if isinstance(provenance, dict) else []
    assets = provenance.get("asset_ids") if isinstance(provenance, dict) else []
    identity = "|".join(
        [
            cve_id,
            uri,
            ",".join(str(item) for item in components if item)
            if isinstance(components, list)
            else "",
            ",".join(str(item) for item in assets if item) if isinstance(assets, list) else "",
        ]
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _csv_safe_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if text.startswith(("\t", "\r", "\n")) or text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _first_value(value: object) -> str:
    if isinstance(value, list) and value:
        return str(value[0])
    return ""


def _first_occurrence_value(provenance: dict[str, Any], field: str) -> str:
    occurrences = provenance.get("occurrences")
    if not isinstance(occurrences, list):
        return ""
    for occurrence in occurrences:
        if not isinstance(occurrence, dict):
            continue
        value = occurrence.get(field)
        if value:
            return str(value)
    return ""


def _finding_status_label(finding: dict[str, Any]) -> str:
    if finding.get("status"):
        return str(finding["status"])
    if finding.get("suppressed_by_vex"):
        return "suppressed"
    if finding.get("waived"):
        return "accepted"
    return "open"


def _data_quality_flags(finding: dict[str, Any]) -> list[dict[str, Any]]:
    raw_flags = finding.get("data_quality_flags")
    if not isinstance(raw_flags, list):
        return []
    return [flag for flag in raw_flags if isinstance(flag, dict)]


def _data_quality_flag_codes(finding: dict[str, Any]) -> list[str]:
    codes: list[str] = []
    for flag in _data_quality_flags(finding):
        code = flag.get("code")
        if code and str(code) not in codes:
            codes.append(str(code))
    return codes


def _decision_guidance(finding: dict[str, Any]) -> dict[str, Any]:
    guidance = finding.get("decision_guidance")
    return guidance if isinstance(guidance, dict) else {}


def _decision_sla_label(decision_guidance: dict[str, Any]) -> str:
    sla = decision_guidance.get("sla")
    if not isinstance(sla, dict):
        return ""
    label = str(sla.get("label") or "")
    target_hours = sla.get("target_hours")
    target_days = sla.get("target_days")
    if isinstance(target_hours, int) and target_hours <= 48:
        return f"{label} ({target_hours}h)"
    if isinstance(target_days, int):
        return f"{label} ({target_days}d)"
    return label


def _decision_business_impact(decision_guidance: dict[str, Any]) -> str:
    business_impact = decision_guidance.get("business_impact")
    if not isinstance(business_impact, dict):
        return ""
    return str(business_impact.get("text") or "")


def _vex_statuses_label(provenance: dict[str, Any]) -> str:
    raw_statuses = provenance.get("vex_statuses")
    if not isinstance(raw_statuses, dict):
        return ""
    return ";".join(f"{status}:{count}" for status, count in sorted(raw_statuses.items()))
