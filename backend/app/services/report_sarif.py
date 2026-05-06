"""SARIF rendering for Workbench report payloads."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from app.services.report_contracts import ANALYSIS_RESULT_SCHEMA_VERSION
from app.services.report_models import MarkdownReportFinding, MarkdownReportPayload
from vuln_prioritizer.sarif_references import dedupe_defensive_http_urls


def render_sarif_report(payload: MarkdownReportPayload) -> dict[str, Any]:
    """Render a SARIF 2.1.0 vulnerability results payload for code scanning imports."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in payload.findings:
        rule_id = _sarif_rule_id(finding.cve_id)
        references = _sarif_references(finding)
        rules_by_id.setdefault(rule_id, _sarif_rule(finding, references=references))
        results.append(_sarif_result(finding, references=references))

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vuln-prioritizer-workbench",
                        "informationUri": "https://github.com/Noetheon/vuln-prioritizer-workbench",
                        "rules": list(rules_by_id.values()),
                        "version": ANALYSIS_RESULT_SCHEMA_VERSION,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": _iso_datetime(payload.generated_at),
                        "properties": {
                            "analysis_run_id": payload.run_id,
                            "project_id": payload.project_id,
                        },
                    }
                ],
                "results": results,
            }
        ],
    }


def _sarif_result(
    finding: MarkdownReportFinding,
    *,
    references: list[str],
) -> dict[str, Any]:
    location_uri = _sarif_location_uri(finding)
    return {
        "ruleId": _sarif_rule_id(finding.cve_id),
        "level": _sarif_level(finding.priority),
        "message": {
            "text": (
                f"{finding.cve_id}: {_priority_label(finding.priority)} priority "
                "vulnerability from Workbench CVSS, EPSS, KEV, asset, and governance context."
            )
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": location_uri,
                        "uriBaseId": "%SRCROOT%",
                    }
                },
                "logicalLocations": [
                    {
                        "fullyQualifiedName": _sarif_logical_location(finding),
                        "kind": "component",
                    }
                ],
            }
        ],
        "partialFingerprints": {
            "vuln-prioritizer-workbench/v1": _sarif_fingerprint(
                finding=finding,
                uri=location_uri,
            )
        },
        "properties": {
            "cve": finding.cve_id,
            "priority": _priority_label(finding.priority),
            "cvss": finding.cvss_base_score,
            "epss": finding.epss,
            "in_kev": finding.in_kev,
            "asset": finding.asset,
            "asset_key": finding.asset_key,
            "component": finding.component,
            "component_purl": finding.component_purl,
            "status": finding.status,
            "references": references,
            "cve_url": references[0],
            "data_quality_confidence": finding.data_quality_confidence,
            "data_quality_flags": finding.data_quality_flags,
            "suppressed_by_vex": _boolish_signal(finding, "suppressed_by_vex"),
            "under_investigation": _boolish_signal(finding, "under_investigation"),
            "waived": _boolish_signal(finding, "waived"),
            "decision_sla": finding.decision_sla,
            "decision_statement": finding.decision_statement,
            "business_impact": finding.business_impact,
        },
    }


def _sarif_rule(
    finding: MarkdownReportFinding,
    *,
    references: list[str],
) -> dict[str, Any]:
    priority = _priority_label(finding.priority)
    return {
        "id": _sarif_rule_id(finding.cve_id),
        "name": f"{finding.cve_id} prioritized vulnerability",
        "shortDescription": {"text": f"{finding.cve_id}: {priority} Workbench priority."},
        "fullDescription": {
            "text": (
                "Known CVE prioritized from CVSS, EPSS, CISA KEV, asset context, "
                "and optional Workbench governance layers."
            )
        },
        "defaultConfiguration": {"level": _sarif_level(finding.priority)},
        "helpUri": references[0],
        "properties": {
            "cve": finding.cve_id,
            "priority": priority,
            "precision": "very-high",
            "security-severity": _sarif_security_severity(finding),
            "tags": ["security", "external/cve", f"priority/{priority.lower()}"],
            "references": references,
        },
    }


def _sarif_rule_id(cve_id: str) -> str:
    return f"vuln-prioritizer/{cve_id.lower()}"


def _sarif_level(priority: str) -> str:
    return {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
    }[_priority_label(priority)]


def _sarif_security_severity(finding: MarkdownReportFinding) -> str:
    if finding.cvss_base_score is not None:
        return f"{min(max(float(finding.cvss_base_score), 0.0), 10.0):.1f}"
    return {
        "Critical": "9.0",
        "High": "7.0",
        "Medium": "5.0",
        "Low": "3.0",
    }[_priority_label(finding.priority)]


def _sarif_references(finding: MarkdownReportFinding) -> list[str]:
    candidates = [f"https://nvd.nist.gov/vuln/detail/{finding.cve_id}"]
    candidates.extend(_http_references_from_mapping(finding.vulnerability))
    candidates.extend(_http_references_from_mapping(finding.evidence))
    candidates.extend(_http_references_from_mapping(finding.explanation))
    return _dedupe_http_urls(candidates)


def _http_references_from_mapping(mapping: dict[str, Any]) -> list[str]:
    urls: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for child in value.values():
                walk(child)
            return
        if isinstance(value, list):
            for child in value:
                walk(child)
            return
        if isinstance(value, str) and value.startswith(("http://", "https://")):
            urls.append(value)

    for key in ("references", "reference_urls", "urls", "url", "href", "link", "provider"):
        if key in mapping:
            walk(mapping[key])
    return urls


def _dedupe_http_urls(values: list[str]) -> list[str]:
    return dedupe_defensive_http_urls(values)


def _sarif_location_uri(finding: MarkdownReportFinding) -> str:
    for occurrence in finding.occurrences:
        evidence = _dict_value(occurrence.get("evidence"))
        for key in ("path", "file", "target_ref", "artifact_uri"):
            value = evidence.get(key) or occurrence.get(key)
            if isinstance(value, str) and value.strip():
                return _sarif_safe_uri(value)
    return _sarif_safe_uri(finding.component_purl or finding.component or finding.cve_id)


def _sarif_safe_uri(value: str) -> str:
    stripped = value.strip().replace("\\", "/")
    if not stripped or stripped.startswith(("/", "../")) or "://" in stripped:
        return "workbench-input"
    return stripped.lstrip("./")


def _sarif_logical_location(finding: MarkdownReportFinding) -> str:
    parts = [
        finding.asset_key or finding.asset,
        finding.component_purl or finding.component,
        finding.cve_id,
    ]
    return " / ".join(str(part) for part in parts if part) or finding.cve_id


def _sarif_fingerprint(*, finding: MarkdownReportFinding, uri: str) -> str:
    occurrence_parts: list[str] = []
    for occurrence in finding.occurrences:
        evidence = _dict_value(occurrence.get("evidence"))
        occurrence_parts.append(
            "|".join(
                str(value or "")
                for value in (
                    occurrence.get("source"),
                    occurrence.get("scanner"),
                    occurrence.get("raw_reference"),
                    occurrence.get("fix_version"),
                    evidence.get("target_ref"),
                    evidence.get("path"),
                )
            )
        )
    identity = "|".join(
        [
            finding.cve_id,
            finding.asset_key or finding.asset or "",
            finding.component_purl or finding.component or "",
            uri,
            "||".join(occurrence_parts),
        ]
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _priority_label(value: str) -> str:
    normalized = value.split(".", maxsplit=1)[-1].strip().lower()
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }.get(normalized, "Low")


def _boolish_signal(finding: MarkdownReportFinding, key: str) -> bool:
    if hasattr(finding, key):
        return bool(getattr(finding, key))
    if key == "attack_mapped":
        value: Any = finding.explanation.get(key, False)
        if value is False:
            value = finding.evidence.get(key, False)
    else:
        value = finding.explanation.get(key, False)
    return bool(value)


def _dict_value(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _iso_datetime(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
