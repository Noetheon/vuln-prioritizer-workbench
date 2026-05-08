"""SARIF rendering for Workbench report payloads."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.services.report_contracts import ANALYSIS_RESULT_SCHEMA_VERSION
from app.services.report_models import MarkdownReportFinding, MarkdownReportPayload
from vuln_prioritizer.sarif_contract import (
    sarif_artifact_uri,
    sarif_component_identities,
    sarif_level,
    sarif_partial_fingerprints,
    sarif_priority_label,
    sarif_rule_id,
    sarif_security_severity,
    sarif_target_identity,
)
from vuln_prioritizer.sarif_references import dedupe_defensive_http_urls


def render_sarif_report(payload: MarkdownReportPayload) -> dict[str, Any]:
    """Render a SARIF 2.1.0 vulnerability results payload for code scanning imports."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in payload.findings:
        rule_id = sarif_rule_id(finding.cve_id)
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
        "ruleId": sarif_rule_id(finding.cve_id),
        "level": sarif_level(finding.priority),
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
        "partialFingerprints": sarif_partial_fingerprints(
            cve_id=finding.cve_id,
            artifact_uri=location_uri,
            components=_sarif_components(finding),
            asset_ids=_sarif_asset_ids(finding),
            include_workbench_alias=True,
        ),
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
        "id": sarif_rule_id(finding.cve_id),
        "name": f"{finding.cve_id} prioritized vulnerability",
        "shortDescription": {"text": f"{finding.cve_id}: {priority} Workbench priority."},
        "fullDescription": {
            "text": (
                "Known CVE prioritized from CVSS, EPSS, CISA KEV, asset context, "
                "and optional Workbench governance layers."
            )
        },
        "defaultConfiguration": {"level": sarif_level(finding.priority)},
        "helpUri": references[0],
        "properties": {
            "cve": finding.cve_id,
            "priority": priority,
            "precision": "very-high",
            "security-severity": sarif_security_severity(
                priority=finding.priority,
                cvss_base_score=finding.cvss_base_score,
            ),
            "tags": ["security", "external/cve", f"priority/{priority.lower()}"],
            "references": references,
        },
    }


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
    affected_paths: list[str] = []
    target_refs: list[str] = []
    for occurrence in finding.occurrences:
        evidence = _dict_value(occurrence.get("evidence"))
        for key in ("path", "file", "artifact_uri"):
            value = evidence.get(key) or occurrence.get(key)
            if isinstance(value, str) and value.strip():
                affected_paths.append(_sarif_safe_uri(value))
        target_identity = sarif_target_identity(
            evidence.get("target_kind") or occurrence.get("target_kind"),
            evidence.get("target_ref") or occurrence.get("target_ref"),
        )
        if target_identity:
            target_refs.append(_sarif_safe_uri(target_identity))
    return sarif_artifact_uri(
        affected_paths=affected_paths,
        target_refs=target_refs,
        fallback=_sarif_safe_uri(finding.component_purl or finding.component or finding.cve_id),
    )


def _sarif_safe_uri(value: str) -> str:
    stripped = value.strip().replace("\\", "/")
    if not stripped or "://" in stripped:
        return "workbench-input"
    while "//" in stripped:
        stripped = stripped.replace("//", "/")
    if stripped.startswith(("/", "../")):
        return "workbench-input"
    return stripped.lstrip("./")


def _sarif_logical_location(finding: MarkdownReportFinding) -> str:
    parts = [
        finding.asset_key or finding.asset,
        finding.component_purl or finding.component,
        finding.cve_id,
    ]
    return " / ".join(str(part) for part in parts if part) or finding.cve_id


def _sarif_components(finding: MarkdownReportFinding) -> list[str]:
    occurrence_purls: list[str] = []
    for occurrence in finding.occurrences:
        evidence = _dict_value(occurrence.get("evidence"))
        purl = evidence.get("purl") or occurrence.get("purl")
        if isinstance(purl, str) and purl.strip():
            occurrence_purls.append(purl)
    return sarif_component_identities(
        component_purls=[finding.component_purl, *occurrence_purls],
        components=[finding.component],
    )


def _sarif_asset_ids(finding: MarkdownReportFinding) -> list[str]:
    return [value for value in [finding.asset_key or finding.asset] if value]


def _priority_label(value: str) -> str:
    return sarif_priority_label(value)


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
