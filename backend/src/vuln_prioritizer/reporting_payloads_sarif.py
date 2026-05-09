"""SARIF payload rendering for analysis reports."""

from __future__ import annotations

import json
from typing import Any

from vuln_prioritizer.models import AnalysisContext, PrioritizedFinding
from vuln_prioritizer.sarif_contract import (
    sarif_artifact_uri,
    sarif_component_identities,
    sarif_level,
    sarif_partial_fingerprints,
    sarif_result_location,
    sarif_rule_id,
    sarif_rule_properties,
)
from vuln_prioritizer.sarif_references import dedupe_defensive_http_urls


def generate_sarif_report(
    findings: list[PrioritizedFinding],
    context: AnalysisContext,
) -> str:
    """Render a SARIF report for analyze output."""
    results: list[dict[str, Any]] = []
    rules_by_id: dict[str, dict[str, Any]] = {}
    for finding in findings:
        artifact_uri = sarif_artifact_uri(
            affected_paths=finding.provenance.affected_paths,
            target_refs=finding.provenance.targets,
            fallback=context.input_path,
        )
        message = (
            f"{finding.cve_id}: {finding.priority_label} priority "
            "based on CVSS/EPSS/KEV with contextual enrichment."
        )
        references = _sarif_reference_urls(
            finding.cve_id,
            nvd_references=(
                finding.provider_evidence.nvd.references
                if finding.provider_evidence is not None
                else []
            ),
            defensive_contexts=finding.defensive_contexts,
        )
        rule_id = sarif_rule_id(finding.cve_id)
        rules_by_id.setdefault(rule_id, _sarif_rule(finding, references=references))
        results.append(
            {
                "ruleId": rule_id,
                "level": sarif_level(finding.priority_label),
                "message": {"text": message},
                "properties": {
                    "cve": finding.cve_id,
                    "priority": finding.priority_label,
                    "priority_state": finding.priority_state or finding.priority_label,
                    "operational_score": finding.operational_score,
                    "operational_score_reasons": finding.operational_score_reasons,
                    "explanation_reason_codes": (
                        [reason.code for reason in finding.explanation.reasons]
                        if finding.explanation
                        else []
                    ),
                    "explanation_notes": (
                        [note.model_dump() for note in finding.explanation.notes]
                        if finding.explanation
                        else []
                    ),
                    "cvss": finding.cvss_base_score,
                    "epss": finding.epss,
                    "in_kev": finding.in_kev,
                    "data_quality_flags": [
                        flag.model_dump() for flag in finding.data_quality_flags
                    ],
                    "data_quality_flag_codes": [flag.code for flag in finding.data_quality_flags],
                    "data_quality_confidence": finding.data_quality_confidence,
                    "references": references,
                    "cve_url": references[0],
                    "attack_relevance": finding.attack_relevance,
                    "defensive_context_sources": sorted(
                        {context_item.source for context_item in finding.defensive_contexts}
                    ),
                    "defensive_context_count": len(finding.defensive_contexts),
                    "defensive_context_ids": [
                        context_item.source_id
                        for context_item in finding.defensive_contexts
                        if context_item.source_id
                    ][:10],
                    "sources": finding.provenance.source_formats,
                    "components": finding.provenance.components,
                    "suppressed_by_vex": finding.suppressed_by_vex,
                    "under_investigation": finding.under_investigation,
                    "remediation_strategy": finding.remediation.strategy,
                    "remediation_ecosystem": finding.remediation.ecosystem,
                    "decision_template": (
                        finding.decision_guidance.template
                        if finding.decision_guidance is not None
                        else None
                    ),
                    "decision_sla": (
                        finding.decision_guidance.sla.model_dump()
                        if finding.decision_guidance is not None
                        else None
                    ),
                    "decision_statement": (
                        finding.decision_guidance.decision_statement
                        if finding.decision_guidance is not None
                        else None
                    ),
                    "business_impact": (
                        finding.decision_guidance.business_impact.model_dump()
                        if finding.decision_guidance is not None
                        else None
                    ),
                },
                "partialFingerprints": sarif_partial_fingerprints(
                    cve_id=finding.cve_id,
                    artifact_uri=artifact_uri,
                    components=_sarif_component_identities(finding),
                    asset_ids=finding.provenance.asset_ids,
                ),
                "locations": [sarif_result_location(artifact_uri=artifact_uri)],
            }
        )
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vuln-prioritizer",
                        "version": context.schema_version,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _sarif_rule(finding: PrioritizedFinding, *, references: list[str]) -> dict[str, Any]:
    priority = finding.priority_label
    return {
        "id": sarif_rule_id(finding.cve_id),
        "name": f"{finding.cve_id} prioritized vulnerability",
        "shortDescription": {"text": f"{finding.cve_id}: {priority} priority."},
        "fullDescription": {
            "text": (
                "Known CVE prioritized from CVSS, EPSS, and CISA KEV with "
                "optional contextual layers such as asset context, VEX, waivers, "
                "remediation, and ATT&CK mapping provenance."
            )
        },
        "defaultConfiguration": {"level": sarif_level(priority)},
        "helpUri": references[0],
        "help": {
            "text": (
                "Review the CVE, provider evidence, affected component or asset, "
                "and recommended remediation action. This tool prioritizes supplied "
                "findings and does not scan systems."
            )
        },
        "properties": sarif_rule_properties(
            cve_id=finding.cve_id,
            priority=priority,
            cvss_base_score=finding.cvss_base_score,
            references=references,
        ),
    }


def _sarif_reference_urls(
    cve_id: str,
    *,
    nvd_references: list[str],
    defensive_contexts: list[Any],
) -> list[str]:
    urls = [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]
    urls.extend(nvd_references)
    for context in defensive_contexts:
        url = getattr(context, "url", None)
        if url:
            urls.append(str(url))
        urls.extend(str(reference) for reference in getattr(context, "references", []) if reference)
    return _dedupe_strings(urls)


def _sarif_component_identities(finding: PrioritizedFinding) -> list[str]:
    return sarif_component_identities(
        component_purls=[
            component.purl for component in finding.remediation.components if component.purl
        ],
        components=finding.provenance.components,
    )


def _dedupe_strings(values: list[str]) -> list[str]:
    return dedupe_defensive_http_urls(values)


__all__ = ["generate_sarif_report"]
