"""Payload and serialization helpers for report exports."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any

from vuln_prioritizer.models import (
    AnalysisContext,
    AttackData,
    ComparisonFinding,
    DoctorReport,
    EpssData,
    EvidenceBundleManifest,
    EvidenceBundleVerificationItem,
    EvidenceBundleVerificationMetadata,
    EvidenceBundleVerificationSummary,
    KevData,
    NvdData,
    PrioritizedFinding,
    RollupBucket,
    RollupMetadata,
    SnapshotDiffItem,
    SnapshotDiffMetadata,
    SnapshotDiffSummary,
    SnapshotMetadata,
    StateHistoryReport,
    StateImportReport,
    StateInitReport,
    StateServiceHistoryReport,
    StateTopServicesReport,
    StateTrendsReport,
    StateWaiverReport,
)
from vuln_prioritizer.reporting_format import _priority_display_label, normalize_whitespace
from vuln_prioritizer.services.baseline_comparison import (
    build_cvss_baseline_comparison_payload,
)


def generate_json_report(
    findings: list[PrioritizedFinding],
    context: AnalysisContext,
) -> str:
    """Render the JSON export."""
    payload = build_analysis_report_payload(findings, context)
    return json.dumps(payload, indent=2, sort_keys=True)


def build_analysis_report_payload(
    findings: list[PrioritizedFinding],
    context: AnalysisContext,
) -> dict[str, Any]:
    """Build the canonical analysis payload shared by JSON and HTML renderers."""
    return {
        "metadata": _context_metadata(context),
        "attack_summary": context.attack_summary.model_dump(),
        "baseline_comparison": build_cvss_baseline_comparison_payload(
            findings,
            top_change_limit=5,
            include_comparisons=False,
        ),
        "findings": [finding.model_dump() for finding in findings],
    }


def build_snapshot_report_payload(
    findings: list[PrioritizedFinding],
    metadata: SnapshotMetadata,
) -> dict[str, Any]:
    """Build the canonical snapshot payload."""
    return {
        "metadata": _context_metadata(metadata),
        "attack_summary": metadata.attack_summary.model_dump(),
        "findings": [finding.model_dump() for finding in findings],
    }


def _context_metadata(context: AnalysisContext | SnapshotMetadata) -> dict[str, Any]:
    metadata = context.model_dump(exclude={"attack_summary"})
    if not metadata.get("provider_data_quality_flags"):
        metadata.pop("provider_data_quality_flags", None)
    return metadata


def generate_summary_markdown(
    report_payload: dict[str, Any],
    *,
    template: str = "detailed",
) -> str:
    """Render a short executive Markdown summary from an analysis-style payload."""
    if template == "compact":
        return generate_compact_summary_markdown(report_payload)
    if template != "detailed":
        raise ValueError(f"Unsupported summary template: {template}")

    metadata = report_payload.get("metadata", {})
    attack_summary = report_payload.get("attack_summary", {})
    findings = report_payload.get("findings", [])
    counts_by_priority = metadata.get("counts_by_priority", {})
    lines = [
        "# Vulnerability Prioritization Summary",
        "",
        f"- Input: `{metadata.get('input_path', 'N.A.')}`",
        f"- Input format: `{metadata.get('input_format', 'N.A.')}`",
        f"- Merged inputs: {metadata.get('merged_input_count', 1)}",
        f"- Duplicate CVEs collapsed: {metadata.get('duplicate_cve_count', 0)}",
        f"- Asset-context conflicts resolved: {metadata.get('asset_match_conflict_count', 0)}",
        f"- VEX conflicts resolved: {metadata.get('vex_conflict_count', 0)}",
        f"- Policy profile: `{metadata.get('policy_profile', 'default')}`",
        f"- Findings shown: {metadata.get('findings_count', 0)}",
        f"- Critical: {counts_by_priority.get('Critical', 0)}",
        f"- High: {counts_by_priority.get('High', 0)}",
        f"- KEV hits: {metadata.get('kev_hits', 0)}",
        f"- Waived: {metadata.get('waived_count', 0)}",
        f"- Waiver review due: {metadata.get('waiver_review_due_count', 0)}",
        f"- Expired waivers: {metadata.get('expired_waiver_count', 0)}",
        f"- ATT&CK mapped CVEs: {attack_summary.get('mapped_cves', 0)}",
        (
            "- ATT&CK safety: defensive context only; not proof that exploitation occurred "
            "or procedure guidance."
        ),
    ]
    input_sources = metadata.get("input_sources", [])
    if input_sources:
        lines.extend(["", "## Input Sources"])
        for source in input_sources:
            lines.append(
                "- "
                + f"`{source.get('input_path', 'N.A.')}` "
                + f"({source.get('input_format', 'N.A.')}, rows={source.get('total_rows', 0)}, "
                + f"occurrences={source.get('occurrence_count', 0)}, "
                + f"unique_cves={source.get('unique_cves', 0)})"
            )
        lines.append("")
    threat_context_findings = [
        finding
        for finding in findings
        if isinstance(finding, dict)
        and finding.get("attack_mapped")
        and finding.get("attack_relevance") in {"High", "Medium"}
        and finding.get("priority_label") != "Low"
    ]
    if threat_context_findings:
        lines.extend(
            [
                "",
                "## Threat-Informed Context",
                (
                    "ATT&CK context is shown separately from base priority and uses only "
                    "approved mapping sources."
                ),
            ]
        )
        technique_distribution = attack_summary.get("technique_distribution", {})
        if isinstance(technique_distribution, dict) and technique_distribution:
            for technique_id, count in sorted(
                technique_distribution.items(),
                key=lambda item: (-int(item[1]), str(item[0])),
            )[:5]:
                lines.append(f"- {technique_id}: {count} mapped finding(s)")
    governance_lines = _governance_summary_lines(metadata, findings)
    if governance_lines:
        lines.extend(["", "## Governance", *governance_lines])
    detection_lines = _detection_coverage_summary_lines(report_payload.get("detection_coverage"))
    if detection_lines:
        lines.extend(["", "## Detection Coverage", *detection_lines])
    comparison_lines = _baseline_comparison_summary_lines(report_payload)
    if comparison_lines:
        lines.extend(["", "## CVSS-only Baseline Comparison", *comparison_lines])
    lines.extend(["", "## Top Findings"])
    if findings:
        top_findings = findings[:5]
        for finding in top_findings:
            lines.append(
                "- "
                + f"{finding.get('cve_id', 'N.A.')} — "
                + _priority_display_label(
                    str(finding.get("priority_label", "N.A.")),
                    bool(finding.get("in_kev")),
                    bool(finding.get("waived")),
                    str(finding.get("waiver_status")) if finding.get("waiver_status") else None,
                )
                + ": "
                + normalize_whitespace(str(finding.get("rationale", "N.A.")))
                + " Decision: "
                + normalize_whitespace(_finding_decision_statement(finding))
                + " SLA: "
                + normalize_whitespace(_finding_sla_label(finding))
            )
    else:
        lines.append("- No findings matched the current filters.")
    return "\n".join(lines) + "\n"


def _baseline_comparison_summary_lines(report_payload: dict[str, Any]) -> list[str]:
    comparison = report_payload.get("baseline_comparison")
    if not isinstance(comparison, dict):
        return []
    raw_summary = comparison.get("summary")
    summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
    raw_methodology = comparison.get("methodology")
    methodology: dict[str, Any] = raw_methodology if isinstance(raw_methodology, dict) else {}
    lines = [
        f"- Changed rows: {summary.get('changed', 0)}",
        f"- Up: {summary.get('up', 0)}",
        f"- Down: {summary.get('down', 0)}",
        f"- Unchanged: {summary.get('unchanged', 0)}",
    ]
    limitation = methodology.get("limitations")
    if limitation:
        lines.append("- Method limit: " + normalize_whitespace(str(limitation)))
    top_changes = comparison.get("top_changes")
    if isinstance(top_changes, list) and top_changes:
        lines.extend(["", "### Top Baseline Changes"])
        for item in top_changes[:5]:
            if not isinstance(item, dict):
                continue
            lines.append(
                "- "
                + f"{item.get('cve_id', 'N.A.')}: "
                + f"{item.get('old_priority', 'N.A.')} "
                + f"(rank {item.get('old_rank', 'N.A.')}) -> "
                + f"{item.get('new_priority', 'N.A.')} "
                + f"(rank {item.get('new_rank', 'N.A.')}); "
                + normalize_whitespace(str(item.get("reason", "N.A.")))
            )
    return lines


def _finding_decision_statement(finding: dict[str, Any]) -> str:
    guidance = finding.get("decision_guidance")
    if isinstance(guidance, dict):
        statement = guidance.get("decision_statement")
        if statement:
            return str(statement)
    return str(finding.get("recommended_action", "N.A."))


def _finding_sla_label(finding: dict[str, Any]) -> str:
    guidance = finding.get("decision_guidance")
    if isinstance(guidance, dict):
        sla = guidance.get("sla")
        if isinstance(sla, dict):
            label = str(sla.get("label") or "N.A.")
            target_days = sla.get("target_days")
            target_hours = sla.get("target_hours")
            if isinstance(target_hours, int) and target_hours <= 48:
                return f"{label} ({target_hours}h)"
            if isinstance(target_days, int):
                return f"{label} ({target_days}d)"
            return label
    return "N.A."


def _governance_summary_lines(metadata: dict[str, Any], findings: list[Any]) -> list[str]:
    lines: list[str] = []
    suppressed = int(metadata.get("suppressed_by_vex", 0) or 0)
    under_investigation = int(metadata.get("under_investigation_count", 0) or 0)
    waived = int(metadata.get("waived_count", 0) or 0)
    review_due = int(metadata.get("waiver_review_due_count", 0) or 0)
    expired = int(metadata.get("expired_waiver_count", 0) or 0)
    if any((suppressed, under_investigation, waived, review_due, expired)):
        lines.extend(
            [
                f"- Suppressed by VEX: {suppressed}",
                f"- Under VEX investigation: {under_investigation}",
                f"- Waived findings: {waived}",
                f"- Waiver review due: {review_due}",
                f"- Expired waivers: {expired}",
            ]
        )
    owners, services = _owner_service_counters(findings)
    if owners:
        lines.append("- Top owners: " + _counter_preview(owners))
    if services:
        lines.append("- Top services: " + _counter_preview(services))
    return lines


def _detection_coverage_summary_lines(value: object) -> list[str]:
    if not isinstance(value, dict):
        return []
    raw_summary = value.get("summary")
    summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
    items = [item for item in value.get("items", []) if isinstance(item, dict)]
    weak_items = [
        item
        for item in items
        if str(item.get("coverage_level")) in {"partial", "not_covered", "unknown"}
    ]
    if not items and not weak_items:
        return []
    lines = [
        f"- Covered techniques: {int(summary.get('covered', 0) or 0)}",
        f"- Partial coverage: {int(summary.get('partial', 0) or 0)}",
        f"- No coverage: {int(summary.get('not_covered', 0) or 0)}",
        f"- Unknown coverage: {int(summary.get('unknown', 0) or 0)}",
        (
            "- Safety note: detection coverage is operator-supplied defensive review "
            "evidence, not proof of security or exploitation."
        ),
    ]
    if weak_items:
        lines.extend(["", "### Coverage Gaps"])
        for item in weak_items[:5]:
            lines.append(
                "- "
                + f"{item.get('technique_id', 'N.A.')} "
                + f"({item.get('coverage_level', 'unknown')}): "
                + normalize_whitespace(str(item.get("recommended_action", "Review coverage.")))
            )
    return lines


def _owner_service_counters(findings: list[Any]) -> tuple[Counter[str], Counter[str]]:
    owners: Counter[str] = Counter()
    services: Counter[str] = Counter()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        provenance = finding.get("provenance")
        occurrences = provenance.get("occurrences") if isinstance(provenance, dict) else None
        if not isinstance(occurrences, list):
            continue
        for occurrence in occurrences:
            if not isinstance(occurrence, dict):
                continue
            owner = occurrence.get("asset_owner")
            service = occurrence.get("asset_business_service")
            if owner:
                owners[str(owner)] += 1
            if service:
                services[str(service)] += 1
    return owners, services


def _counter_preview(counter: Counter[str], *, limit: int = 5) -> str:
    return ", ".join(f"{name} ({count})" for name, count in counter.most_common(limit))


def generate_compact_summary_markdown(report_payload: dict[str, Any]) -> str:
    """Render a compact Markdown summary suitable for GitHub step summaries."""
    metadata = report_payload.get("metadata", {})
    attack_summary = report_payload.get("attack_summary", {})
    findings = report_payload.get("findings", [])
    counts_by_priority = metadata.get("counts_by_priority", {})
    metrics = [
        str(metadata.get("findings_count", 0)),
        str(counts_by_priority.get("Critical", 0)),
        str(counts_by_priority.get("High", 0)),
        str(metadata.get("kev_hits", 0)),
        str(attack_summary.get("mapped_cves", 0)),
        str(metadata.get("waiver_review_due_count", 0)),
        str(metadata.get("expired_waiver_count", 0)),
    ]
    lines = [
        "# Vulnerability Prioritization Summary",
        "",
        f"- Input: `{metadata.get('input_path', 'N.A.')}`",
        f"- Input format: `{metadata.get('input_format', 'N.A.')}`",
        f"- Policy profile: `{metadata.get('policy_profile', 'default')}`",
        "",
        " | ".join(
            [
                "| Findings shown",
                "Critical",
                "High",
                "KEV hits",
                "ATT&CK mapped",
                "Review due",
                "Expired waivers |",
            ]
        ),
        "| --- | --- | --- | --- | --- | --- | --- |",
        "| " + " | ".join(metrics) + " |",
    ]
    if findings:
        lines.extend(["", "## Top Findings"])
        for finding in findings[:3]:
            lines.append(
                "- "
                + f"{finding.get('cve_id', 'N.A.')} "
                + "("
                + _priority_display_label(
                    str(finding.get("priority_label", "N.A.")),
                    bool(finding.get("in_kev")),
                    bool(finding.get("waived")),
                    str(finding.get("waiver_status")) if finding.get("waiver_status") else None,
                )
                + ")"
            )
    return "\n".join(lines) + "\n"


def generate_compare_json(
    comparisons: list[ComparisonFinding],
    context: AnalysisContext,
) -> str:
    """Render the JSON comparison export."""
    payload = {
        "metadata": _context_metadata(context),
        "attack_summary": context.attack_summary.model_dump(),
        "comparisons": [row.model_dump() for row in comparisons],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def generate_snapshot_diff_json(
    items: list[SnapshotDiffItem],
    summary: SnapshotDiffSummary,
    metadata: SnapshotDiffMetadata,
) -> str:
    """Render the JSON snapshot diff export."""
    payload = {
        "metadata": metadata.model_dump(),
        "summary": summary.model_dump(),
        "items": [item.model_dump() for item in items],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def generate_rollup_json(
    buckets: list[RollupBucket],
    metadata: RollupMetadata,
) -> str:
    """Render the JSON rollup export."""
    payload = {
        "metadata": metadata.model_dump(),
        "buckets": [bucket.model_dump() for bucket in buckets],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def generate_state_init_json(report: StateInitReport) -> str:
    """Render the JSON state-init export."""
    return json.dumps(report.model_dump(), indent=2, sort_keys=True)


def generate_state_import_json(report: StateImportReport) -> str:
    """Render the JSON state-import export."""
    return json.dumps(report.model_dump(), indent=2, sort_keys=True)


def generate_state_history_json(report: StateHistoryReport) -> str:
    """Render the JSON state-history export."""
    return json.dumps(report.model_dump(), indent=2, sort_keys=True)


def generate_state_waivers_json(report: StateWaiverReport) -> str:
    """Render the JSON state-waivers export."""
    return json.dumps(report.model_dump(), indent=2, sort_keys=True)


def generate_state_top_services_json(report: StateTopServicesReport) -> str:
    """Render the JSON state-top-services export."""
    return json.dumps(report.model_dump(), indent=2, sort_keys=True)


def generate_state_trends_json(report: StateTrendsReport) -> str:
    """Render the JSON state-trends export."""
    return json.dumps(report.model_dump(), indent=2, sort_keys=True)


def generate_state_service_history_json(report: StateServiceHistoryReport) -> str:
    """Render the JSON state-service-history export."""
    return json.dumps(report.model_dump(), indent=2, sort_keys=True)


def generate_doctor_json(report: DoctorReport) -> str:
    """Render the JSON doctor report."""
    return json.dumps(report.model_dump(), indent=2, sort_keys=True)


def generate_evidence_bundle_manifest_json(manifest: EvidenceBundleManifest) -> str:
    """Render the JSON manifest stored inside evidence bundles."""
    return json.dumps(manifest.model_dump(), indent=2, sort_keys=True)


def generate_evidence_bundle_verification_json(
    items: list[EvidenceBundleVerificationItem],
    summary: EvidenceBundleVerificationSummary,
    metadata: EvidenceBundleVerificationMetadata,
) -> str:
    """Render the JSON evidence bundle verification export."""
    payload = {
        "metadata": metadata.model_dump(),
        "summary": summary.model_dump(),
        "items": [item.model_dump() for item in items],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def generate_explain_json(
    finding: PrioritizedFinding,
    nvd: NvdData,
    epss: EpssData,
    kev: KevData,
    attack: AttackData,
    context: AnalysisContext,
    comparison: ComparisonFinding | None = None,
) -> str:
    """Render a single-CVE detailed JSON explanation."""
    payload = {
        "metadata": _context_metadata(context),
        "attack_summary": context.attack_summary.model_dump(),
        "finding": finding.model_dump(),
        "nvd": nvd.model_dump(),
        "epss": epss.model_dump(),
        "kev": kev.model_dump(),
        "attack": attack.model_dump(),
        "comparison": comparison.model_dump() if comparison is not None else None,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def generate_sarif_report(
    findings: list[PrioritizedFinding],
    context: AnalysisContext,
) -> str:
    """Render a SARIF report for analyze output."""
    level_map = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
    }
    results: list[dict[str, Any]] = []
    rules_by_id: dict[str, dict[str, Any]] = {}
    for finding in findings:
        artifact_uri = (
            finding.provenance.affected_paths[0]
            if finding.provenance.affected_paths
            else context.input_path
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
        rule_id = _sarif_rule_id(finding.cve_id)
        rules_by_id.setdefault(rule_id, _sarif_rule(finding, references=references))
        results.append(
            {
                "ruleId": rule_id,
                "level": level_map.get(finding.priority_label, "note"),
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
                "partialFingerprints": {
                    "vuln-prioritizer/v1": _sarif_fingerprint(finding, artifact_uri),
                },
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": artifact_uri}}}],
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


def _sarif_rule_id(cve_id: str) -> str:
    return f"vuln-prioritizer/{cve_id.lower()}"


def _sarif_rule(finding: PrioritizedFinding, *, references: list[str]) -> dict[str, Any]:
    level_map = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
    }
    priority = finding.priority_label
    return {
        "id": _sarif_rule_id(finding.cve_id),
        "name": f"{finding.cve_id} prioritized vulnerability",
        "shortDescription": {"text": f"{finding.cve_id}: {priority} priority."},
        "fullDescription": {
            "text": (
                "Known CVE prioritized from CVSS, EPSS, and CISA KEV with "
                "optional contextual layers such as asset context, VEX, waivers, "
                "remediation, and ATT&CK mapping provenance."
            )
        },
        "defaultConfiguration": {"level": level_map.get(priority, "note")},
        "helpUri": references[0],
        "help": {
            "text": (
                "Review the CVE, provider evidence, affected component or asset, "
                "and recommended remediation action. This tool prioritizes supplied "
                "findings and does not scan systems."
            )
        },
        "properties": {
            "cve": finding.cve_id,
            "priority": priority,
            "precision": "very-high",
            "security-severity": _sarif_security_severity(finding),
            "tags": ["security", "external/cve", f"priority/{priority.lower()}"],
            "references": references,
        },
    }


def _sarif_security_severity(finding: PrioritizedFinding) -> str:
    if finding.cvss_base_score is not None:
        return f"{min(max(finding.cvss_base_score, 0.0), 10.0):.1f}"
    return {
        "Critical": "9.0",
        "High": "7.0",
        "Medium": "5.0",
        "Low": "3.0",
    }.get(finding.priority_label, "0.0")


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


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        normalized = str(value).strip()
        if normalized.startswith(("http://", "https://")) and normalized not in seen:
            seen.add(normalized)
            deduped.append(normalized)
    return deduped


def _sarif_fingerprint(finding: PrioritizedFinding, artifact_uri: str | None) -> str:
    identity = "|".join(
        [
            finding.cve_id,
            artifact_uri or "",
            ",".join(finding.provenance.components),
            ",".join(finding.provenance.asset_ids),
        ]
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()
