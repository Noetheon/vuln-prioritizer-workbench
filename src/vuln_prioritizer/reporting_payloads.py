"""Payload and serialization helpers for report exports."""

from __future__ import annotations

import json
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
    StateTopServicesReport,
    StateWaiverReport,
)
from vuln_prioritizer.reporting_format import _priority_display_label, normalize_whitespace


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
        "metadata": context.model_dump(exclude={"attack_summary"}),
        "attack_summary": context.attack_summary.model_dump(),
        "findings": [finding.model_dump() for finding in findings],
    }


def build_snapshot_report_payload(
    findings: list[PrioritizedFinding],
    metadata: SnapshotMetadata,
) -> dict[str, Any]:
    """Build the canonical snapshot payload."""
    return {
        "metadata": metadata.model_dump(exclude={"attack_summary"}),
        "attack_summary": metadata.attack_summary.model_dump(),
        "findings": [finding.model_dump() for finding in findings],
    }


def generate_summary_markdown(report_payload: dict[str, Any]) -> str:
    """Render a short executive Markdown summary from an analysis-style payload."""
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
                + " Next action: "
                + normalize_whitespace(str(finding.get("recommended_action", "N.A.")))
            )
    else:
        lines.append("- No findings matched the current filters.")
    return "\n".join(lines) + "\n"


def generate_compare_json(
    comparisons: list[ComparisonFinding],
    context: AnalysisContext,
) -> str:
    """Render the JSON comparison export."""
    payload = {
        "metadata": context.model_dump(exclude={"attack_summary"}),
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
        "metadata": context.model_dump(exclude={"attack_summary"}),
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
    for finding in findings:
        message = (
            f"{finding.cve_id}: {finding.priority_label} priority "
            "based on CVSS/EPSS/KEV with contextual enrichment."
        )
        results.append(
            {
                "ruleId": f"vuln-prioritizer/{finding.priority_label.lower()}",
                "level": level_map.get(finding.priority_label, "note"),
                "message": {"text": message},
                "properties": {
                    "cve": finding.cve_id,
                    "priority": finding.priority_label,
                    "cvss": finding.cvss_base_score,
                    "epss": finding.epss,
                    "in_kev": finding.in_kev,
                    "attack_relevance": finding.attack_relevance,
                    "sources": finding.provenance.source_formats,
                    "components": finding.provenance.components,
                    "suppressed_by_vex": finding.suppressed_by_vex,
                    "under_investigation": finding.under_investigation,
                    "remediation_strategy": finding.remediation.strategy,
                    "remediation_ecosystem": finding.remediation.ecosystem,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.provenance.affected_paths[0]
                                if finding.provenance.affected_paths
                                else context.input_path
                            }
                        }
                    }
                ],
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
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
