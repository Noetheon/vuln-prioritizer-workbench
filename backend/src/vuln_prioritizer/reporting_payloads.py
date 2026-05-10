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
    StateServiceHistoryReport,
    StateTopServicesReport,
    StateTrendsReport,
    StateWaiverReport,
)
from vuln_prioritizer.reporting_payloads_sarif import (
    generate_sarif_report as generate_sarif_report,
)
from vuln_prioritizer.reporting_payloads_summary import (
    generate_compact_summary_markdown as generate_compact_summary_markdown,
)
from vuln_prioritizer.reporting_payloads_summary import (
    generate_summary_markdown as generate_summary_markdown,
)
from vuln_prioritizer.services.baseline_comparison import (
    build_cvss_baseline_comparison_payload,
)

__all__ = [
    "build_analysis_report_payload",
    "build_snapshot_report_payload",
    "generate_compare_json",
    "generate_compact_summary_markdown",
    "generate_doctor_json",
    "generate_evidence_bundle_manifest_json",
    "generate_evidence_bundle_verification_json",
    "generate_explain_json",
    "generate_json_report",
    "generate_rollup_json",
    "generate_sarif_report",
    "generate_snapshot_diff_json",
    "generate_state_history_json",
    "generate_state_import_json",
    "generate_state_init_json",
    "generate_state_service_history_json",
    "generate_state_top_services_json",
    "generate_state_trends_json",
    "generate_state_waivers_json",
    "generate_summary_markdown",
]


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
