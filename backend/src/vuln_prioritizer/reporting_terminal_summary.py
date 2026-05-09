"""Rich summary panel renderer for terminal reports."""

from __future__ import annotations

from pathlib import Path

from rich.panel import Panel

from vuln_prioritizer.models import AnalysisContext
from vuln_prioritizer.reporting_format import _format_distribution


def render_summary_panel(
    context: AnalysisContext,
    *,
    mode: str = "analyze",
    changed_count: int | None = None,
) -> Panel:
    """Render the shared terminal summary panel."""
    lines = [
        f"Schema version: {context.schema_version}",
        f"Total input rows: {context.total_input}",
        f"Valid unique CVEs: {context.valid_input}",
        f"Occurrences: {context.occurrences_count}",
        f"Input format: {context.input_format}",
        f"Merged inputs: {context.merged_input_count}",
        f"Findings shown: {context.findings_count}",
        f"Filtered out: {context.filtered_out_count}",
        f"Locked provider data: {'yes' if context.locked_provider_data else 'no'}",
        f"NVD hits: {context.nvd_hits}/{context.valid_input}",
        f"EPSS hits: {context.epss_hits}/{context.valid_input}",
        f"KEV hits: {context.kev_hits}/{context.valid_input}",
    ]
    if context.defensive_context_sources:
        lines.append(
            "Defensive context: "
            + ", ".join(source.upper() for source in context.defensive_context_sources)
            + f" ({context.defensive_context_hits}/{context.valid_input})"
        )
    if context.attack_enabled:
        lines.extend(
            [
                f"ATT&CK source: {context.attack_source}",
                f"ATT&CK hits: {context.attack_hits}/{context.valid_input}",
                f"Mapped CVEs shown: {context.attack_summary.mapped_cves}",
                f"Unmapped CVEs shown: {context.attack_summary.unmapped_cves}",
            ]
        )
        if context.mapping_framework_version:
            lines.append(f"Mapping version: {context.mapping_framework_version}")
        if context.attack_version:
            lines.append(f"ATT&CK version: {context.attack_version}")
    if context.source_stats:
        lines.append("Source stats: " + _format_distribution(context.source_stats))
    if context.input_sources:
        lines.extend(
            [
                "Input sources: "
                + "; ".join(
                    f"{Path(source.input_path).name} ({source.input_format}, "
                    f"rows={source.total_rows}, unique_cves={source.unique_cves})"
                    for source in context.input_sources
                )
            ]
        )
    if context.duplicate_cve_count:
        lines.append(f"Duplicate CVEs collapsed: {context.duplicate_cve_count}")
    if context.provider_snapshot_file:
        lines.append(f"Provider snapshot: {context.provider_snapshot_file}")
    if context.provider_snapshot_id:
        lines.append(f"Provider snapshot ID: {context.provider_snapshot_id}")
    if context.provider_snapshot_hash:
        lines.append(f"Provider snapshot hash: {context.provider_snapshot_hash}")
    if context.provider_snapshot_sources:
        lines.append("Provider snapshot sources: " + ", ".join(context.provider_snapshot_sources))
    snapshot_generated_at = context.provider_freshness.get("provider_snapshot_generated_at")
    if snapshot_generated_at:
        lines.append(f"Provider snapshot generated at: {snapshot_generated_at}")
    if context.nvd_diagnostics.requested:
        diagnostics = context.nvd_diagnostics
        lines.append(
            "NVD diagnostics: "
            + f"requested={diagnostics.requested}, "
            + f"cache_hits={diagnostics.cache_hits}, "
            + f"network_fetches={diagnostics.network_fetches}, "
            + f"failures={diagnostics.failures}, "
            + f"content_hits={diagnostics.content_hits}, "
            + f"empty_records={diagnostics.empty_records}, "
            + f"stale_cache_hits={diagnostics.stale_cache_hits}"
        )
    if context.provider_degraded:
        lines.append("Provider degraded: yes")
    if context.epss_diagnostics.requested:
        diagnostics = context.epss_diagnostics
        lines.append(
            "EPSS diagnostics: "
            + f"requested={diagnostics.requested}, "
            + f"cache_hits={diagnostics.cache_hits}, "
            + f"network_fetches={diagnostics.network_fetches}, "
            + f"failures={diagnostics.failures}, "
            + f"content_hits={diagnostics.content_hits}, "
            + f"empty_records={diagnostics.empty_records}, "
            + f"stale_cache_hits={diagnostics.stale_cache_hits}"
        )
    if context.kev_diagnostics.requested:
        diagnostics = context.kev_diagnostics
        lines.append(
            "KEV diagnostics: "
            + f"requested={diagnostics.requested}, "
            + f"cache_hits={diagnostics.cache_hits}, "
            + f"network_fetches={diagnostics.network_fetches}, "
            + f"failures={diagnostics.failures}, "
            + f"content_hits={diagnostics.content_hits}, "
            + f"empty_records={diagnostics.empty_records}, "
            + f"stale_cache_hits={diagnostics.stale_cache_hits}"
        )
    if context.suppressed_by_vex:
        lines.append(f"Suppressed by VEX: {context.suppressed_by_vex}")
    if context.under_investigation_count:
        lines.append(f"Under investigation: {context.under_investigation_count}")
    if context.asset_match_conflict_count:
        lines.append(f"Asset-context conflicts resolved: {context.asset_match_conflict_count}")
    if context.vex_conflict_count:
        lines.append(f"VEX conflicts resolved: {context.vex_conflict_count}")
    if context.waived_count:
        lines.append(f"Waived: {context.waived_count}")
    if context.waiver_review_due_count:
        lines.append(f"Waiver review due: {context.waiver_review_due_count}")
    if context.expired_waiver_count:
        lines.append(f"Expired waivers: {context.expired_waiver_count}")

    if mode == "compare" and changed_count is not None:
        unchanged_count = max(context.findings_count - changed_count, 0)
        lines.extend(
            [
                f"Changed rows: {changed_count}",
                f"Unchanged rows: {unchanged_count}",
            ]
        )

    for label in ("Critical", "High", "Medium", "Low"):
        lines.append(f"{label}: {context.counts_by_priority.get(label, 0)}")

    if context.active_filters:
        lines.append("Active filters: " + ", ".join(context.active_filters))
    if context.policy_overrides:
        lines.append("Policy overrides: " + ", ".join(context.policy_overrides))

    return Panel("\n".join(lines), title="Summary")


__all__ = ["render_summary_panel"]
