"""Shared formatting helpers for report rendering."""

from __future__ import annotations

from vuln_prioritizer.models import (
    AnalysisContext,
    AttackMapping,
    AttackSummary,
    PrioritizedFinding,
    RollupBucket,
    RollupCandidate,
)


def format_score(value: float | None, digits: int) -> str:
    """Format numeric output or return N.A."""
    if value is None:
        return "N.A."
    return f"{value:.{digits}f}"


def format_change(delta_rank: int) -> str:
    """Render the comparison delta for terminal and Markdown output."""
    if delta_rank > 0:
        return f"Up {delta_rank}"
    if delta_rank < 0:
        return f"Down {abs(delta_rank)}"
    return "No change"


def truncate_text(value: str, limit: int) -> str:
    """Keep long descriptions compact in the terminal view."""
    value = normalize_whitespace(value)
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def escape_pipes(value: str) -> str:
    """Escape Markdown table separators."""
    return normalize_whitespace(value).replace("|", "\\|").strip()


def normalize_whitespace(value: str) -> str:
    """Flatten multi-line values for console and Markdown rendering."""
    return " ".join(value.replace("\r", " ").replace("\n", " ").split())


def comma_or_na(values: list[str]) -> str:
    """Render lists consistently."""
    return ", ".join(values) if values else "N.A."


def format_filters(active_filters: list[str]) -> str:
    """Render filters consistently across Markdown and terminal output."""
    return ", ".join(active_filters) if active_filters else "None"


def _run_metadata_lines(context: AnalysisContext) -> list[str]:
    lines = [
        f"- Generated at: `{context.generated_at}`",
        f"- Input file: `{context.input_path}`",
        f"- Output format: `{context.output_format}`",
        f"- ATT&CK context enabled: `{'yes' if context.attack_enabled else 'no'}`",
        f"- ATT&CK source: `{context.attack_source}`",
        f"- Cache enabled: `{'yes' if context.cache_enabled else 'no'}`",
    ]
    if context.output_path:
        lines.append(f"- Output path: `{context.output_path}`")
    if context.provider_snapshot_file:
        lines.append(f"- Provider snapshot file: `{context.provider_snapshot_file}`")
        snapshot_mode = "locked" if context.locked_provider_data else "fallback"
        lines.append(f"- Provider snapshot mode: `{snapshot_mode}`")
    if context.provider_snapshot_sources:
        lines.append(
            "- Provider snapshot sources: " + f"`{', '.join(context.provider_snapshot_sources)}`"
        )
    if context.merged_input_count > 1:
        lines.append(f"- Inputs merged: `{context.merged_input_count}`")
    if context.input_paths:
        lines.append(f"- Input files: `{', '.join(context.input_paths)}`")
    for source in context.input_sources:
        lines.append(
            "- Source input: "
            + f"`{source.input_path}` "
            + f"({source.input_format}, rows={source.total_rows}, "
            + f"occurrences={source.occurrence_count}, unique_cves={source.unique_cves})"
        )
    if context.duplicate_cve_count:
        lines.append(f"- Duplicate CVEs collapsed: `{context.duplicate_cve_count}`")
    if context.asset_match_conflict_count:
        lines.append(f"- Asset-context conflicts resolved: `{context.asset_match_conflict_count}`")
    if context.vex_conflict_count:
        lines.append(f"- VEX conflicts resolved: `{context.vex_conflict_count}`")
    if context.cache_dir:
        lines.append(f"- Cache directory: `{context.cache_dir}`")
    if context.nvd_diagnostics.requested:
        diagnostics = context.nvd_diagnostics
        lines.append(
            "- NVD diagnostics: "
            + f"`requested={diagnostics.requested}, "
            + f"cache_hits={diagnostics.cache_hits}, "
            + f"network_fetches={diagnostics.network_fetches}, "
            + f"failures={diagnostics.failures}, "
            + f"content_hits={diagnostics.content_hits}`"
        )
    if context.attack_mapping_file:
        lines.append(f"- ATT&CK mapping file: `{context.attack_mapping_file}`")
    if context.attack_technique_metadata_file:
        lines.append(
            f"- ATT&CK technique metadata file: `{context.attack_technique_metadata_file}`"
        )
    if context.mapping_framework:
        lines.append(f"- ATT&CK mapping framework: `{context.mapping_framework}`")
    if context.mapping_framework_version:
        lines.append(f"- ATT&CK mapping framework version: `{context.mapping_framework_version}`")
    if context.attack_version:
        lines.append(f"- ATT&CK version: `{context.attack_version}`")
    if context.attack_domain:
        lines.append(f"- ATT&CK domain: `{context.attack_domain}`")
    if context.waiver_file:
        lines.append(f"- Waiver file: `{context.waiver_file}`")
    lines.append(f"- Policy overrides: `{format_filters(context.policy_overrides)}`")
    return lines


def _summary_lines(context: AnalysisContext) -> list[str]:
    lines = [
        f"- Total input rows: {context.total_input}",
        f"- Valid unique CVEs: {context.valid_input}",
        f"- Merged inputs: {context.merged_input_count}",
        f"- Findings shown: {context.findings_count}",
        f"- Filtered out: {context.filtered_out_count}",
        f"- Locked provider data: {'yes' if context.locked_provider_data else 'no'}",
        f"- NVD hits: {context.nvd_hits}/{context.valid_input}",
        f"- EPSS hits: {context.epss_hits}/{context.valid_input}",
        f"- KEV hits: {context.kev_hits}/{context.valid_input}",
        f"- ATT&CK hits: {context.attack_hits}/{context.valid_input}",
        f"- Duplicate CVEs collapsed: {context.duplicate_cve_count}",
        f"- Asset-context conflicts resolved: {context.asset_match_conflict_count}",
        f"- VEX conflicts resolved: {context.vex_conflict_count}",
        f"- Waived: {context.waived_count}",
        f"- Waiver review due: {context.waiver_review_due_count}",
        f"- Expired waivers: {context.expired_waiver_count}",
    ]
    for label in ("Critical", "High", "Medium", "Low"):
        lines.append(f"- {label}: {context.counts_by_priority.get(label, 0)}")
    lines.append(f"- Active filters: {format_filters(context.active_filters)}")
    return lines


def _attack_methodology_lines(context: AnalysisContext) -> list[str]:
    if not context.attack_enabled:
        return ["- ATT&CK context was disabled for this run."]
    return [
        "- ATT&CK context is sourced from explicit local files only.",
        "- No heuristic or LLM-generated CVE-to-ATT&CK mapping is performed.",
        "- ATT&CK relevance is reported separately and does not change the primary priority score.",
    ]


def _attack_summary_lines(summary: AttackSummary, enabled: bool) -> list[str]:
    if not enabled:
        return ["ATT&CK context was disabled for this export."]

    lines = [
        f"- CVEs with ATT&CK mappings: {summary.mapped_cves}",
        f"- Unmapped CVEs: {summary.unmapped_cves}",
        "- Mapping type distribution: " + _format_distribution(summary.mapping_type_distribution),
        "- Technique distribution: " + _format_distribution(summary.technique_distribution),
        "- Tactic distribution: " + _format_distribution(summary.tactic_distribution),
        "- ATT&CK mappings are imported from explicit local CTID or local CSV files only.",
    ]
    return lines


def _warning_lines(warnings: list[str]) -> list[str]:
    if warnings:
        return [f"- {warning}" for warning in warnings]
    return ["- None"]


def _format_distribution(distribution: dict[str, int]) -> str:
    if not distribution:
        return "None"
    return ", ".join(
        f"{key}: {value}"
        for key, value in sorted(distribution.items(), key=lambda item: (-item[1], item[0]))
    )


def _format_attack_indicator(mapped: bool, technique_count: int) -> str:
    if not mapped:
        return "Unmapped"
    return f"{technique_count} technique(s)"


def _format_priority_indicator(
    priority_label: str,
    suppressed_by_vex: bool,
    *,
    in_kev: bool,
    waived: bool = False,
    waiver_status: str | None = None,
) -> str:
    parts: list[str] = []
    if in_kev:
        parts.append("KEV")
    if suppressed_by_vex:
        parts.append("suppressed")
    if waiver_status == "expired":
        parts.append("waiver expired")
    elif waiver_status == "review_due":
        parts.append("waiver review due")
    elif waived:
        parts.append("waived")
    if not parts:
        return priority_label
    return f"{priority_label} ({', '.join(parts)})"


def _priority_display_label(
    priority_label: str,
    in_kev: bool,
    waived: bool = False,
    waiver_status: str | None = None,
) -> str:
    parts = [priority_label]
    if in_kev:
        parts.append("KEV")
    if waiver_status == "expired":
        parts.append("Waiver Expired")
    elif waiver_status == "review_due":
        parts.append("Waiver Review Due")
    elif waived:
        parts.append("Waived")
    return " / ".join(parts)


def _format_exploit_status(in_kev: bool) -> str:
    if in_kev:
        return "Known exploited (KEV)"
    return "No KEV listing"


def _format_vex_statuses(vex_statuses: dict[str, int]) -> str:
    if not vex_statuses:
        return "N.A."
    return _format_distribution(vex_statuses)


def _format_waiver_status(finding: PrioritizedFinding) -> str:
    if not finding.waived and not finding.waiver_status:
        return "N.A."
    details = [
        f"status={finding.waiver_status or ('active' if finding.waived else 'N.A.')}",
        f"owner={finding.waiver_owner or 'N.A.'}",
        f"expires={finding.waiver_expires_on or 'N.A.'}",
    ]
    if finding.waiver_review_on:
        details.append(f"review_on={finding.waiver_review_on}")
    if finding.waiver_days_remaining is not None:
        details.append(f"days_remaining={finding.waiver_days_remaining}")
    if finding.waiver_scope:
        details.append(f"scope={finding.waiver_scope}")
    return ", ".join(details)


def _mapping_types(mappings: list[AttackMapping]) -> list[str]:
    values: list[str] = []
    for mapping in mappings:
        if mapping.mapping_type and mapping.mapping_type not in values:
            values.append(mapping.mapping_type)
    return values


def _capability_groups(mappings: list[AttackMapping]) -> list[str]:
    values: list[str] = []
    for mapping in mappings:
        if mapping.capability_group and mapping.capability_group not in values:
            values.append(mapping.capability_group)
    return values


def _format_rollup_candidates(candidates: list[RollupCandidate]) -> str:
    if not candidates:
        return "N.A."
    return "; ".join(f"{candidate.cve_id} ({candidate.rank_reason})" for candidate in candidates)


def _format_rollup_reason(bucket: RollupBucket) -> str:
    if bucket.actionable_count == 0:
        base = "All findings waived"
    else:
        parts = [bucket.highest_priority]
        if bucket.kev_count:
            parts.append("KEV")
        if bucket.internet_facing_count:
            parts.append("internet-facing")
        if bucket.production_count:
            parts.append("prod")
        if bucket.waived_count:
            parts.append(f"{bucket.waived_count} waived")
        base = " + ".join(parts)

    if not bucket.context_hints:
        return base
    return base + " (" + ", ".join(bucket.context_hints) + ")"


def _format_state_waiver_status(waived: bool, waiver_status: str | None) -> str:
    if not waived and waiver_status is None:
        return "No"
    return waiver_status or "active"
