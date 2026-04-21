"""Typer-based command line interface."""

from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from collections.abc import MutableMapping
from enum import Enum
from pathlib import Path
from typing import cast

import requests
import typer
from dotenv import load_dotenv
from pydantic import ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.config import (
    DATA_SOURCES,
    DEFAULT_CACHE_DIR,
    DEFAULT_CACHE_TTL_HOURS,
    DEFAULT_NVD_API_KEY_ENV,
    EPSS_API_URL,
    KEV_FEED_URL,
    KEV_MIRROR_URL,
    NVD_API_URL,
)
from vuln_prioritizer.inputs import (
    InputLoader,
    build_inline_input,
    load_asset_context_file,
    load_vex_files,
)
from vuln_prioritizer.models import (
    AnalysisContext,
    AssetContextRecord,
    AttackData,
    AttackSummary,
    ContextPolicyProfile,
    DoctorCheck,
    DoctorReport,
    EnrichmentResult,
    EpssData,
    EvidenceBundleFile,
    EvidenceBundleManifest,
    KevData,
    NvdData,
    ParsedInput,
    PrioritizedFinding,
    PriorityPolicy,
    RollupBucket,
    RollupMetadata,
    SnapshotDiffItem,
    SnapshotDiffMetadata,
    SnapshotDiffSummary,
    SnapshotMetadata,
    VexStatement,
    WaiverRule,
)
from vuln_prioritizer.providers.attack import AttackProvider
from vuln_prioritizer.providers.attack_metadata import AttackMetadataProvider
from vuln_prioritizer.providers.ctid_mappings import CtidMappingsProvider
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider
from vuln_prioritizer.reporter import (
    build_analysis_report_payload,
    build_snapshot_report_payload,
    generate_compare_json,
    generate_compare_markdown,
    generate_doctor_json,
    generate_evidence_bundle_manifest_json,
    generate_explain_json,
    generate_explain_markdown,
    generate_html_report,
    generate_json_report,
    generate_markdown_report,
    generate_rollup_json,
    generate_rollup_markdown,
    generate_sarif_report,
    generate_snapshot_diff_json,
    generate_snapshot_diff_markdown,
    generate_summary_markdown,
    render_compare_table,
    render_explain_view,
    render_findings_table,
    render_rollup_table,
    render_snapshot_diff_table,
    render_summary_panel,
    write_output,
)
from vuln_prioritizer.runtime_config import (
    LoadedRuntimeConfig,
    build_cli_default_map,
    collect_referenced_files,
    discover_runtime_config,
    load_runtime_config,
)
from vuln_prioritizer.services.attack_enrichment import AttackEnrichmentService
from vuln_prioritizer.services.contextualization import (
    aggregate_provenance,
    load_context_profile,
)
from vuln_prioritizer.services.enrichment import EnrichmentService
from vuln_prioritizer.services.prioritization import PrioritizationService
from vuln_prioritizer.services.waivers import apply_waivers, load_waiver_rules
from vuln_prioritizer.utils import iso_utc_now, normalize_cve_id

app = typer.Typer(help="Prioritize known CVEs with NVD, EPSS, KEV, and ATT&CK context.")
attack_app = typer.Typer(help="Validate and summarize local ATT&CK mapping files.")
data_app = typer.Typer(help="Inspect cache state and local data-source metadata.")
report_app = typer.Typer(help="Render secondary report formats from exported analysis JSON.")
snapshot_app = typer.Typer(help="Create and compare prioritized snapshots.")
app.add_typer(attack_app, name="attack")
app.add_typer(data_app, name="data")
app.add_typer(report_app, name="report")
app.add_typer(snapshot_app, name="snapshot")
console = Console()


class OutputFormat(str, Enum):
    markdown = "markdown"
    json = "json"
    sarif = "sarif"
    table = "table"


class PriorityFilter(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class SortBy(str, Enum):
    priority = "priority"
    epss = "epss"
    cvss = "cvss"
    cve = "cve"


class AttackSource(str, Enum):
    none = "none"
    local_csv = "local-csv"
    ctid_json = "ctid-json"


class InputFormat(str, Enum):
    auto = "auto"
    cve_list = "cve-list"
    trivy_json = "trivy-json"
    grype_json = "grype-json"
    cyclonedx_json = "cyclonedx-json"
    spdx_json = "spdx-json"
    dependency_check_json = "dependency-check-json"
    github_alerts_json = "github-alerts-json"
    nessus_xml = "nessus-xml"
    openvas_xml = "openvas-xml"


class PolicyProfile(str, Enum):
    default = "default"
    enterprise = "enterprise"
    conservative = "conservative"


class DataSourceName(str, Enum):
    all = "all"
    nvd = "nvd"
    epss = "epss"
    kev = "kev"


class TargetKind(str, Enum):
    generic = "generic"
    image = "image"
    repository = "repository"
    filesystem = "filesystem"
    host = "host"


class RollupBy(str, Enum):
    asset = "asset"
    service = "service"


PRIORITY_LABELS = {
    PriorityFilter.critical: "Critical",
    PriorityFilter.high: "High",
    PriorityFilter.medium: "Medium",
    PriorityFilter.low: "Low",
}


@app.callback()
def callback(
    ctx: typer.Context,
    config: Path | None = typer.Option(None, "--config", dir_okay=False, readable=True),
    no_config: bool = typer.Option(False, "--no-config"),
) -> None:
    """CLI entrypoint."""
    if config is not None and no_config:
        console.print(
            "[red]Input validation failed:[/red] --config and --no-config cannot be combined."
        )
        raise typer.Exit(code=2)

    loaded = _load_runtime_config_for_session(config=config, no_config=no_config)
    ctx.obj = {"runtime_config": loaded}
    if loaded is not None:
        ctx.default_map = _merge_default_maps(ctx.default_map, build_cli_default_map(loaded))


@app.command()
def analyze(
    ctx: typer.Context,
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    html_output: Path | None = typer.Option(None, "--html-output", dir_okay=False),
    summary_output: Path | None = typer.Option(None, "--summary-output", dir_okay=False),
    format: OutputFormat = typer.Option(OutputFormat.markdown, "--format"),
    input_format: InputFormat = typer.Option(InputFormat.auto, "--input-format"),
    no_attack: bool = typer.Option(False, "--no-attack"),
    attack_source: AttackSource = typer.Option(AttackSource.none, "--attack-source"),
    attack_mapping_file: Path | None = typer.Option(None, "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
    priority: list[PriorityFilter] | None = typer.Option(None, "--priority"),
    kev_only: bool = typer.Option(False, "--kev-only"),
    min_cvss: float | None = typer.Option(None, "--min-cvss", min=0.0, max=10.0),
    min_epss: float | None = typer.Option(None, "--min-epss", min=0.0, max=1.0),
    sort_by: SortBy = typer.Option(SortBy.priority, "--sort-by"),
    critical_epss_threshold: float = typer.Option(0.70, "--critical-epss-threshold"),
    critical_cvss_threshold: float = typer.Option(7.0, "--critical-cvss-threshold"),
    high_epss_threshold: float = typer.Option(0.40, "--high-epss-threshold"),
    high_cvss_threshold: float = typer.Option(9.0, "--high-cvss-threshold"),
    medium_epss_threshold: float = typer.Option(0.10, "--medium-epss-threshold"),
    medium_cvss_threshold: float = typer.Option(7.0, "--medium-cvss-threshold"),
    policy_profile: str = typer.Option(PolicyProfile.default.value, "--policy-profile"),
    policy_file: Path | None = typer.Option(None, "--policy-file", dir_okay=False),
    waiver_file: Path | None = typer.Option(None, "--waiver-file", dir_okay=False),
    asset_context: Path | None = typer.Option(None, "--asset-context", dir_okay=False),
    target_kind: TargetKind = typer.Option(TargetKind.generic, "--target-kind"),
    target_ref: str | None = typer.Option(None, "--target-ref"),
    vex_file: list[Path] | None = typer.Option(None, "--vex-file", dir_okay=False),
    show_suppressed: bool = typer.Option(False, "--show-suppressed"),
    hide_waived: bool = typer.Option(False, "--hide-waived"),
    fail_on: PriorityFilter | None = typer.Option(None, "--fail-on"),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    offline_attack_file: Path | None = typer.Option(None, "--offline-attack-file", dir_okay=False),
    nvd_api_key_env: str = typer.Option(DEFAULT_NVD_API_KEY_ENV, "--nvd-api-key-env"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
) -> None:
    """Analyze a CVE list and produce a prioritized terminal view and optional report."""
    load_dotenv()
    _validate_output_mode(format, output)
    _validate_unique_output_paths(
        {
            "--output": output,
            "--html-output": html_output,
            "--summary-output": summary_output,
        }
    )
    _validate_command_formats(
        command_name="analyze",
        format=format,
        allowed_formats={
            OutputFormat.markdown,
            OutputFormat.json,
            OutputFormat.sarif,
            OutputFormat.table,
        },
    )

    findings, context = _prepare_analysis(
        input_path=input,
        output=output,
        format=format,
        input_format=input_format,
        no_attack=no_attack,
        attack_source=attack_source,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
        offline_attack_file=offline_attack_file,
        priority_filters=priority,
        kev_only=kev_only,
        min_cvss=min_cvss,
        min_epss=min_epss,
        sort_by=sort_by,
        policy=_build_priority_policy(
            critical_epss_threshold=critical_epss_threshold,
            critical_cvss_threshold=critical_cvss_threshold,
            high_epss_threshold=high_epss_threshold,
            high_cvss_threshold=high_cvss_threshold,
            medium_epss_threshold=medium_epss_threshold,
            medium_cvss_threshold=medium_cvss_threshold,
        ),
        policy_profile=policy_profile,
        policy_file=policy_file,
        waiver_file=waiver_file,
        asset_context=asset_context,
        target_kind=target_kind.value,
        target_ref=target_ref,
        vex_files=vex_file or [],
        show_suppressed=show_suppressed,
        hide_waived=hide_waived,
        max_cves=max_cves,
        offline_kev_file=offline_kev_file,
        nvd_api_key_env=nvd_api_key_env,
        no_cache=no_cache,
        cache_dir=cache_dir,
        cache_ttl_hours=cache_ttl_hours,
    )

    console.print(render_findings_table(findings))
    console.print(render_summary_panel(context))
    _print_warnings(context.warnings)

    if output is not None:
        if format == OutputFormat.markdown:
            write_output(output, generate_markdown_report(findings, context))
        elif format == OutputFormat.json:
            write_output(output, generate_json_report(findings, context))
        elif format == OutputFormat.sarif:
            write_output(output, generate_sarif_report(findings, context))
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")
    if html_output is not None:
        write_output(
            html_output, generate_html_report(build_analysis_report_payload(findings, context))
        )
        console.print(f"[green]Wrote html output to {html_output}[/green]")
    if summary_output is not None:
        write_output(
            summary_output,
            generate_summary_markdown(build_analysis_report_payload(findings, context)),
        )
        console.print(f"[green]Wrote markdown summary to {summary_output}[/green]")
    if fail_on is not None:
        _handle_fail_on(findings, fail_on)


@app.command()
def compare(
    ctx: typer.Context,
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: OutputFormat = typer.Option(OutputFormat.markdown, "--format"),
    input_format: InputFormat = typer.Option(InputFormat.auto, "--input-format"),
    no_attack: bool = typer.Option(False, "--no-attack"),
    attack_source: AttackSource = typer.Option(AttackSource.none, "--attack-source"),
    attack_mapping_file: Path | None = typer.Option(None, "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
    priority: list[PriorityFilter] | None = typer.Option(None, "--priority"),
    kev_only: bool = typer.Option(False, "--kev-only"),
    min_cvss: float | None = typer.Option(None, "--min-cvss", min=0.0, max=10.0),
    min_epss: float | None = typer.Option(None, "--min-epss", min=0.0, max=1.0),
    sort_by: SortBy = typer.Option(SortBy.priority, "--sort-by"),
    critical_epss_threshold: float = typer.Option(0.70, "--critical-epss-threshold"),
    critical_cvss_threshold: float = typer.Option(7.0, "--critical-cvss-threshold"),
    high_epss_threshold: float = typer.Option(0.40, "--high-epss-threshold"),
    high_cvss_threshold: float = typer.Option(9.0, "--high-cvss-threshold"),
    medium_epss_threshold: float = typer.Option(0.10, "--medium-epss-threshold"),
    medium_cvss_threshold: float = typer.Option(7.0, "--medium-cvss-threshold"),
    policy_profile: str = typer.Option(PolicyProfile.default.value, "--policy-profile"),
    policy_file: Path | None = typer.Option(None, "--policy-file", dir_okay=False),
    waiver_file: Path | None = typer.Option(None, "--waiver-file", dir_okay=False),
    asset_context: Path | None = typer.Option(None, "--asset-context", dir_okay=False),
    target_kind: TargetKind = typer.Option(TargetKind.generic, "--target-kind"),
    target_ref: str | None = typer.Option(None, "--target-ref"),
    vex_file: list[Path] | None = typer.Option(None, "--vex-file", dir_okay=False),
    show_suppressed: bool = typer.Option(False, "--show-suppressed"),
    hide_waived: bool = typer.Option(False, "--hide-waived"),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    offline_attack_file: Path | None = typer.Option(None, "--offline-attack-file", dir_okay=False),
    nvd_api_key_env: str = typer.Option(DEFAULT_NVD_API_KEY_ENV, "--nvd-api-key-env"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
) -> None:
    """Compare a CVSS-only baseline with the enriched prioritization result."""
    load_dotenv()
    _validate_output_mode(format, output)
    _validate_command_formats(
        command_name="compare",
        format=format,
        allowed_formats={OutputFormat.markdown, OutputFormat.json, OutputFormat.table},
    )

    findings, context = _prepare_analysis(
        input_path=input,
        output=output,
        format=format,
        input_format=input_format,
        no_attack=no_attack,
        attack_source=attack_source,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
        offline_attack_file=offline_attack_file,
        priority_filters=priority,
        kev_only=kev_only,
        min_cvss=min_cvss,
        min_epss=min_epss,
        sort_by=sort_by,
        policy=_build_priority_policy(
            critical_epss_threshold=critical_epss_threshold,
            critical_cvss_threshold=critical_cvss_threshold,
            high_epss_threshold=high_epss_threshold,
            high_cvss_threshold=high_cvss_threshold,
            medium_epss_threshold=medium_epss_threshold,
            medium_cvss_threshold=medium_cvss_threshold,
        ),
        policy_profile=policy_profile,
        policy_file=policy_file,
        waiver_file=waiver_file,
        asset_context=asset_context,
        target_kind=target_kind.value,
        target_ref=target_ref,
        vex_files=vex_file or [],
        show_suppressed=show_suppressed,
        hide_waived=hide_waived,
        max_cves=max_cves,
        offline_kev_file=offline_kev_file,
        nvd_api_key_env=nvd_api_key_env,
        no_cache=no_cache,
        cache_dir=cache_dir,
        cache_ttl_hours=cache_ttl_hours,
    )

    prioritizer = PrioritizationService()
    comparisons = prioritizer.build_comparison(findings, sort_by=sort_by.value)
    changed_count = sum(1 for row in comparisons if row.changed)

    console.print(render_compare_table(comparisons))
    console.print(render_summary_panel(context, mode="compare", changed_count=changed_count))
    _print_warnings(context.warnings)

    if output is not None:
        if format == OutputFormat.markdown:
            write_output(output, generate_compare_markdown(comparisons, context))
        elif format == OutputFormat.json:
            write_output(output, generate_compare_json(comparisons, context))
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")


@app.command()
def explain(
    ctx: typer.Context,
    cve: str = typer.Option(..., "--cve"),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: OutputFormat = typer.Option(OutputFormat.table, "--format"),
    no_attack: bool = typer.Option(False, "--no-attack"),
    attack_source: AttackSource = typer.Option(AttackSource.none, "--attack-source"),
    attack_mapping_file: Path | None = typer.Option(None, "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
    critical_epss_threshold: float = typer.Option(0.70, "--critical-epss-threshold"),
    critical_cvss_threshold: float = typer.Option(7.0, "--critical-cvss-threshold"),
    high_epss_threshold: float = typer.Option(0.40, "--high-epss-threshold"),
    high_cvss_threshold: float = typer.Option(9.0, "--high-cvss-threshold"),
    medium_epss_threshold: float = typer.Option(0.10, "--medium-epss-threshold"),
    medium_cvss_threshold: float = typer.Option(7.0, "--medium-cvss-threshold"),
    policy_profile: str = typer.Option(PolicyProfile.default.value, "--policy-profile"),
    policy_file: Path | None = typer.Option(None, "--policy-file", dir_okay=False),
    waiver_file: Path | None = typer.Option(None, "--waiver-file", dir_okay=False),
    asset_context: Path | None = typer.Option(None, "--asset-context", dir_okay=False),
    target_kind: TargetKind = typer.Option(TargetKind.generic, "--target-kind"),
    target_ref: str | None = typer.Option(None, "--target-ref"),
    vex_file: list[Path] | None = typer.Option(None, "--vex-file", dir_okay=False),
    show_suppressed: bool = typer.Option(False, "--show-suppressed"),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    offline_attack_file: Path | None = typer.Option(None, "--offline-attack-file", dir_okay=False),
    nvd_api_key_env: str = typer.Option(DEFAULT_NVD_API_KEY_ENV, "--nvd-api-key-env"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
) -> None:
    """Explain the prioritization result for a single CVE."""
    load_dotenv()
    _validate_output_mode(format, output)
    _validate_command_formats(
        command_name="explain",
        format=format,
        allowed_formats={OutputFormat.markdown, OutputFormat.json, OutputFormat.table},
    )

    normalized_cve = normalize_cve_id(cve)
    if normalized_cve is None:
        console.print(f"[red]Input validation failed:[/red] Invalid CVE identifier: {cve!r}")
        raise typer.Exit(code=2)

    policy = _build_priority_policy(
        critical_epss_threshold=critical_epss_threshold,
        critical_cvss_threshold=critical_cvss_threshold,
        high_epss_threshold=high_epss_threshold,
        high_cvss_threshold=high_cvss_threshold,
        medium_epss_threshold=medium_epss_threshold,
        medium_cvss_threshold=medium_cvss_threshold,
    )
    context_profile = _load_context_profile_or_exit(policy_profile, policy_file)
    attack_enabled, resolved_attack_source, resolved_mapping_file, resolved_metadata_file = (
        _resolve_attack_options(
            no_attack=no_attack,
            attack_source=attack_source,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
            offline_attack_file=offline_attack_file,
        )
    )
    asset_records = _load_asset_records_or_exit(asset_context)
    vex_statements = _load_vex_statements_or_exit(vex_file or [])
    waiver_rules = _load_waiver_rules_or_exit(waiver_file)
    parsed_input = build_inline_input(
        normalized_cve,
        target_kind=target_kind.value,
        target_ref=target_ref,
        asset_records=asset_records,
        vex_statements=vex_statements,
    )
    findings, counts, enrichment = _build_findings(
        parsed_input.unique_cves,
        policy=policy,
        parsed_input=parsed_input,
        context_profile=context_profile,
        attack_enabled=attack_enabled,
        attack_source=resolved_attack_source,
        attack_mapping_file=resolved_mapping_file,
        attack_technique_metadata_file=resolved_metadata_file,
        offline_kev_file=offline_kev_file,
        offline_attack_file=offline_attack_file,
        nvd_api_key_env=nvd_api_key_env,
        no_cache=no_cache,
        cache_dir=cache_dir,
        cache_ttl_hours=cache_ttl_hours,
    )
    findings, waiver_warnings = apply_waivers(findings, waiver_rules)
    if not show_suppressed:
        findings = [finding for finding in findings if not finding.suppressed_by_vex]

    if not findings:
        console.print("[red]No finding could be generated for the requested CVE.[/red]")
        raise typer.Exit(code=1)

    finding = findings[0]
    nvd = enrichment.nvd.get(normalized_cve, NvdData(cve_id=normalized_cve))
    epss = enrichment.epss.get(normalized_cve, EpssData(cve_id=normalized_cve))
    kev = enrichment.kev.get(normalized_cve, KevData(cve_id=normalized_cve, in_kev=False))
    attack = enrichment.attack.get(normalized_cve, AttackData(cve_id=normalized_cve))
    warnings = enrichment.warnings + waiver_warnings
    comparison = PrioritizationService(policy=policy).build_comparison([finding])[0]
    attack_summary = _build_attack_summary_from_findings([finding])

    context = AnalysisContext(
        input_path=f"inline:{normalized_cve}",
        output_path=str(output) if output else None,
        output_format=format.value,
        generated_at=iso_utc_now(),
        attack_enabled=attack_enabled,
        attack_source=enrichment.attack_source,
        attack_mapping_file=enrichment.attack_mapping_file,
        attack_technique_metadata_file=enrichment.attack_technique_metadata_file,
        attack_source_version=enrichment.attack_source_version,
        attack_version=enrichment.attack_version,
        attack_domain=enrichment.attack_domain,
        mapping_framework=enrichment.mapping_framework,
        mapping_framework_version=enrichment.mapping_framework_version,
        warnings=warnings,
        total_input=1,
        valid_input=1,
        occurrences_count=parsed_input.total_rows,
        findings_count=1,
        filtered_out_count=0,
        nvd_hits=_count_nvd_hits(enrichment),
        epss_hits=_count_epss_hits(enrichment),
        kev_hits=_count_kev_hits(enrichment),
        attack_hits=attack_summary.mapped_cves,
        suppressed_by_vex=sum(1 for item in findings if item.suppressed_by_vex),
        under_investigation_count=sum(1 for item in findings if item.under_investigation),
        waived_count=sum(1 for item in findings if item.waived),
        attack_summary=attack_summary,
        policy_overrides=policy.override_descriptions(),
        priority_policy=policy,
        policy_profile=context_profile.name,
        policy_file=str(policy_file) if policy_file else None,
        waiver_file=str(waiver_file) if waiver_file else None,
        counts_by_priority=counts,
        source_stats=parsed_input.source_stats,
        input_format=parsed_input.input_format,
        data_sources=_build_data_sources(enrichment),
        cache_enabled=not no_cache,
        cache_dir=str(cache_dir) if not no_cache else None,
    )

    console.print(render_explain_view(finding, nvd, epss, kev, attack, comparison))
    _print_warnings(warnings)

    if output is not None:
        if format == OutputFormat.markdown:
            write_output(
                output,
                generate_explain_markdown(
                    finding,
                    nvd,
                    epss,
                    kev,
                    attack,
                    context,
                    comparison,
                ),
            )
        elif format == OutputFormat.json:
            write_output(
                output,
                generate_explain_json(
                    finding,
                    nvd,
                    epss,
                    kev,
                    attack,
                    context,
                    comparison,
                ),
            )
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")


@app.command()
def doctor(
    ctx: typer.Context,
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: OutputFormat = typer.Option(OutputFormat.table, "--format"),
    live: bool = typer.Option(False, "--live"),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    attack_mapping_file: Path | None = typer.Option(None, "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
) -> None:
    """Run local environment and data-source diagnostics."""
    _validate_output_mode(format, output)
    _validate_command_formats(
        command_name="doctor",
        format=format,
        allowed_formats={OutputFormat.json, OutputFormat.table},
    )

    report = _build_doctor_report(
        ctx,
        live=live,
        cache_dir=cache_dir,
        cache_ttl_hours=cache_ttl_hours,
        offline_kev_file=offline_kev_file,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
    )

    console.print(
        Panel(
            "\n".join(
                [
                    f"Generated at: {report.generated_at}",
                    f"Runtime config: {report.config_file or 'Not discovered'}",
                    f"Live probes: {'enabled' if report.live else 'disabled'}",
                ]
            ),
            title="Doctor",
        )
    )
    console.print(_render_doctor_table(report))

    if output is not None:
        write_output(output, generate_doctor_json(report))
        console.print(f"[green]Wrote json output to {output}[/green]")

    if any(check.status != "ok" for check in report.checks):
        raise typer.Exit(code=1)


@snapshot_app.command("create")
def snapshot_create(
    ctx: typer.Context,
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False),
    format: OutputFormat = typer.Option(OutputFormat.json, "--format"),
    input_format: InputFormat = typer.Option(InputFormat.auto, "--input-format"),
    no_attack: bool = typer.Option(False, "--no-attack"),
    attack_source: AttackSource = typer.Option(AttackSource.none, "--attack-source"),
    attack_mapping_file: Path | None = typer.Option(None, "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
    priority: list[PriorityFilter] | None = typer.Option(None, "--priority"),
    kev_only: bool = typer.Option(False, "--kev-only"),
    min_cvss: float | None = typer.Option(None, "--min-cvss", min=0.0, max=10.0),
    min_epss: float | None = typer.Option(None, "--min-epss", min=0.0, max=1.0),
    sort_by: SortBy = typer.Option(SortBy.priority, "--sort-by"),
    critical_epss_threshold: float = typer.Option(0.70, "--critical-epss-threshold"),
    critical_cvss_threshold: float = typer.Option(7.0, "--critical-cvss-threshold"),
    high_epss_threshold: float = typer.Option(0.40, "--high-epss-threshold"),
    high_cvss_threshold: float = typer.Option(9.0, "--high-cvss-threshold"),
    medium_epss_threshold: float = typer.Option(0.10, "--medium-epss-threshold"),
    medium_cvss_threshold: float = typer.Option(7.0, "--medium-cvss-threshold"),
    policy_profile: str = typer.Option(PolicyProfile.default.value, "--policy-profile"),
    policy_file: Path | None = typer.Option(None, "--policy-file", dir_okay=False),
    waiver_file: Path | None = typer.Option(None, "--waiver-file", dir_okay=False),
    asset_context: Path | None = typer.Option(None, "--asset-context", dir_okay=False),
    target_kind: TargetKind = typer.Option(TargetKind.generic, "--target-kind"),
    target_ref: str | None = typer.Option(None, "--target-ref"),
    vex_file: list[Path] | None = typer.Option(None, "--vex-file", dir_okay=False),
    show_suppressed: bool = typer.Option(False, "--show-suppressed"),
    hide_waived: bool = typer.Option(False, "--hide-waived"),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    offline_attack_file: Path | None = typer.Option(None, "--offline-attack-file", dir_okay=False),
    nvd_api_key_env: str = typer.Option(DEFAULT_NVD_API_KEY_ENV, "--nvd-api-key-env"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
) -> None:
    """Create a reusable prioritized snapshot artifact."""
    load_dotenv()
    _validate_command_formats(
        command_name="snapshot create",
        format=format,
        allowed_formats={OutputFormat.json, OutputFormat.markdown},
    )

    findings, context = _prepare_analysis(
        input_path=input,
        output=output,
        format=format,
        input_format=input_format,
        no_attack=no_attack,
        attack_source=attack_source,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
        offline_attack_file=offline_attack_file,
        priority_filters=priority,
        kev_only=kev_only,
        min_cvss=min_cvss,
        min_epss=min_epss,
        sort_by=sort_by,
        policy=_build_priority_policy(
            critical_epss_threshold=critical_epss_threshold,
            critical_cvss_threshold=critical_cvss_threshold,
            high_epss_threshold=high_epss_threshold,
            high_cvss_threshold=high_cvss_threshold,
            medium_epss_threshold=medium_epss_threshold,
            medium_cvss_threshold=medium_cvss_threshold,
        ),
        policy_profile=policy_profile,
        policy_file=policy_file,
        waiver_file=waiver_file,
        asset_context=asset_context,
        target_kind=target_kind.value,
        target_ref=target_ref,
        vex_files=vex_file or [],
        show_suppressed=show_suppressed,
        hide_waived=hide_waived,
        max_cves=max_cves,
        offline_kev_file=offline_kev_file,
        nvd_api_key_env=nvd_api_key_env,
        no_cache=no_cache,
        cache_dir=cache_dir,
        cache_ttl_hours=cache_ttl_hours,
    )
    snapshot_metadata = SnapshotMetadata.model_validate(
        {
            **context.model_dump(),
            "schema_version": SnapshotMetadata.model_fields["schema_version"].default,
            "snapshot_kind": SnapshotMetadata.model_fields["snapshot_kind"].default,
            "config_file": str(_runtime_config_path(ctx)) if _runtime_config_path(ctx) else None,
        }
    )

    console.print(render_findings_table(findings))
    console.print(render_summary_panel(snapshot_metadata))
    _print_warnings(snapshot_metadata.warnings)

    if format == OutputFormat.json:
        write_output(
            output,
            json.dumps(
                build_snapshot_report_payload(findings, snapshot_metadata),
                indent=2,
                sort_keys=True,
            ),
        )
    else:
        write_output(output, generate_markdown_report(findings, snapshot_metadata))
    console.print(f"[green]Wrote snapshot {format.value} output to {output}[/green]")


@snapshot_app.command("diff")
def snapshot_diff(
    before: Path = typer.Option(..., "--before", exists=True, dir_okay=False, readable=True),
    after: Path = typer.Option(..., "--after", exists=True, dir_okay=False, readable=True),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: OutputFormat = typer.Option(OutputFormat.table, "--format"),
    include_unchanged: bool = typer.Option(False, "--include-unchanged"),
) -> None:
    """Compare two snapshot artifacts by CVE."""
    _validate_output_mode(format, output)
    _validate_command_formats(
        command_name="snapshot diff",
        format=format,
        allowed_formats={OutputFormat.table, OutputFormat.markdown, OutputFormat.json},
    )

    before_payload = _load_snapshot_payload(before)
    after_payload = _load_snapshot_payload(after)
    items, summary = _build_snapshot_diff(
        before_payload,
        after_payload,
        include_unchanged=include_unchanged,
    )
    metadata = SnapshotDiffMetadata(
        generated_at=iso_utc_now(),
        before_path=str(before),
        after_path=str(after),
        include_unchanged=include_unchanged,
    )

    console.print(render_snapshot_diff_table(items, summary, metadata))
    if output is not None:
        if format == OutputFormat.markdown:
            write_output(output, generate_snapshot_diff_markdown(items, summary, metadata))
        elif format == OutputFormat.json:
            write_output(output, generate_snapshot_diff_json(items, summary, metadata))
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")


@app.command()
def rollup(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    by: RollupBy = typer.Option(RollupBy.asset, "--by"),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: OutputFormat = typer.Option(OutputFormat.table, "--format"),
    top: int = typer.Option(5, "--top", min=1),
) -> None:
    """Aggregate analysis or snapshot findings by asset or business service."""
    _validate_output_mode(format, output)
    _validate_command_formats(
        command_name="rollup",
        format=format,
        allowed_formats={OutputFormat.table, OutputFormat.markdown, OutputFormat.json},
    )

    input_kind, payload = _load_rollup_payload(input)
    buckets = _build_rollup_buckets(payload, dimension=by.value, top=top)
    metadata = RollupMetadata(
        generated_at=iso_utc_now(),
        input_path=str(input),
        input_kind=input_kind,
        dimension=by.value,
        bucket_count=len(buckets),
    )

    console.print(render_rollup_table(buckets, metadata))
    if output is not None:
        if format == OutputFormat.markdown:
            write_output(output, generate_rollup_markdown(buckets, metadata))
        elif format == OutputFormat.json:
            write_output(output, generate_rollup_json(buckets, metadata))
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")


@attack_app.command("validate")
def attack_validate(
    attack_source: AttackSource = typer.Option(AttackSource.ctid_json, "--attack-source"),
    attack_mapping_file: Path = typer.Option(..., "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: OutputFormat = typer.Option(OutputFormat.table, "--format"),
) -> None:
    """Validate local ATT&CK mapping and metadata files."""
    _validate_output_mode(format, output)
    _validate_command_formats(
        command_name="attack validate",
        format=format,
        allowed_formats={OutputFormat.markdown, OutputFormat.json, OutputFormat.table},
    )

    result = _validate_attack_inputs_or_exit(
        attack_source=attack_source.value,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
    )

    console.print(_render_attack_validation_panel(result))
    _print_warnings(result["warnings"])

    if output is not None:
        if format == OutputFormat.markdown:
            write_output(output, _generate_attack_validation_markdown(result))
        elif format == OutputFormat.json:
            write_output(output, json.dumps(result, indent=2, sort_keys=True))
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")


@attack_app.command("coverage")
def attack_coverage(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    attack_source: AttackSource = typer.Option(AttackSource.ctid_json, "--attack-source"),
    attack_mapping_file: Path = typer.Option(..., "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: OutputFormat = typer.Option(OutputFormat.table, "--format"),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
) -> None:
    """Show ATT&CK coverage for a local CVE list."""
    _validate_output_mode(format, output)
    _validate_command_formats(
        command_name="attack coverage",
        format=format,
        allowed_formats={OutputFormat.markdown, OutputFormat.json, OutputFormat.table},
    )

    cve_ids, total_input_rows, parser_warnings = _read_input_cves(input, max_cves=max_cves)
    attack_items, metadata, warnings = _load_attack_only_or_exit(
        cve_ids,
        attack_source=attack_source.value,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
    )
    summary = AttackEnrichmentService().summarize(attack_items)
    warnings = parser_warnings + warnings

    console.print(_render_attack_coverage_table(attack_items))
    console.print(
        Panel(
            "\n".join(
                [
                    f"Total input rows: {total_input_rows}",
                    f"Valid unique CVEs: {len(cve_ids)}",
                    f"Mapped CVEs: {summary.mapped_cves}",
                    f"Unmapped CVEs: {summary.unmapped_cves}",
                    f"ATT&CK source: {metadata['source']}",
                    "Mapping type distribution: "
                    + _format_distribution(summary.mapping_type_distribution),
                    "Technique distribution: "
                    + _format_distribution(summary.technique_distribution),
                    "Tactic distribution: " + _format_distribution(summary.tactic_distribution),
                ]
            ),
            title="ATT&CK Coverage",
        )
    )
    _print_warnings(warnings)

    if output is not None:
        if format == OutputFormat.markdown:
            write_output(
                output,
                _generate_attack_coverage_markdown(
                    input_path=str(input),
                    attack_items=attack_items,
                    summary=summary,
                    metadata=metadata,
                    warnings=warnings,
                ),
            )
        elif format == OutputFormat.json:
            write_output(
                output,
                json.dumps(
                    {
                        "metadata": {
                            "input_path": str(input),
                            **metadata,
                        },
                        "summary": summary.model_dump(),
                        "items": [item.model_dump() for item in attack_items],
                        "warnings": warnings,
                    },
                    indent=2,
                    sort_keys=True,
                ),
            )
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")


@attack_app.command("navigator-layer")
def attack_navigator_layer(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    attack_source: AttackSource = typer.Option(AttackSource.ctid_json, "--attack-source"),
    attack_mapping_file: Path = typer.Option(..., "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
    output: Path = typer.Option(..., "--output", dir_okay=False),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
) -> None:
    """Export an ATT&CK Navigator layer from local mapping coverage."""
    cve_ids, _, parser_warnings = _read_input_cves(input, max_cves=max_cves)
    attack_items, metadata, warnings = _load_attack_only_or_exit(
        cve_ids,
        attack_source=attack_source.value,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
    )
    layer = AttackEnrichmentService().build_navigator_layer(attack_items)
    write_output(output, json.dumps(layer, indent=2, sort_keys=True))
    console.print(
        Panel(
            "\n".join(
                [
                    f"Input file: {input}",
                    f"Output file: {output}",
                    f"ATT&CK source: {metadata['source']}",
                    f"Mapped techniques: {len(layer['techniques'])}",
                ]
            ),
            title="Navigator Layer",
        )
    )
    _print_warnings(parser_warnings + warnings)
    console.print(f"[green]Wrote navigator layer to {output}[/green]")


@data_app.command("status")
def data_status(
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    attack_mapping_file: Path | None = typer.Option(None, "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
) -> None:
    """Show cache status and local metadata versions."""
    cache = FileCache(cache_dir, cache_ttl_hours)
    console.print(
        Panel(
            "\n".join(
                [
                    f"Cache directory: {cache_dir}",
                    f"Cache TTL (hours): {cache_ttl_hours}",
                    f"KEV mode: {'offline file' if offline_kev_file else 'live/cache'}",
                ]
            ),
            title="Data Status",
        )
    )
    console.print(
        _render_cache_namespace_table(
            [
                cache.inspect_namespace("nvd"),
                cache.inspect_namespace("epss"),
                cache.inspect_namespace("kev"),
            ]
        )
    )
    if attack_mapping_file is not None:
        validation = _validate_attack_inputs_or_exit(
            attack_source=AttackSource.ctid_json.value,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
        )
        console.print(
            Panel(
                "\n".join(
                    [
                        f"ATT&CK source: {validation['source']}",
                        f"ATT&CK mapping file: {validation['mapping_file']}",
                        "ATT&CK mapping SHA256: "
                        + (_sha256_file(attack_mapping_file) if attack_mapping_file else "N.A."),
                        f"ATT&CK source version: {validation['source_version'] or 'N.A.'}",
                        f"ATT&CK version: {validation['attack_version'] or 'N.A.'}",
                        f"ATT&CK domain: {validation['domain'] or 'N.A.'}",
                    ]
                ),
                title="ATT&CK Metadata",
            )
        )
        _print_warnings(validation["warnings"])


@data_app.command("update")
def data_update(
    source: list[DataSourceName] | None = typer.Option(None, "--source"),
    input: Path | None = typer.Option(None, "--input", exists=True, dir_okay=False, readable=True),
    input_format: InputFormat = typer.Option(InputFormat.auto, "--input-format"),
    cve: list[str] | None = typer.Option(None, "--cve"),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    nvd_api_key_env: str = typer.Option(DEFAULT_NVD_API_KEY_ENV, "--nvd-api-key-env"),
) -> None:
    """Refresh cached live-source data for requested CVEs or the KEV catalog."""
    load_dotenv()
    selected_sources = _resolve_data_sources(source)
    requires_cves = _data_sources_require_cves(selected_sources)
    cve_ids, input_warnings = _load_data_command_cves_or_exit(
        input_path=input,
        input_format=input_format.value,
        inline_cves=cve or [],
        max_cves=max_cves,
        required=requires_cves,
    )
    cache = FileCache(cache_dir, cache_ttl_hours)

    rows: list[dict[str, str | int | None]] = []
    warnings = list(input_warnings)
    if "nvd" in selected_sources:
        nvd_results, provider_warnings = NvdProvider.from_env(
            api_key_env=nvd_api_key_env,
            cache=cache,
        ).fetch_many(cve_ids, refresh=True)
        warnings.extend(provider_warnings)
        rows.append(
            {
                "source": "NVD",
                "mode": "live/api",
                "requested": len(cve_ids),
                "records": sum(1 for item in nvd_results.values() if _has_nvd_content(item)),
                "latest_cached_at": cache.latest_cached_at("nvd") or "N.A.",
                "details": "Per-CVE records refreshed from the NVD CVE API cache namespace.",
            }
        )
    if "epss" in selected_sources:
        epss_results, provider_warnings = EpssProvider(cache=cache).fetch_many(
            cve_ids, refresh=True
        )
        warnings.extend(provider_warnings)
        rows.append(
            {
                "source": "EPSS",
                "mode": "live/api",
                "requested": len(cve_ids),
                "records": sum(
                    1
                    for item in epss_results.values()
                    if item.epss is not None or item.percentile is not None or item.date is not None
                ),
                "latest_cached_at": cache.latest_cached_at("epss") or "N.A.",
                "details": (
                    "Per-CVE EPSS records refreshed from the FIRST EPSS API cache namespace."
                ),
            }
        )
    if "kev" in selected_sources:
        _, provider_warnings = KevProvider(cache=cache).fetch_many(
            cve_ids,
            offline_file=offline_kev_file,
            refresh=True,
        )
        warnings.extend(provider_warnings)
        cached_catalog = cache.get_json("kev", "catalog") or {}
        rows.append(
            {
                "source": "KEV",
                "mode": "offline file" if offline_kev_file else "live/catalog",
                "requested": len(cve_ids),
                "records": len(cached_catalog) if isinstance(cached_catalog, dict) else 0,
                "latest_cached_at": cache.latest_cached_at("kev") or "N.A.",
                "details": "Catalog namespace refreshed and indexed for cached KEV lookups.",
            }
        )

    console.print(
        Panel(
            "\n".join(
                [
                    "Selected sources: " + ", ".join(selected_sources),
                    f"Cache directory: {cache_dir}",
                    f"Cache TTL (hours): {cache_ttl_hours}",
                    f"Requested CVEs: {len(cve_ids)}",
                ]
            ),
            title="Data Update",
        )
    )
    console.print(_render_data_update_table(rows))
    _print_warnings(warnings)


@data_app.command("verify")
def data_verify(
    input: Path | None = typer.Option(None, "--input", exists=True, dir_okay=False, readable=True),
    input_format: InputFormat = typer.Option(InputFormat.auto, "--input-format"),
    cve: list[str] | None = typer.Option(None, "--cve"),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    attack_mapping_file: Path | None = typer.Option(None, "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
) -> None:
    """Verify cache integrity, cache coverage, and local file checksums."""
    cache = FileCache(cache_dir, cache_ttl_hours)
    cve_ids, input_warnings = _load_data_command_cves_or_exit(
        input_path=input,
        input_format=input_format.value,
        inline_cves=cve or [],
        max_cves=max_cves,
        required=False,
    )
    statuses = [
        cache.inspect_namespace("nvd"),
        cache.inspect_namespace("epss"),
        cache.inspect_namespace("kev"),
    ]

    console.print(
        Panel(
            "\n".join(
                [
                    f"Cache directory: {cache_dir}",
                    f"Cache TTL (hours): {cache_ttl_hours}",
                    f"Requested CVEs for coverage check: {len(cve_ids)}",
                    f"KEV mode: {'offline file' if offline_kev_file else 'live/cache'}",
                ]
            ),
            title="Data Verify",
        )
    )
    console.print(_render_cache_namespace_table(statuses))
    if cve_ids:
        console.print(_render_cache_coverage_table(cache, cve_ids))

    if offline_kev_file is not None:
        console.print(
            _render_local_file_table(
                [
                    {
                        "label": "Offline KEV file",
                        "path": str(offline_kev_file),
                        "sha256": _sha256_file(offline_kev_file),
                        "size_bytes": offline_kev_file.stat().st_size,
                    }
                ],
                title="Pinned Local Files",
            )
        )
    if attack_mapping_file is not None:
        validation = _validate_attack_inputs_or_exit(
            attack_source=AttackSource.ctid_json.value,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
        )
        file_rows: list[dict[str, str | int]] = [
            {
                "label": "ATT&CK mapping file",
                "path": str(attack_mapping_file),
                "sha256": _sha256_file(attack_mapping_file),
                "size_bytes": attack_mapping_file.stat().st_size,
            }
        ]
        if attack_technique_metadata_file is not None:
            file_rows.append(
                {
                    "label": "ATT&CK metadata file",
                    "path": str(attack_technique_metadata_file),
                    "sha256": _sha256_file(attack_technique_metadata_file),
                    "size_bytes": attack_technique_metadata_file.stat().st_size,
                }
            )
        console.print(_render_local_file_table(file_rows, title="Pinned Local Files"))
        console.print(
            Panel(
                "\n".join(
                    [
                        f"ATT&CK source: {validation['source']}",
                        f"Source version: {validation['source_version'] or 'N.A.'}",
                        f"ATT&CK version: {validation['attack_version'] or 'N.A.'}",
                        f"Domain: {validation['domain'] or 'N.A.'}",
                        f"Unique CVEs in mapping: {validation['unique_cves']}",
                        f"Total mapping objects: {validation['mapping_count']}",
                        f"Technique metadata entries: {validation['technique_count']}",
                    ]
                ),
                title="ATT&CK Verification",
            )
        )
        input_warnings.extend(validation["warnings"])
    _print_warnings(input_warnings)


@report_app.command("html")
def report_html(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False),
) -> None:
    """Render a static HTML report from an analysis JSON export."""
    payload = _load_analysis_report_payload(input)
    write_output(output, generate_html_report(payload))
    console.print(f"[green]Wrote html output to {output}[/green]")


@report_app.command("evidence-bundle")
def report_evidence_bundle(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False),
    include_input_copy: bool = typer.Option(True, "--include-input-copy/--no-include-input-copy"),
) -> None:
    """Build a reproducible evidence bundle from an analysis JSON export."""
    payload = _load_analysis_report_payload(input)
    manifest = _write_evidence_bundle(
        analysis_path=input,
        output_path=output,
        payload=payload,
        include_input_copy=include_input_copy,
    )
    console.print(f"[green]Wrote evidence bundle to {output}[/green]")
    console.print(f"[green]Included {len(manifest.files)} artifact(s) plus manifest.[/green]")


def _prepare_analysis(
    *,
    input_path: Path,
    output: Path | None,
    format: OutputFormat,
    input_format: InputFormat,
    no_attack: bool,
    attack_source: AttackSource,
    attack_mapping_file: Path | None,
    attack_technique_metadata_file: Path | None,
    offline_attack_file: Path | None,
    priority_filters: list[PriorityFilter] | None,
    kev_only: bool,
    min_cvss: float | None,
    min_epss: float | None,
    sort_by: SortBy,
    policy: PriorityPolicy,
    policy_profile: str,
    policy_file: Path | None,
    waiver_file: Path | None,
    asset_context: Path | None,
    target_kind: str,
    target_ref: str | None,
    vex_files: list[Path],
    show_suppressed: bool,
    hide_waived: bool,
    max_cves: int | None,
    offline_kev_file: Path | None,
    nvd_api_key_env: str,
    no_cache: bool,
    cache_dir: Path,
    cache_ttl_hours: int,
) -> tuple[list[PrioritizedFinding], AnalysisContext]:
    attack_enabled, resolved_attack_source, resolved_mapping_file, resolved_metadata_file = (
        _resolve_attack_options(
            no_attack=no_attack,
            attack_source=attack_source,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
            offline_attack_file=offline_attack_file,
        )
    )
    try:
        asset_records = _load_asset_records_or_exit(asset_context)
        vex_statements = _load_vex_statements_or_exit(vex_files)
        parsed_input = InputLoader().load(
            input_path,
            input_format=input_format.value,
            max_cves=max_cves,
            target_kind=target_kind,
            target_ref=target_ref,
            asset_records=asset_records,
            vex_statements=vex_statements,
        )
    except ValidationError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except ValueError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    cve_ids = parsed_input.unique_cves
    context_profile = _load_context_profile_or_exit(policy_profile, policy_file)
    waiver_rules = _load_waiver_rules_or_exit(waiver_file)
    all_findings, _, enrichment = _build_findings(
        cve_ids,
        policy=policy,
        parsed_input=parsed_input,
        context_profile=context_profile,
        attack_enabled=attack_enabled,
        attack_source=resolved_attack_source,
        attack_mapping_file=resolved_mapping_file,
        attack_technique_metadata_file=resolved_metadata_file,
        offline_kev_file=offline_kev_file,
        offline_attack_file=offline_attack_file,
        nvd_api_key_env=nvd_api_key_env,
        no_cache=no_cache,
        cache_dir=cache_dir,
        cache_ttl_hours=cache_ttl_hours,
    )
    all_findings, waiver_warnings = apply_waivers(all_findings, waiver_rules)

    if not all_findings:
        console.print("[red]No findings could be generated from the provided CVEs.[/red]")
        raise typer.Exit(code=1)

    prioritizer = PrioritizationService(policy=policy)
    normalized_priority_filters = _normalize_priority_filters(priority_filters)
    filtered_findings = prioritizer.filter_findings(
        all_findings,
        priorities=normalized_priority_filters,
        kev_only=kev_only,
        min_cvss=min_cvss,
        min_epss=min_epss,
        show_suppressed=show_suppressed,
        hide_waived=hide_waived,
    )
    findings = prioritizer.sort_findings(filtered_findings, sort_by=sort_by.value)
    warnings = parsed_input.warnings + enrichment.warnings + waiver_warnings
    attack_summary = _build_attack_summary_from_findings(findings)

    context = AnalysisContext(
        input_path=str(input_path),
        output_path=str(output) if output else None,
        output_format=format.value,
        generated_at=iso_utc_now(),
        input_format=parsed_input.input_format,
        attack_enabled=attack_enabled,
        attack_source=enrichment.attack_source,
        attack_mapping_file=enrichment.attack_mapping_file,
        attack_technique_metadata_file=enrichment.attack_technique_metadata_file,
        attack_source_version=enrichment.attack_source_version,
        attack_version=enrichment.attack_version,
        attack_domain=enrichment.attack_domain,
        mapping_framework=enrichment.mapping_framework,
        mapping_framework_version=enrichment.mapping_framework_version,
        warnings=warnings,
        total_input=parsed_input.total_rows,
        valid_input=len(cve_ids),
        occurrences_count=len(parsed_input.occurrences),
        findings_count=len(findings),
        filtered_out_count=max(len(all_findings) - len(findings), 0),
        nvd_hits=_count_nvd_hits(enrichment),
        epss_hits=_count_epss_hits(enrichment),
        kev_hits=_count_kev_hits(enrichment),
        attack_hits=attack_summary.mapped_cves,
        suppressed_by_vex=sum(1 for item in all_findings if item.suppressed_by_vex),
        under_investigation_count=sum(1 for item in all_findings if item.under_investigation),
        waived_count=sum(1 for item in all_findings if item.waived),
        attack_summary=attack_summary,
        active_filters=_build_active_filters(
            priority_filters=priority_filters,
            kev_only=kev_only,
            min_cvss=min_cvss,
            min_epss=min_epss,
            show_suppressed=show_suppressed,
            hide_waived=hide_waived,
        ),
        policy_overrides=policy.override_descriptions(),
        priority_policy=policy,
        policy_profile=context_profile.name,
        policy_file=str(policy_file) if policy_file else None,
        waiver_file=str(waiver_file) if waiver_file else None,
        counts_by_priority=prioritizer.count_by_priority(findings),
        source_stats=parsed_input.source_stats,
        data_sources=_build_data_sources(enrichment),
        cache_enabled=not no_cache,
        cache_dir=str(cache_dir) if not no_cache else None,
    )

    return findings, context


def _build_findings(
    cve_ids: list[str],
    *,
    policy: PriorityPolicy,
    parsed_input: ParsedInput,
    context_profile: ContextPolicyProfile,
    attack_enabled: bool,
    attack_source: str,
    attack_mapping_file: Path | None,
    attack_technique_metadata_file: Path | None,
    offline_kev_file: Path | None,
    offline_attack_file: Path | None,
    nvd_api_key_env: str,
    no_cache: bool,
    cache_dir: Path,
    cache_ttl_hours: int,
) -> tuple[list[PrioritizedFinding], dict[str, int], EnrichmentResult]:
    _validate_requested_attack_mode(
        attack_enabled=attack_enabled,
        attack_source=attack_source,
        attack_mapping_file=attack_mapping_file,
        offline_attack_file=offline_attack_file,
    )
    enricher = EnrichmentService(
        nvd_api_key_env=nvd_api_key_env,
        use_cache=not no_cache,
        cache_dir=cache_dir,
        cache_ttl_hours=cache_ttl_hours,
    )
    try:
        enrichment = enricher.enrich(
            cve_ids,
            attack_enabled=attack_enabled,
            attack_source=attack_source,
            offline_kev_file=offline_kev_file,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
            offline_attack_file=offline_attack_file,
        )
    except (OSError, ValidationError, ValueError) as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    enrichment.parsed_input = parsed_input
    provenance_by_cve = aggregate_provenance(parsed_input.unique_cves, parsed_input.occurrences)

    prioritizer = PrioritizationService(policy=policy)
    findings, counts = prioritizer.prioritize(
        cve_ids,
        nvd_data=enrichment.nvd,
        epss_data=enrichment.epss,
        kev_data=enrichment.kev,
        attack_data=enrichment.attack,
        provenance_by_cve=provenance_by_cve,
        context_profile=context_profile,
    )
    return findings, counts, enrichment


def _validate_output_mode(format: OutputFormat, output: Path | None) -> None:
    if format == OutputFormat.table and output is not None:
        console.print(
            "[red]Input validation failed:[/red] "
            "--output cannot be used together with --format table."
        )
        raise typer.Exit(code=2)


def _validate_unique_output_paths(paths: dict[str, Path | None]) -> None:
    resolved: dict[Path, str] = {}
    for label, path in paths.items():
        if path is None:
            continue
        resolved_path = path.resolve()
        if resolved_path in resolved:
            _exit_input_validation(
                f"{resolved[resolved_path]} and {label} must point to different files."
            )
        resolved[resolved_path] = label


def _load_runtime_config_for_session(
    *,
    config: Path | None,
    no_config: bool,
) -> LoadedRuntimeConfig | None:
    if no_config:
        return None

    config_path = config
    if config_path is None:
        config_path = discover_runtime_config(Path.cwd())
    if config_path is None:
        return None

    try:
        return load_runtime_config(config_path)
    except ValueError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc


def _merge_default_maps(
    current: MutableMapping[str, object] | None,
    update: dict[str, object],
) -> dict:
    if current is None:
        return update
    merged = dict(current)
    for key, value in update.items():
        existing = merged.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            merged[key] = _merge_default_maps(existing, value)
        else:
            merged[key] = value
    return merged


def _runtime_config_path(ctx: typer.Context) -> Path | None:
    root = ctx.find_root()
    obj = root.obj if isinstance(root.obj, dict) else {}
    loaded = obj.get("runtime_config")
    if isinstance(loaded, LoadedRuntimeConfig):
        return loaded.path
    return None


def _runtime_config(ctx: typer.Context) -> LoadedRuntimeConfig | None:
    root = ctx.find_root()
    obj = root.obj if isinstance(root.obj, dict) else {}
    loaded = obj.get("runtime_config")
    return loaded if isinstance(loaded, LoadedRuntimeConfig) else None


def _validate_command_formats(
    *,
    command_name: str,
    format: OutputFormat,
    allowed_formats: set[OutputFormat],
) -> None:
    if format in allowed_formats:
        return

    supported = ", ".join(
        item.value for item in sorted(allowed_formats, key=lambda item: item.value)
    )
    console.print(
        f"[red]Input validation failed:[/red] {command_name} supports only --format {supported}."
    )
    raise typer.Exit(code=2)


def _normalize_priority_filters(priority_filters: list[PriorityFilter] | None) -> set[str]:
    if not priority_filters:
        return set()
    return {PRIORITY_LABELS[item] for item in priority_filters}


def _build_active_filters(
    *,
    priority_filters: list[PriorityFilter] | None,
    kev_only: bool,
    min_cvss: float | None,
    min_epss: float | None,
    show_suppressed: bool = False,
    hide_waived: bool = False,
) -> list[str]:
    active_filters: list[str] = []

    if priority_filters:
        ordered_labels = []
        for item in priority_filters:
            label = PRIORITY_LABELS[item]
            if label not in ordered_labels:
                ordered_labels.append(label)
        active_filters.append("priority=" + ",".join(ordered_labels))
    if kev_only:
        active_filters.append("kev-only")
    if min_cvss is not None:
        active_filters.append(f"min-cvss>={min_cvss:.1f}")
    if min_epss is not None:
        active_filters.append(f"min-epss>={min_epss:.3f}")
    if show_suppressed:
        active_filters.append("show-suppressed")
    if hide_waived:
        active_filters.append("hide-waived")

    return active_filters


def _build_priority_policy(
    *,
    critical_epss_threshold: float,
    critical_cvss_threshold: float,
    high_epss_threshold: float,
    high_cvss_threshold: float,
    medium_epss_threshold: float,
    medium_cvss_threshold: float,
) -> PriorityPolicy:
    try:
        return PriorityPolicy(
            critical_epss_threshold=critical_epss_threshold,
            critical_cvss_threshold=critical_cvss_threshold,
            high_epss_threshold=high_epss_threshold,
            high_cvss_threshold=high_cvss_threshold,
            medium_epss_threshold=medium_epss_threshold,
            medium_cvss_threshold=medium_cvss_threshold,
        )
    except ValueError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc


def _resolve_attack_options(
    *,
    no_attack: bool,
    attack_source: AttackSource,
    attack_mapping_file: Path | None,
    attack_technique_metadata_file: Path | None,
    offline_attack_file: Path | None,
) -> tuple[bool, str, Path | None, Path | None]:
    if no_attack:
        return False, AttackSource.none.value, None, None

    if attack_source == AttackSource.none:
        if offline_attack_file is not None:
            return True, AttackSource.local_csv.value, offline_attack_file, None
        if attack_mapping_file is not None:
            return (
                True,
                AttackSource.ctid_json.value,
                attack_mapping_file,
                attack_technique_metadata_file,
            )
        return False, AttackSource.none.value, None, None

    if attack_source == AttackSource.local_csv:
        return True, attack_source.value, attack_mapping_file or offline_attack_file, None

    return (
        True,
        attack_source.value,
        attack_mapping_file or offline_attack_file,
        attack_technique_metadata_file,
    )


def _count_nvd_hits(enrichment: EnrichmentResult) -> int:
    return sum(1 for item in enrichment.nvd.values() if _has_nvd_content(item))


def _count_epss_hits(enrichment: EnrichmentResult) -> int:
    return sum(
        1
        for item in enrichment.epss.values()
        if item.epss is not None or item.percentile is not None or item.date is not None
    )


def _count_kev_hits(enrichment: EnrichmentResult) -> int:
    return sum(1 for item in enrichment.kev.values() if item.in_kev)


def _count_attack_hits(enrichment: EnrichmentResult) -> int:
    return sum(1 for item in enrichment.attack.values() if item.mapped)


def _build_attack_summary_from_findings(findings: list[PrioritizedFinding]) -> AttackSummary:
    attack_items: list[AttackData] = []
    for finding in findings:
        mapping_types: list[str] = []
        capability_groups: list[str] = []
        for mapping in finding.attack_mappings:
            if mapping.mapping_type and mapping.mapping_type not in mapping_types:
                mapping_types.append(mapping.mapping_type)
            if mapping.capability_group and mapping.capability_group not in capability_groups:
                capability_groups.append(mapping.capability_group)
        attack_items.append(
            AttackData(
                cve_id=finding.cve_id,
                mapped=finding.attack_mapped,
                mappings=finding.attack_mappings,
                techniques=finding.attack_technique_details,
                mapping_types=mapping_types,
                capability_groups=capability_groups,
                attack_techniques=finding.attack_techniques,
                attack_tactics=finding.attack_tactics,
                attack_relevance=finding.attack_relevance,
            )
        )
    return AttackEnrichmentService().summarize(attack_items)


def _build_data_sources(enrichment: EnrichmentResult) -> list[str]:
    sources = list(DATA_SOURCES)
    if enrichment.attack_source == "ctid-mappings-explorer":
        sources.append("CTID Mappings Explorer (local JSON artifact)")
    elif enrichment.attack_source == "local-csv":
        sources.append("Local ATT&CK CSV mapping")
    parsed_input = enrichment.parsed_input
    if parsed_input.source_stats:
        sources.append("Input formats: " + ", ".join(sorted(parsed_input.source_stats)))
    return sources


def _has_nvd_content(item: NvdData) -> bool:
    return any(
        [
            item.description is not None,
            item.cvss_base_score is not None,
            item.cvss_severity is not None,
            item.cvss_version is not None,
            item.published is not None,
            item.last_modified is not None,
            bool(item.cwes),
            bool(item.references),
        ]
    )


def _print_warnings(warnings: list[str]) -> None:
    if warnings:
        console.print(
            Panel(
                "\n".join(f"- {warning}" for warning in warnings),
                title="Warnings",
                border_style="yellow",
            )
        )


def _resolve_data_sources(sources: list[DataSourceName] | None) -> list[str]:
    ordered: list[str] = []
    requested = sources or [DataSourceName.all]
    for source in requested:
        expanded = ["nvd", "epss", "kev"] if source == DataSourceName.all else [source.value]
        for item in expanded:
            if item not in ordered:
                ordered.append(item)
    return ordered


def _data_sources_require_cves(sources: list[str]) -> bool:
    return any(item in {"nvd", "epss"} for item in sources)


def _load_data_command_cves_or_exit(
    *,
    input_path: Path | None,
    input_format: str,
    inline_cves: list[str],
    max_cves: int | None,
    required: bool,
) -> tuple[list[str], list[str]]:
    cve_ids: list[str] = []
    warnings: list[str] = []

    if input_path is not None:
        try:
            parsed_input = InputLoader().load(
                input_path, input_format=input_format, max_cves=max_cves
            )
        except ValidationError as exc:
            console.print(f"[red]Input validation failed:[/red] {exc}")
            raise typer.Exit(code=2) from exc
        except ValueError as exc:
            console.print(f"[red]Input validation failed:[/red] {exc}")
            raise typer.Exit(code=2) from exc
        cve_ids.extend(parsed_input.unique_cves)
        warnings.extend(parsed_input.warnings)

    for raw_cve in inline_cves:
        normalized = normalize_cve_id(raw_cve)
        if normalized is None:
            warnings.append(f"Ignored invalid CVE identifier: {raw_cve!r}")
            continue
        if normalized not in cve_ids:
            cve_ids.append(normalized)

    if max_cves is not None and len(cve_ids) > max_cves:
        warnings.append(f"Truncated data-source verification input to the first {max_cves} CVEs.")
        cve_ids = cve_ids[:max_cves]

    if required and not cve_ids:
        console.print(
            "[red]Input validation failed:[/red] "
            "NVD and EPSS cache refresh requires --input or at least one --cve."
        )
        raise typer.Exit(code=2)

    return cve_ids, warnings


def _render_cache_namespace_table(statuses: list[dict[str, object]]) -> Table:
    table = Table(title="Cache Namespaces", show_lines=False)
    table.add_column("Source", style="bold")
    table.add_column("Files")
    table.add_column("Valid")
    table.add_column("Expired")
    table.add_column("Invalid")
    table.add_column("Latest Cached At")
    table.add_column("Namespace SHA256")

    labels = {"nvd": "NVD", "epss": "EPSS", "kev": "KEV"}
    for status in statuses:
        namespace = str(status["namespace"])
        table.add_row(
            labels.get(namespace, namespace.upper()),
            str(status["file_count"]),
            str(status["valid_count"]),
            str(status["expired_count"]),
            str(status["invalid_count"]),
            str(status["latest_cached_at"] or "N.A."),
            str(status["namespace_checksum"] or "N.A."),
        )
    return table


def _render_data_update_table(rows: list[dict[str, str | int | None]]) -> Table:
    table = Table(title="Updated Sources", show_lines=False)
    table.add_column("Source", style="bold")
    table.add_column("Mode")
    table.add_column("Requested CVEs")
    table.add_column("Cached Records")
    table.add_column("Latest Cached At")
    table.add_column("Details")

    for row in rows:
        table.add_row(
            str(row["source"]),
            str(row["mode"]),
            str(row["requested"]),
            str(row["records"]),
            str(row["latest_cached_at"]),
            str(row["details"]),
        )
    return table


def _render_cache_coverage_table(cache: FileCache, cve_ids: list[str]) -> Table:
    table = Table(title="Cache Coverage", show_lines=False)
    table.add_column("Source", style="bold")
    table.add_column("Cached Coverage")
    table.add_column("Details")

    nvd_hits = sum(1 for cve_id in cve_ids if cache.get_json("nvd", cve_id) is not None)
    epss_hits = sum(1 for cve_id in cve_ids if cache.get_json("epss", cve_id) is not None)
    kev_payload = cache.get_json("kev", "catalog")
    kev_catalog = kev_payload if isinstance(kev_payload, dict) else {}
    kev_hits = sum(1 for cve_id in cve_ids if cve_id in kev_catalog)

    table.add_row("NVD", f"{nvd_hits}/{len(cve_ids)}", "Fresh per-CVE cache entries available.")
    table.add_row("EPSS", f"{epss_hits}/{len(cve_ids)}", "Fresh per-CVE cache entries available.")
    table.add_row(
        "KEV",
        f"{kev_hits}/{len(cve_ids)}",
        "Coverage derived from the cached KEV catalog index.",
    )
    return table


def _render_local_file_table(rows: list[dict[str, str | int]], *, title: str) -> Table:
    table = Table(title=title, show_lines=False)
    table.add_column("Label", style="bold")
    table.add_column("Path")
    table.add_column("Size (bytes)")
    table.add_column("SHA256")

    for row in rows:
        table.add_row(
            str(row["label"]),
            str(row["path"]),
            str(row["size_bytes"]),
            str(row["sha256"]),
        )
    return table


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _validate_attack_inputs_or_exit(
    *,
    attack_source: str,
    attack_mapping_file: Path,
    attack_technique_metadata_file: Path | None,
) -> dict:
    try:
        return _validate_attack_inputs(
            attack_source=attack_source,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
        )
    except (OSError, ValidationError, ValueError) as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc


def _validate_attack_inputs(
    *,
    attack_source: str,
    attack_mapping_file: Path,
    attack_technique_metadata_file: Path | None,
) -> dict:
    warnings: list[str] = []
    metadata: dict[str, str | None]
    mapping_count = 0
    unique_cves = 0
    technique_count = 0
    missing_metadata_ids: list[str] = []
    domain_mismatch = False
    attack_version_mismatch = False
    revoked_or_deprecated_count = 0

    if attack_source == AttackSource.ctid_json.value:
        mappings_by_cve, mapping_metadata, mapping_warnings = CtidMappingsProvider().load(
            attack_mapping_file
        )
        warnings.extend(mapping_warnings)
        mapping_count = sum(len(items) for items in mappings_by_cve.values())
        unique_cves = len(mappings_by_cve)
        mapped_technique_ids = sorted(
            {mapping.attack_object_id for items in mappings_by_cve.values() for mapping in items}
        )
        metadata = {
            "source": "ctid-mappings-explorer",
            "mapping_file": str(attack_mapping_file),
            "technique_metadata_file": (
                str(attack_technique_metadata_file)
                if attack_technique_metadata_file is not None
                else None
            ),
            "source_version": mapping_metadata.get("mapping_framework_version")
            or mapping_metadata.get("mapping_version"),
            "attack_version": mapping_metadata.get("attack_version"),
            "domain": mapping_metadata.get("domain"),
            "mapping_framework": mapping_metadata.get("mapping_framework"),
            "mapping_framework_version": mapping_metadata.get("mapping_framework_version"),
        }
        if attack_technique_metadata_file is not None:
            techniques, technique_metadata, technique_warnings = AttackMetadataProvider().load(
                attack_technique_metadata_file
            )
            warnings.extend(technique_warnings)
            technique_count = len(techniques)
            missing_metadata_ids = [
                technique_id
                for technique_id in mapped_technique_ids
                if technique_id not in techniques
            ]
            if missing_metadata_ids:
                warnings.append(
                    "Missing ATT&CK technique metadata for mapped technique IDs: "
                    + ", ".join(missing_metadata_ids)
                    + "."
                )
            domain_mismatch = _values_mismatch(
                mapping_metadata.get("domain"),
                technique_metadata.get("domain"),
            )
            if domain_mismatch:
                warnings.append(
                    "ATT&CK domain mismatch between CTID mappings and technique metadata: "
                    f"{mapping_metadata.get('domain') or 'N.A.'} vs "
                    f"{technique_metadata.get('domain') or 'N.A.'}."
                )
            attack_version_mismatch = _values_mismatch(
                mapping_metadata.get("attack_version"),
                technique_metadata.get("attack_version"),
            )
            if attack_version_mismatch:
                warnings.append(
                    "ATT&CK version mismatch between CTID mappings and technique metadata: "
                    f"{mapping_metadata.get('attack_version') or 'N.A.'} vs "
                    f"{technique_metadata.get('attack_version') or 'N.A.'}."
                )
            revoked_or_deprecated_count = sum(
                1
                for technique_id in mapped_technique_ids
                if (
                    techniques.get(technique_id) is not None
                    and (techniques[technique_id].revoked or techniques[technique_id].deprecated)
                )
            )
            metadata["attack_version"] = (
                technique_metadata.get("attack_version") or metadata["attack_version"]
            )
            metadata["domain"] = technique_metadata.get("domain") or metadata["domain"]
    else:
        provider = AttackProvider()
        results, metadata, provider_warnings = provider.inspect_legacy_csv(attack_mapping_file)
        warnings.extend(provider_warnings)
        mapping_count = sum(1 for item in results.values() if item.mapped)
        unique_cves = len(results)

    return {
        "source": metadata["source"],
        "mapping_file": metadata["mapping_file"],
        "technique_metadata_file": metadata.get("technique_metadata_file"),
        "source_version": metadata.get("source_version"),
        "attack_version": metadata.get("attack_version"),
        "domain": metadata.get("domain"),
        "mapping_framework": metadata.get("mapping_framework"),
        "mapping_framework_version": metadata.get("mapping_framework_version"),
        "mapping_count": mapping_count,
        "unique_cves": unique_cves,
        "technique_count": technique_count,
        "missing_metadata_ids": missing_metadata_ids,
        "domain_mismatch": domain_mismatch,
        "attack_version_mismatch": attack_version_mismatch,
        "revoked_or_deprecated_count": revoked_or_deprecated_count,
        "warnings": warnings,
    }


def _render_attack_validation_panel(result: dict) -> Panel:
    lines = [
        f"ATT&CK source: {result['source']}",
        f"Mapping file: {result['mapping_file']}",
        f"Technique metadata file: {result['technique_metadata_file'] or 'N.A.'}",
        f"Unique CVEs in mapping: {result['unique_cves']}",
        f"Total mapping objects: {result['mapping_count']}",
        f"Technique metadata entries: {result['technique_count']}",
        f"Source version: {result['source_version'] or 'N.A.'}",
        f"ATT&CK version: {result['attack_version'] or 'N.A.'}",
        f"Domain: {result['domain'] or 'N.A.'}",
        f"Missing technique metadata IDs: {', '.join(result['missing_metadata_ids']) or 'None'}",
        f"Domain mismatch: {'Yes' if result['domain_mismatch'] else 'No'}",
        f"ATT&CK version mismatch: {'Yes' if result['attack_version_mismatch'] else 'No'}",
        f"Revoked/deprecated mapped techniques: {result['revoked_or_deprecated_count']}",
    ]
    return Panel("\n".join(lines), title="ATT&CK Validation")


def _generate_attack_validation_markdown(result: dict) -> str:
    lines = [
        "# ATT&CK Validation",
        "",
        f"- ATT&CK source: `{result['source']}`",
        f"- Mapping file: `{result['mapping_file']}`",
        f"- Technique metadata file: `{result['technique_metadata_file'] or 'N.A.'}`",
        f"- Unique CVEs in mapping: {result['unique_cves']}",
        f"- Total mapping objects: {result['mapping_count']}",
        f"- Technique metadata entries: {result['technique_count']}",
        f"- Source version: `{result['source_version'] or 'N.A.'}`",
        f"- ATT&CK version: `{result['attack_version'] or 'N.A.'}`",
        f"- Domain: `{result['domain'] or 'N.A.'}`",
        "- Missing technique metadata IDs: "
        + (", ".join(result["missing_metadata_ids"]) or "None"),
        f"- Domain mismatch: {'Yes' if result['domain_mismatch'] else 'No'}",
        "- ATT&CK version mismatch: " + ("Yes" if result["attack_version_mismatch"] else "No"),
        "- Revoked/deprecated mapped techniques: " + str(result["revoked_or_deprecated_count"]),
        "",
        "## Warnings",
    ]
    if result["warnings"]:
        lines.extend(f"- {warning}" for warning in result["warnings"])
    else:
        lines.append("- None")
    return "\n".join(lines) + "\n"


def _read_input_cves(input_path: Path, *, max_cves: int | None) -> tuple[list[str], int, list[str]]:
    try:
        parsed_input = InputLoader().load(input_path, input_format="auto", max_cves=max_cves)
    except ValidationError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except ValueError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    return parsed_input.unique_cves, parsed_input.total_rows, parsed_input.warnings


def _load_asset_records_or_exit(
    asset_context: Path | None,
) -> dict[tuple[str, str], AssetContextRecord]:
    try:
        return load_asset_context_file(asset_context)
    except ValueError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc


def _load_vex_statements_or_exit(vex_files: list[Path]) -> list[VexStatement]:
    try:
        return load_vex_files(vex_files)
    except ValueError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc


def _load_waiver_rules_or_exit(waiver_file: Path | None) -> list[WaiverRule]:
    try:
        return load_waiver_rules(waiver_file)
    except ValueError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc


def _load_context_profile_or_exit(
    policy_profile: str,
    policy_file: Path | None,
) -> ContextPolicyProfile:
    try:
        return load_context_profile(policy_profile, policy_file)
    except ValueError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc


def _build_doctor_report(
    ctx: typer.Context,
    *,
    live: bool,
    cache_dir: Path,
    cache_ttl_hours: int,
    offline_kev_file: Path | None,
    attack_mapping_file: Path | None,
    attack_technique_metadata_file: Path | None,
) -> DoctorReport:
    checks: list[DoctorCheck] = []
    loaded = _runtime_config(ctx)

    python_ok = sys.version_info >= (3, 11)
    checks.append(
        DoctorCheck(
            name="python",
            status="ok" if python_ok else "error",
            detail=f"Python {sys.version.split()[0]}",
        )
    )
    checks.append(
        DoctorCheck(
            name="runtime_config",
            status="ok",
            detail=str(loaded.path) if loaded is not None else "No runtime config discovered.",
        )
    )

    referenced_files = list(collect_referenced_files(loaded)) if loaded is not None else []
    if offline_kev_file is not None:
        referenced_files.append(("Offline KEV file", offline_kev_file))
    if attack_mapping_file is not None:
        referenced_files.append(("ATT&CK mapping file", attack_mapping_file))
    if attack_technique_metadata_file is not None:
        referenced_files.append(("ATT&CK technique metadata file", attack_technique_metadata_file))
    if not any(label == "Cache directory" for label, _ in referenced_files):
        referenced_files.append(("Cache directory", cache_dir))

    for label, path in _unique_path_entries(referenced_files):
        if label == "Cache directory":
            status = "ok"
            detail = (
                f"{path} exists."
                if path.exists()
                else f"{path} does not exist yet and will be created on demand."
            )
        else:
            status = "ok" if path.exists() else "error"
            detail = f"{path} exists." if path.exists() else f"{path} does not exist."
        checks.append(
            DoctorCheck(
                name=_doctor_check_name(label),
                status=status,
                detail=detail,
            )
        )

    cache = FileCache(cache_dir, cache_ttl_hours)
    for namespace in ("nvd", "epss", "kev"):
        cache_status = cache.inspect_namespace(namespace)
        checks.append(
            DoctorCheck(
                name=f"cache_{namespace}",
                status="ok",
                detail=(
                    f"{cache_status['file_count']} files, {cache_status['valid_count']} valid, "
                    f"{cache_status['expired_count']} expired, "
                    f"{cache_status['invalid_count']} invalid."
                ),
            )
        )

    effective_attack_mapping_file = attack_mapping_file
    effective_attack_metadata_file = attack_technique_metadata_file
    if effective_attack_mapping_file is None and loaded is not None:
        defaults = loaded.document.defaults
        if defaults.attack_mapping_file:
            effective_attack_mapping_file = Path(defaults.attack_mapping_file)
        if defaults.attack_technique_metadata_file:
            effective_attack_metadata_file = Path(defaults.attack_technique_metadata_file)

    if effective_attack_mapping_file is not None:
        try:
            result = _validate_attack_inputs(
                attack_source=AttackSource.ctid_json.value,
                attack_mapping_file=effective_attack_mapping_file,
                attack_technique_metadata_file=effective_attack_metadata_file,
            )
            status = "warn" if result["warnings"] else "ok"
            detail = (
                f"{result['unique_cves']} CVEs, {result['mapping_count']} mapping objects, "
                f"{result['technique_count']} technique metadata entries."
            )
        except (OSError, ValidationError, ValueError) as exc:
            status = "error"
            detail = str(exc)
        checks.append(DoctorCheck(name="attack_validation", status=status, detail=detail))

    if live:
        checks.extend(_run_live_doctor_checks())

    return DoctorReport(
        generated_at=iso_utc_now(),
        live=live,
        config_file=str(loaded.path) if loaded is not None else None,
        checks=checks,
    )


def _render_doctor_table(report: DoctorReport) -> Table:
    table = Table(title="Doctor Checks", show_lines=False)
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Detail", overflow="fold")
    for check in report.checks:
        table.add_row(check.name, check.status.upper(), check.detail)
    return table


def _run_live_doctor_checks() -> list[DoctorCheck]:
    return [
        _probe_live_source(
            "nvd_api",
            NVD_API_URL,
            params={"cveId": "CVE-2021-44228"},
        ),
        _probe_live_source(
            "epss_api",
            EPSS_API_URL,
            params={"cve": "CVE-2021-44228"},
        ),
        _probe_kev_live_source(),
    ]


def _probe_live_source(
    name: str,
    url: str,
    *,
    params: dict[str, str] | None = None,
) -> DoctorCheck:
    try:
        response = requests.get(url, params=params, timeout=5)
        response.raise_for_status()
    except requests.RequestException as exc:
        return DoctorCheck(name=name, status="error", detail=str(exc))
    return DoctorCheck(name=name, status="ok", detail=f"{url} reachable ({response.status_code}).")


def _probe_kev_live_source() -> DoctorCheck:
    primary = _probe_live_source("kev_feed", KEV_FEED_URL)
    if primary.status == "ok":
        return primary
    mirror = _probe_live_source("kev_mirror", KEV_MIRROR_URL)
    if mirror.status == "ok":
        return DoctorCheck(
            name="kev_feed",
            status="warn",
            detail="Primary KEV feed unreachable; mirror endpoint reachable.",
        )
    return DoctorCheck(
        name="kev_feed",
        status="error",
        detail=f"Primary and mirror KEV endpoints failed: {primary.detail} / {mirror.detail}",
    )


def _unique_path_entries(entries: list[tuple[str, Path]]) -> list[tuple[str, Path]]:
    unique: list[tuple[str, Path]] = []
    seen: set[tuple[str, Path]] = set()
    for label, path in entries:
        key = (label, path)
        if key in seen:
            continue
        seen.add(key)
        unique.append((label, path))
    return unique


def _doctor_check_name(label: str) -> str:
    normalized = label.lower().replace("att&ck", "attack")
    normalized = normalized.replace(" ", "_").replace("&", "and")
    return normalized


def _load_json_document_or_exit(input_path: Path) -> dict:
    try:
        payload = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _exit_input_validation(f"{input_path} is not valid JSON: {exc.msg}.")
    if not isinstance(payload, dict):
        _exit_input_validation(f"{input_path} must contain a top-level JSON object.")
    return payload


def _load_snapshot_payload(input_path: Path) -> dict:
    payload = _load_json_document_or_exit(input_path)
    metadata = payload.get("metadata")
    findings = payload.get("findings")
    if (
        not isinstance(metadata, dict)
        or not isinstance(findings, list)
        or metadata.get("snapshot_kind") != "snapshot"
    ):
        _exit_input_validation(
            "snapshot diff expects JSON files produced by `snapshot create --format json`."
        )
    return payload


def _load_rollup_payload(input_path: Path) -> tuple[str, dict]:
    payload = _load_json_document_or_exit(input_path)
    metadata = payload.get("metadata")
    findings = payload.get("findings")
    if not isinstance(metadata, dict) or not isinstance(findings, list):
        _exit_input_validation("rollup expects an analysis JSON export or a snapshot JSON export.")
    metadata_dict = cast(dict[str, object], metadata)
    input_kind = "snapshot" if metadata_dict.get("snapshot_kind") == "snapshot" else "analysis"
    return input_kind, payload


def _build_snapshot_diff(
    before_payload: dict,
    after_payload: dict,
    *,
    include_unchanged: bool,
) -> tuple[list[SnapshotDiffItem], SnapshotDiffSummary]:
    before_findings = {item["cve_id"]: item for item in before_payload["findings"]}
    after_findings = {item["cve_id"]: item for item in after_payload["findings"]}
    counters = {
        "added": 0,
        "removed": 0,
        "priority_up": 0,
        "priority_down": 0,
        "context_changed": 0,
        "unchanged": 0,
    }
    items: list[SnapshotDiffItem] = []

    for cve_id in sorted(set(before_findings) | set(after_findings)):
        before = before_findings.get(cve_id)
        after = after_findings.get(cve_id)
        if before is None:
            counters["added"] += 1
            items.append(_build_snapshot_diff_item(cve_id, "added", None, after, []))
            continue
        if after is None:
            counters["removed"] += 1
            items.append(_build_snapshot_diff_item(cve_id, "removed", before, None, []))
            continue

        before_rank = int(before.get("priority_rank", 99))
        after_rank = int(after.get("priority_rank", 99))
        if after_rank < before_rank:
            counters["priority_up"] += 1
            items.append(_build_snapshot_diff_item(cve_id, "priority_up", before, after, []))
            continue
        if after_rank > before_rank:
            counters["priority_down"] += 1
            items.append(_build_snapshot_diff_item(cve_id, "priority_down", before, after, []))
            continue

        changed_fields = _find_snapshot_context_changes(before, after)
        if changed_fields:
            counters["context_changed"] += 1
            items.append(
                _build_snapshot_diff_item(cve_id, "context_changed", before, after, changed_fields)
            )
            continue

        counters["unchanged"] += 1
        if include_unchanged:
            items.append(_build_snapshot_diff_item(cve_id, "unchanged", before, after, []))

    items.sort(key=lambda item: (_snapshot_category_order(item.category), item.cve_id))
    return items, SnapshotDiffSummary(**counters)


def _build_snapshot_diff_item(
    cve_id: str,
    category: str,
    before: dict | None,
    after: dict | None,
    changed_fields: list[str],
) -> SnapshotDiffItem:
    return SnapshotDiffItem(
        cve_id=cve_id,
        category=category,
        before_priority=None if before is None else before.get("priority_label"),
        after_priority=None if after is None else after.get("priority_label"),
        before_rank=None if before is None else before.get("priority_rank"),
        after_rank=None if after is None else after.get("priority_rank"),
        before_targets=[] if before is None else before.get("provenance", {}).get("targets", []),
        after_targets=[] if after is None else after.get("provenance", {}).get("targets", []),
        before_asset_ids=[]
        if before is None
        else before.get("provenance", {}).get("asset_ids", []),
        after_asset_ids=[] if after is None else after.get("provenance", {}).get("asset_ids", []),
        before_services=[] if before is None else _finding_services(before),
        after_services=[] if after is None else _finding_services(after),
        context_change_fields=changed_fields,
    )


def _find_snapshot_context_changes(before: dict, after: dict) -> list[str]:
    changed: list[str] = []
    if before.get("in_kev") != after.get("in_kev"):
        changed.append("kev")
    if before.get("attack_mapped") != after.get("attack_mapped"):
        changed.append("attack_mapped")
    if before.get("attack_relevance") != after.get("attack_relevance"):
        changed.append("attack_relevance")
    if sorted(before.get("attack_techniques", [])) != sorted(after.get("attack_techniques", [])):
        changed.append("attack_techniques")
    if sorted(before.get("attack_tactics", [])) != sorted(after.get("attack_tactics", [])):
        changed.append("attack_tactics")
    if sorted(before.get("provenance", {}).get("targets", [])) != sorted(
        after.get("provenance", {}).get("targets", [])
    ):
        changed.append("targets")
    if sorted(before.get("provenance", {}).get("asset_ids", [])) != sorted(
        after.get("provenance", {}).get("asset_ids", [])
    ):
        changed.append("asset_ids")
    if _finding_services(before) != _finding_services(after):
        changed.append("services")
    if before.get("provenance", {}).get("vex_statuses", {}) != after.get("provenance", {}).get(
        "vex_statuses", {}
    ):
        changed.append("vex")
    return changed


def _finding_services(finding: dict) -> list[str]:
    services = sorted(
        {
            occurrence.get("asset_business_service")
            for occurrence in finding.get("provenance", {}).get("occurrences", [])
            if occurrence.get("asset_business_service")
        }
    )
    return services


def _snapshot_category_order(category: str) -> int:
    return {
        "added": 0,
        "removed": 1,
        "priority_up": 2,
        "priority_down": 3,
        "context_changed": 4,
        "unchanged": 5,
    }.get(category, 99)


def _build_rollup_buckets(
    payload: dict,
    *,
    dimension: str,
    top: int,
) -> list[RollupBucket]:
    by_bucket: dict[str, list[dict]] = {}
    for finding in payload.get("findings", []):
        bucket_names = _rollup_bucket_names(finding, dimension=dimension)
        for bucket_name in bucket_names:
            by_bucket.setdefault(bucket_name, []).append(finding)

    buckets: list[RollupBucket] = []
    for bucket_name, findings in by_bucket.items():
        sorted_findings = sorted(findings, key=_rollup_finding_sort_key)
        buckets.append(
            RollupBucket(
                bucket=bucket_name,
                dimension=dimension,
                finding_count=len(findings),
                critical_count=sum(
                    1 for finding in findings if finding.get("priority_label") == "Critical"
                ),
                high_count=sum(
                    1 for finding in findings if finding.get("priority_label") == "High"
                ),
                kev_count=sum(1 for finding in findings if finding.get("in_kev")),
                attack_mapped_count=sum(1 for finding in findings if finding.get("attack_mapped")),
                waived_count=sum(1 for finding in findings if finding.get("waived")),
                highest_priority=str(sorted_findings[0].get("priority_label", "Low")),
                top_cves=[str(finding.get("cve_id")) for finding in sorted_findings[:top]],
                owners=_finding_top_owners(findings, top=top),
                recommended_actions=_finding_top_actions(findings, top=top),
            )
        )

    buckets.sort(key=_rollup_bucket_sort_key)
    return buckets


def _rollup_bucket_names(finding: dict, *, dimension: str) -> list[str]:
    if dimension == RollupBy.asset.value:
        asset_ids = finding.get("provenance", {}).get("asset_ids", [])
        return sorted(asset_ids) if asset_ids else ["Unmapped"]
    services = _finding_services(finding)
    return services if services else ["Unmapped"]


def _rollup_finding_sort_key(finding: dict) -> tuple:
    priority_rank = int(finding.get("priority_rank", 99))
    return (
        priority_rank,
        0 if finding.get("in_kev") else 1,
        -float(finding.get("epss") or 0.0),
        -float(finding.get("cvss_base_score") or 0.0),
        str(finding.get("cve_id", "")),
    )


def _rollup_bucket_sort_key(bucket: RollupBucket) -> tuple:
    rank = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}.get(bucket.highest_priority, 99)
    return (rank, -bucket.critical_count, -bucket.finding_count, bucket.bucket)


def _finding_top_owners(findings: list[dict], *, top: int) -> list[str]:
    counts: dict[str, int] = {}
    for finding in findings:
        owners = {
            occurrence.get("asset_owner")
            for occurrence in finding.get("provenance", {}).get("occurrences", [])
            if occurrence.get("asset_owner")
        }
        for owner in owners:
            owner_str = str(owner)
            counts[owner_str] = counts.get(owner_str, 0) + 1
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [owner for owner, _ in ordered[:top]]


def _finding_top_actions(findings: list[dict], *, top: int) -> list[str]:
    counts: dict[str, int] = {}
    for finding in findings:
        action = str(finding.get("recommended_action") or "").strip()
        if not action:
            continue
        counts[action] = counts.get(action, 0) + 1
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [action for action, _ in ordered[:top]]


def _exit_input_validation(message: str) -> None:
    console.print(f"[red]Input validation failed:[/red] {message}")
    raise typer.Exit(code=2)


def _load_analysis_report_payload(input_path: Path) -> dict:
    try:
        payload = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _exit_input_validation(f"{input_path} is not valid JSON: {exc.msg}.")

    if not isinstance(payload, dict):
        _exit_input_validation(
            "report commands expect an analysis JSON export produced by `analyze`."
        )

    metadata = payload.get("metadata")
    findings = payload.get("findings")
    if not isinstance(metadata, dict) or not isinstance(findings, list):
        _exit_input_validation(
            "report commands expect an analysis JSON export produced by `analyze`."
        )
    return payload


def _write_evidence_bundle(
    *,
    analysis_path: Path,
    output_path: Path,
    payload: dict,
    include_input_copy: bool,
) -> EvidenceBundleManifest:
    metadata = payload.get("metadata", {})
    attack_summary = payload.get("attack_summary", {})
    bundle_entries: list[tuple[str, bytes, str]] = [
        ("analysis.json", analysis_path.read_bytes(), "analysis-json"),
        ("report.html", generate_html_report(payload).encode("utf-8"), "html-report"),
        ("summary.md", generate_summary_markdown(payload).encode("utf-8"), "markdown-summary"),
    ]
    resolved_input = _resolve_analysis_input_path(metadata.get("input_path"), analysis_path)
    included_input_copy = False
    if include_input_copy:
        if resolved_input is not None:
            bundle_entries.append(
                (
                    f"input/{resolved_input.name}",
                    resolved_input.read_bytes(),
                    "source-input",
                )
            )
            included_input_copy = True
        elif metadata.get("input_path"):
            console.print(
                "[yellow]Referenced input file could not be resolved; bundle will omit the "
                "original input copy.[/yellow]"
            )

    file_entries = [
        _bundle_file_entry(path=path, content=content, kind=kind)
        for path, content, kind in bundle_entries
    ]
    manifest = EvidenceBundleManifest(
        generated_at=iso_utc_now(),
        source_analysis_path=str(analysis_path),
        source_input_path=str(metadata.get("input_path")) if metadata.get("input_path") else None,
        findings_count=int(metadata.get("findings_count", 0)),
        kev_hits=int(metadata.get("kev_hits", 0)),
        waived_count=int(metadata.get("waived_count", 0)),
        attack_mapped_cves=int(attack_summary.get("mapped_cves", 0)),
        included_input_copy=included_input_copy,
        files=file_entries,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, content, _kind in bundle_entries:
            archive.writestr(path, content)
        archive.writestr("manifest.json", generate_evidence_bundle_manifest_json(manifest))
    return manifest


def _resolve_analysis_input_path(reported_path: object, analysis_path: Path) -> Path | None:
    if not isinstance(reported_path, str) or not reported_path.strip():
        return None
    candidate = Path(reported_path).expanduser()
    paths = (
        [candidate]
        if candidate.is_absolute()
        else [Path.cwd() / candidate, analysis_path.parent / candidate]
    )
    for path in paths:
        resolved = path.resolve()
        if resolved.is_file():
            return resolved
    return None


def _bundle_file_entry(*, path: str, content: bytes, kind: str) -> EvidenceBundleFile:
    return EvidenceBundleFile(
        path=path,
        kind=kind,
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )


def _handle_fail_on(findings: list[PrioritizedFinding], fail_on: PriorityFilter) -> None:
    threshold = PRIORITY_LABELS[fail_on]
    ordered = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
    active_findings = [finding for finding in findings if not finding.waived]
    if any(ordered[finding.priority_label] <= ordered[threshold] for finding in active_findings):
        raise typer.Exit(code=1)


def _load_attack_only(
    cve_ids: list[str],
    *,
    attack_source: str,
    attack_mapping_file: Path,
    attack_technique_metadata_file: Path | None,
) -> tuple[list[AttackData], dict[str, str | None], list[str]]:
    provider = AttackProvider()
    attack_data, metadata, warnings = provider.fetch_many(
        cve_ids,
        enabled=True,
        source=attack_source,
        mapping_file=attack_mapping_file,
        technique_metadata_file=attack_technique_metadata_file,
    )
    items = [attack_data.get(cve_id, AttackData(cve_id=cve_id)) for cve_id in cve_ids]
    return items, metadata, warnings


def _load_attack_only_or_exit(
    cve_ids: list[str],
    *,
    attack_source: str,
    attack_mapping_file: Path,
    attack_technique_metadata_file: Path | None,
) -> tuple[list[AttackData], dict[str, str | None], list[str]]:
    try:
        return _load_attack_only(
            cve_ids,
            attack_source=attack_source,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
        )
    except (OSError, ValidationError, ValueError) as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc


def _render_attack_coverage_table(attack_items: list[AttackData]) -> Table:
    table = Table(title="ATT&CK Coverage", show_lines=False)
    table.add_column("CVE", style="bold")
    table.add_column("Mapped")
    table.add_column("Relevance")
    table.add_column("Techniques")
    table.add_column("Tactics")
    table.add_column("Mapping Types")

    for item in attack_items:
        table.add_row(
            item.cve_id,
            "Yes" if item.mapped else "No",
            item.attack_relevance,
            ", ".join(item.attack_techniques) or "N.A.",
            ", ".join(item.attack_tactics) or "N.A.",
            ", ".join(item.mapping_types) or "N.A.",
        )
    return table


def _generate_attack_coverage_markdown(
    *,
    input_path: str,
    attack_items: list[AttackData],
    summary: AttackSummary,
    metadata: dict[str, str | None],
    warnings: list[str],
) -> str:
    lines = [
        "# ATT&CK Coverage",
        "",
        f"- Input file: `{input_path}`",
        f"- ATT&CK source: `{metadata['source']}`",
        f"- Mapping file: `{metadata['mapping_file']}`",
        f"- Technique metadata file: `{metadata.get('technique_metadata_file') or 'N.A.'}`",
        f"- Mapped CVEs: {summary.mapped_cves}",
        f"- Unmapped CVEs: {summary.unmapped_cves}",
        "- Mapping type distribution: " + _format_distribution(summary.mapping_type_distribution),
        "- Technique distribution: " + _format_distribution(summary.technique_distribution),
        "- Tactic distribution: " + _format_distribution(summary.tactic_distribution),
        "",
        "## Items",
        "",
        "| CVE ID | Mapped | Relevance | Techniques | Tactics | Mapping Types |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in attack_items:
        lines.append(
            "| "
            + " | ".join(
                [
                    item.cve_id,
                    "Yes" if item.mapped else "No",
                    item.attack_relevance,
                    ", ".join(item.attack_techniques) or "N.A.",
                    ", ".join(item.attack_tactics) or "N.A.",
                    ", ".join(item.mapping_types) or "N.A.",
                ]
            )
            + " |"
        )
    lines.extend(["", "## Warnings"])
    if warnings:
        lines.extend(f"- {warning}" for warning in warnings)
    else:
        lines.append("- None")
    return "\n".join(lines) + "\n"


def _format_distribution(distribution: dict[str, int]) -> str:
    if not distribution:
        return "None"
    return ", ".join(
        f"{key}: {value}"
        for key, value in sorted(distribution.items(), key=lambda item: (-item[1], item[0]))
    )


def _validate_requested_attack_mode(
    *,
    attack_enabled: bool,
    attack_source: str,
    attack_mapping_file: Path | None,
    offline_attack_file: Path | None,
) -> None:
    if not attack_enabled or attack_source == AttackSource.none.value:
        return
    if attack_mapping_file is not None or offline_attack_file is not None:
        return
    _exit_input_validation(
        "ATT&CK mode requires --attack-mapping-file or legacy --offline-attack-file."
    )


def _values_mismatch(left: str | None, right: str | None) -> bool:
    if left is None or right is None:
        return False
    return left.strip().lower() != right.strip().lower()


def main() -> None:
    """Entrypoint used by the console script."""
    app()


if __name__ == "__main__":
    main()
