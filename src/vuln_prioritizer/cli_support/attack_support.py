"""ATT&CK-focused CLI helpers used by command modules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import ValidationError
from rich.panel import Panel
from rich.table import Table

from vuln_prioritizer.inputs import InputLoader, InputSpec
from vuln_prioritizer.models import AttackData, AttackSummary
from vuln_prioritizer.providers.attack import AttackProvider
from vuln_prioritizer.providers.attack_metadata import AttackMetadataProvider
from vuln_prioritizer.providers.ctid_mappings import CtidMappingsProvider

from .common import AttackSource, exit_input_validation


def validate_attack_inputs_or_exit(
    *,
    attack_source: str,
    attack_mapping_file: Path,
    attack_technique_metadata_file: Path | None,
) -> dict[str, Any]:
    try:
        return validate_attack_inputs(
            attack_source=attack_source,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
        )
    except (OSError, ValidationError, ValueError) as exc:
        exit_input_validation(str(exc))
    raise AssertionError("unreachable")


def validate_attack_inputs(
    *,
    attack_source: str,
    attack_mapping_file: Path,
    attack_technique_metadata_file: Path | None,
) -> dict[str, Any]:
    if attack_source == AttackSource.none.value:
        raise ValueError("ATT&CK utility commands require --attack-source ctid-json or local-csv.")

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
            domain_mismatch = values_mismatch(
                mapping_metadata.get("domain"),
                technique_metadata.get("domain"),
            )
            if domain_mismatch:
                warnings.append(
                    "ATT&CK domain mismatch between CTID mappings and technique metadata: "
                    f"{mapping_metadata.get('domain') or 'N.A.'} vs "
                    f"{technique_metadata.get('domain') or 'N.A.'}."
                )
            attack_version_mismatch = values_mismatch(
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
        "schema_version": "1.2.0",
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


def render_attack_validation_panel(result: dict[str, Any]) -> Panel:
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


def generate_attack_validation_markdown(result: dict[str, Any]) -> str:
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


def read_input_cves(input_path: Path, *, max_cves: int | None) -> tuple[list[str], int, list[str]]:
    try:
        parsed_input = InputLoader().load(input_path, input_format="auto", max_cves=max_cves)
    except (ValidationError, ValueError) as exc:
        exit_input_validation(str(exc))
    return parsed_input.unique_cves, parsed_input.total_rows, parsed_input.warnings


def read_input_cves_from_specs(
    input_specs: list[InputSpec],
    *,
    max_cves: int | None,
) -> tuple[list[str], int, list[str], list[dict[str, object]], str, list[str]]:
    try:
        parsed_input = InputLoader().load_many(input_specs, max_cves=max_cves)
    except (ValidationError, ValueError) as exc:
        exit_input_validation(str(exc))
    return (
        parsed_input.unique_cves,
        parsed_input.total_rows,
        parsed_input.warnings,
        [summary.model_dump() for summary in parsed_input.source_summaries],
        parsed_input.input_format,
        parsed_input.input_paths,
    )


def load_attack_only(
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


def load_attack_only_or_exit(
    cve_ids: list[str],
    *,
    attack_source: str,
    attack_mapping_file: Path,
    attack_technique_metadata_file: Path | None,
) -> tuple[list[AttackData], dict[str, str | None], list[str]]:
    try:
        return load_attack_only(
            cve_ids,
            attack_source=attack_source,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
        )
    except (OSError, ValidationError, ValueError) as exc:
        exit_input_validation(str(exc))
    raise AssertionError("unreachable")


def render_attack_coverage_table(attack_items: list[AttackData]) -> Table:
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


def generate_attack_coverage_markdown(
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
        "- Mapping type distribution: " + format_distribution(summary.mapping_type_distribution),
        "- Technique distribution: " + format_distribution(summary.technique_distribution),
        "- Tactic distribution: " + format_distribution(summary.tactic_distribution),
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


def format_distribution(distribution: dict[str, int]) -> str:
    if not distribution:
        return "None"
    return ", ".join(
        f"{key}: {value}"
        for key, value in sorted(distribution.items(), key=lambda item: (-item[1], item[0]))
    )


def values_mismatch(left: str | None, right: str | None) -> bool:
    if left is None or right is None:
        return False
    return left.strip().lower() != right.strip().lower()
