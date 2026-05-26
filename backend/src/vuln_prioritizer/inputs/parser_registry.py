"""Static input parser registry."""

from __future__ import annotations

from .parsers import (
    parse_cve_list,
    parse_cyclonedx_json,
    parse_dependency_check_json,
    parse_generic_occurrence_csv,
    parse_github_alerts_json,
    parse_grype_json,
    parse_nessus_xml,
    parse_openvas_xml,
    parse_spdx_json,
    parse_trivy_json,
)
from .sdk import InputParserDefinition, build_input_parser_registry

INPUT_PARSER_DEFINITIONS: tuple[InputParserDefinition, ...] = (
    # CVE lists and occurrence CSVs.
    InputParserDefinition(
        name="cve-list",
        parser=parse_cve_list,
        file_suffixes=(".txt", ".csv"),
        media_types=("text/plain", "text/csv"),
        fixture_names=("sample_cves.txt",),
    ),
    InputParserDefinition(
        name="generic-occurrence-csv",
        parser=parse_generic_occurrence_csv,
        file_suffixes=(".csv",),
        media_types=("text/csv",),
        fixture_names=("generic_occurrences.csv",),
    ),
    # Scanner and advisory exports.
    InputParserDefinition(
        name="trivy-json",
        parser=parse_trivy_json,
        file_suffixes=(".json",),
        media_types=("application/json",),
        fixture_names=("trivy_report.json",),
    ),
    InputParserDefinition(
        name="grype-json",
        parser=parse_grype_json,
        file_suffixes=(".json",),
        media_types=("application/json",),
        fixture_names=("grype_report.json",),
    ),
    InputParserDefinition(
        name="dependency-check-json",
        parser=parse_dependency_check_json,
        file_suffixes=(".json",),
        media_types=("application/json",),
        fixture_names=("dependency_check_report.json",),
    ),
    InputParserDefinition(
        name="github-alerts-json",
        parser=parse_github_alerts_json,
        file_suffixes=(".json",),
        media_types=("application/json",),
        fixture_names=("github_alerts_export.json",),
    ),
    # SBOM formats.
    InputParserDefinition(
        name="cyclonedx-json",
        parser=parse_cyclonedx_json,
        file_suffixes=(".json",),
        media_types=("application/json",),
        fixture_names=("cyclonedx_bom.json",),
    ),
    InputParserDefinition(
        name="spdx-json",
        parser=parse_spdx_json,
        file_suffixes=(".json",),
        media_types=("application/json",),
        fixture_names=("spdx_bom.json",),
    ),
    # XML scanner exports; parsing stays limited to safe local XML support.
    InputParserDefinition(
        name="nessus-xml",
        parser=parse_nessus_xml,
        file_suffixes=(".nessus", ".xml"),
        media_types=("application/xml", "text/xml"),
        fixture_names=("nessus_report.nessus",),
    ),
    InputParserDefinition(
        name="openvas-xml",
        parser=parse_openvas_xml,
        file_suffixes=(".xml",),
        media_types=("application/xml", "text/xml"),
        fixture_names=("openvas_report.xml",),
    ),
)

_INPUT_PARSERS = dict(build_input_parser_registry(INPUT_PARSER_DEFINITIONS))


__all__ = [
    "INPUT_PARSER_DEFINITIONS",
    "_INPUT_PARSERS",
]
