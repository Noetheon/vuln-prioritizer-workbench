"""Parsers for SBOM input formats."""

from __future__ import annotations

from pathlib import Path

from vuln_prioritizer.models import InputOccurrence, ParsedInput

from .. import _cve_support
from .common import dict_items, dict_value, load_json_object


def parse_cyclonedx_json(path: Path) -> ParsedInput:
    document = load_json_object(path, "CycloneDX JSON")
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    component_by_ref = {
        component.get("bom-ref"): component
        for component in dict_items(document.get("components"))
        if component.get("bom-ref")
    }
    target_ref = dict_value(dict_value(document.get("metadata")).get("component")).get("name")

    for index, vulnerability in enumerate(dict_items(document.get("vulnerabilities")), start=1):
        cve_id = _cve_support.normalize_cve_or_warn(
            vulnerability.get("id"),
            source_name="CycloneDX",
            warnings=warnings,
        )
        if cve_id is None:
            continue
        affects = dict_items(vulnerability.get("affects"))
        if not affects:
            occurrences.append(
                InputOccurrence(
                    cve_id=cve_id,
                    source_format="cyclonedx-json",
                    source_record_id=f"vulnerability:{index}",
                    raw_severity=_cyclonedx_rating(vulnerability),
                    target_kind="repository",
                    target_ref=target_ref,
                )
            )
            continue
        for affect_index, affect in enumerate(affects, start=1):
            reference = affect.get("ref")
            component = component_by_ref.get(reference, {})
            occurrences.append(
                InputOccurrence(
                    cve_id=cve_id,
                    source_format="cyclonedx-json",
                    component_name=component.get("name"),
                    component_version=component.get("version"),
                    purl=component.get("purl"),
                    package_type=component.get("type"),
                    file_path=dict_value(dict_value(component.get("evidence")).get("identity")).get(
                        "field"
                    ),
                    source_record_id=f"vulnerability:{index}:affect:{affect_index}",
                    raw_severity=_cyclonedx_rating(vulnerability),
                    target_kind="repository",
                    target_ref=target_ref,
                )
            )

    return ParsedInput(
        input_format="cyclonedx-json",
        total_rows=len(dict_items(document.get("vulnerabilities"))),
        occurrences=occurrences,
        warnings=warnings,
    )


def parse_spdx_json(path: Path) -> ParsedInput:
    document = load_json_object(path, "SPDX JSON")
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    packages = {
        package.get("SPDXID"): package
        for package in dict_items(document.get("packages"))
        if package.get("SPDXID")
    }

    for index, vulnerability in enumerate(dict_items(document.get("vulnerabilities")), start=1):
        cve_id = _cve_support.normalize_cve_or_warn(
            vulnerability.get("id"),
            source_name="SPDX",
            warnings=warnings,
        )
        if cve_id is None:
            continue
        affects = dict_items(vulnerability.get("affects"))
        if not affects:
            occurrences.append(
                InputOccurrence(
                    cve_id=cve_id,
                    source_format="spdx-json",
                    source_record_id=f"vulnerability:{index}",
                    raw_severity=vulnerability.get("severity"),
                    target_kind="repository",
                    target_ref=document.get("name"),
                )
            )
            continue
        for affect_index, affect in enumerate(affects, start=1):
            package = packages.get(affect.get("ref"), {})
            occurrences.append(
                InputOccurrence(
                    cve_id=cve_id,
                    source_format="spdx-json",
                    component_name=package.get("name"),
                    component_version=package.get("versionInfo"),
                    purl=_spdx_purl(package),
                    package_type=package.get("primaryPackagePurpose"),
                    file_path=package.get("downloadLocation"),
                    source_record_id=f"vulnerability:{index}:affect:{affect_index}",
                    raw_severity=vulnerability.get("severity"),
                    target_kind="repository",
                    target_ref=document.get("name"),
                )
            )

    return ParsedInput(
        input_format="spdx-json",
        total_rows=len(dict_items(document.get("vulnerabilities"))),
        occurrences=occurrences,
        warnings=warnings,
    )


def _cyclonedx_rating(vulnerability: dict) -> str | None:
    ratings = dict_items(vulnerability.get("ratings"))
    if not ratings:
        return None
    severity = ratings[0].get("severity")
    return str(severity) if severity else None


def _spdx_purl(package: dict) -> str | None:
    for reference in dict_items(package.get("externalRefs")):
        if reference.get("referenceType") == "purl":
            return reference.get("referenceLocator")
    return None
