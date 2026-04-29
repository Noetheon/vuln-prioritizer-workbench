"""Parsers for scanner and advisory export inputs."""

from __future__ import annotations

import json
from pathlib import Path

from vuln_prioritizer.models import InputOccurrence, ParsedInput

from .. import _cve_support
from .common import (
    as_string_list,
    dict_items,
    dict_value,
    first_present_string,
    first_string_from_list,
    load_json_object,
    split_versions,
)


def parse_trivy_json(path: Path) -> ParsedInput:
    document = load_json_object(path, "Trivy JSON")
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    total_rows = 0

    for result_index, result in enumerate(dict_items(document.get("Results")), start=1):
        target = first_present_string(result.get("Target"), document.get("ArtifactName"))
        package_type = first_present_string(result.get("Type"))
        for vuln_index, vulnerability in enumerate(
            dict_items(result.get("Vulnerabilities")),
            start=1,
        ):
            total_rows += 1
            source_id = first_present_string(vulnerability.get("VulnerabilityID"))
            cve_id = _cve_support.first_normalized_cve(_trivy_cve_candidates(vulnerability))
            if cve_id is None:
                _warn_non_cve_trivy_id(source_id, warnings)
                continue
            occurrences.append(
                InputOccurrence(
                    cve_id=cve_id,
                    source_format="trivy-json",
                    source_id=source_id or cve_id,
                    component_name=vulnerability.get("PkgName"),
                    component_version=vulnerability.get("InstalledVersion"),
                    purl=dict_value(vulnerability.get("PkgIdentifier")).get("PURL"),
                    package_type=package_type,
                    file_path=vulnerability.get("PkgPath"),
                    fix_versions=_trivy_fix_versions(vulnerability),
                    source_record_id=f"result:{result_index}:vuln:{vuln_index}",
                    raw_severity=vulnerability.get("Severity"),
                    target_kind="image",
                    target_ref=target,
                )
            )

    return ParsedInput(
        input_format="trivy-json",
        total_rows=total_rows,
        occurrences=occurrences,
        warnings=warnings,
    )


def _trivy_cve_candidates(vulnerability: dict) -> list[str | None]:
    candidates: list[str | None] = []
    for field_name in ("VulnerabilityID", "CVE", "CVEID", "CVEs", "CVEIDs", "Aliases"):
        value = vulnerability.get(field_name)
        if isinstance(value, str):
            candidates.append(value)
            continue
        if isinstance(value, list):
            candidates.extend(str(item) for item in value if item is not None)
    return candidates


def _warn_non_cve_trivy_id(source_id: str | None, warnings: list[str]) -> None:
    warnings.append(f"Ignored non-CVE Trivy vulnerability identifier: {source_id!r}")


def _trivy_fix_versions(vulnerability: dict) -> list[str]:
    for field_name in ("FixedVersion", "FixedVersions"):
        versions = split_versions(vulnerability.get(field_name))
        if versions:
            return versions
    return []


def parse_grype_json(path: Path) -> ParsedInput:
    document = load_json_object(path, "Grype JSON")
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    source = dict_value(document.get("source"))
    target = dict_value(source.get("target"))
    source_target = target.get("userInput") or target.get("name")
    matches = dict_items(document.get("matches"))

    for index, match in enumerate(matches, start=1):
        vulnerability = dict_value(match.get("vulnerability"))
        cve_id = _cve_support.normalize_cve_or_warn(
            vulnerability.get("id"),
            source_name="Grype",
            warnings=warnings,
        )
        if cve_id is None:
            continue
        artifact = dict_value(match.get("artifact"))
        locations = dict_items(artifact.get("locations"))
        file_path = None
        if locations:
            file_path = locations[0].get("path") or locations[0].get("realPath")
        occurrences.append(
            InputOccurrence(
                cve_id=cve_id,
                source_format="grype-json",
                component_name=artifact.get("name"),
                component_version=artifact.get("version"),
                purl=artifact.get("purl"),
                package_type=artifact.get("type"),
                file_path=file_path,
                fix_versions=as_string_list(dict_value(match.get("fix")).get("versions")),
                source_record_id=f"match:{index}",
                raw_severity=vulnerability.get("severity"),
                target_kind="image",
                target_ref=source_target,
            )
        )

    return ParsedInput(
        input_format="grype-json",
        total_rows=len(matches),
        occurrences=occurrences,
        warnings=warnings,
    )


def parse_dependency_check_json(path: Path) -> ParsedInput:
    document = load_json_object(path, "Dependency-Check JSON")
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    dependencies = dict_items(document.get("dependencies"))

    for dep_index, dependency in enumerate(dependencies, start=1):
        for vuln_index, vulnerability in enumerate(
            dict_items(dependency.get("vulnerabilities")),
            start=1,
        ):
            cve_id = _cve_support.normalize_cve_or_warn(
                vulnerability.get("name"),
                source_name="Dependency-Check",
                warnings=warnings,
            )
            if cve_id is None:
                continue
            occurrences.append(
                InputOccurrence(
                    cve_id=cve_id,
                    source_format="dependency-check-json",
                    component_name=dependency.get("fileName"),
                    file_path=dependency.get("filePath"),
                    source_record_id=f"dependency:{dep_index}:vuln:{vuln_index}",
                    raw_severity=vulnerability.get("severity"),
                    target_kind="filesystem",
                    target_ref=first_string_from_list(dependency.get("projectReferences")),
                )
            )

    return ParsedInput(
        input_format="dependency-check-json",
        total_rows=len(dependencies),
        occurrences=occurrences,
        warnings=warnings,
    )


def parse_github_alerts_json(path: Path) -> ParsedInput:
    document = json.loads(path.read_text(encoding="utf-8"))
    raw_alerts: list[object]
    if isinstance(document, list):
        raw_alerts = document
    elif isinstance(document, dict):
        if "alerts" in document:
            alerts_value = document.get("alerts")
            if not isinstance(alerts_value, list):
                raise ValueError("GitHub alerts JSON `alerts` must be a list.")
            raw_alerts = alerts_value
        else:
            raw_alerts = [document]
    else:
        raise ValueError("GitHub alerts JSON must be an alert object, an alerts object, or a list.")
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    alerts = dict_items(raw_alerts)
    skipped_alert_items = len(raw_alerts) - len(alerts)
    if skipped_alert_items:
        warnings.append(
            f"Ignored {skipped_alert_items} GitHub alert item(s) that were not JSON objects."
        )

    for index, alert in enumerate(alerts, start=1):
        advisory = dict_value(alert.get("security_advisory"))
        identifiers = dict_items(advisory.get("identifiers"))
        cve_id = _cve_support.first_normalized_cve(
            [advisory.get("cve_id"), *(identifier.get("value") for identifier in identifiers)]
        )
        if cve_id is None:
            warnings.append(
                "Ignored GitHub alert without a resolvable CVE identifier: "
                f"{advisory.get('ghsa_id') or alert.get('number')!r}"
            )
            continue
        dependency = dict_value(alert.get("dependency"))
        package = dict_value(dependency.get("package"))
        vulnerability = dict_value(alert.get("security_vulnerability"))
        first_patched_version = vulnerability.get("first_patched_version")
        first_patched_version = (
            first_patched_version if isinstance(first_patched_version, dict) else {}
        )
        occurrences.append(
            InputOccurrence(
                cve_id=cve_id,
                source_format="github-alerts-json",
                component_name=package.get("name"),
                component_version=first_present_string(
                    dependency.get("package_version"),
                    dependency.get("version"),
                    package.get("version"),
                    vulnerability.get("package_version"),
                    vulnerability.get("version"),
                ),
                package_type=package.get("ecosystem"),
                file_path=dependency.get("manifest_path"),
                fix_versions=as_string_list([first_patched_version.get("identifier")]),
                source_record_id=f"alert:{index}",
                raw_severity=advisory.get("severity"),
                target_kind="repository",
                target_ref=alert.get("html_url") or dependency.get("manifest_path"),
            )
        )

    return ParsedInput(
        input_format="github-alerts-json",
        total_rows=len(raw_alerts),
        occurrences=occurrences,
        warnings=warnings,
    )
