"""Input normalization for CVE lists, scanners, SBOMs, asset context, and VEX."""

from __future__ import annotations

import csv
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

from vuln_prioritizer.models import (
    AssetContextRecord,
    InputOccurrence,
    ParsedInput,
    VexStatement,
)
from vuln_prioritizer.utils import normalize_cve_id


class InputLoader:
    """Load different source formats into a normalized occurrence model."""

    def load(
        self,
        path: Path,
        *,
        input_format: str = "auto",
        max_cves: int | None = None,
        target_kind: str | None = None,
        target_ref: str | None = None,
        asset_records: dict[tuple[str, str], AssetContextRecord] | None = None,
        vex_statements: list[VexStatement] | None = None,
    ) -> ParsedInput:
        if not path.exists() or not path.is_file():
            raise ValueError(f"Input file does not exist: {path}")

        resolved_format = detect_input_format(path, explicit_format=input_format)
        if resolved_format == "cve-list":
            parsed = _parse_cve_list(path)
        elif resolved_format == "trivy-json":
            parsed = _parse_trivy_json(path)
        elif resolved_format == "grype-json":
            parsed = _parse_grype_json(path)
        elif resolved_format == "cyclonedx-json":
            parsed = _parse_cyclonedx_json(path)
        elif resolved_format == "spdx-json":
            parsed = _parse_spdx_json(path)
        elif resolved_format == "dependency-check-json":
            parsed = _parse_dependency_check_json(path)
        elif resolved_format == "github-alerts-json":
            parsed = _parse_github_alerts_json(path)
        elif resolved_format == "nessus-xml":
            parsed = _parse_nessus_xml(path)
        elif resolved_format == "openvas-xml":
            parsed = _parse_openvas_xml(path)
        else:
            raise ValueError(f"Unsupported input format: {resolved_format}")

        occurrences = [
            _apply_manual_target(occurrence, target_kind=target_kind, target_ref=target_ref)
            for occurrence in parsed.occurrences
        ]
        occurrences = _apply_asset_context(occurrences, asset_records or {})
        occurrences = _apply_vex_statements(occurrences, vex_statements or [])

        final = _finalize_occurrences(
            occurrences,
            input_format=resolved_format,
            warnings=parsed.warnings,
            total_rows=parsed.total_rows,
            max_cves=max_cves,
        )
        return final


def build_inline_input(
    cve_id: str,
    *,
    target_kind: str | None = None,
    target_ref: str | None = None,
    asset_records: dict[tuple[str, str], AssetContextRecord] | None = None,
    vex_statements: list[VexStatement] | None = None,
) -> ParsedInput:
    """Build a parsed input for a single inline CVE."""
    occurrence = InputOccurrence(
        cve_id=cve_id,
        source_format="cve-list",
        source_record_id="inline:1",
        target_kind=(target_kind or "generic").lower(),
        target_ref=target_ref,
    )
    occurrences = _apply_asset_context([occurrence], asset_records or {})
    occurrences = _apply_vex_statements(occurrences, vex_statements or [])
    return _finalize_occurrences(
        occurrences,
        input_format="cve-list",
        warnings=[],
        total_rows=1,
        max_cves=1,
    )


def detect_input_format(path: Path, *, explicit_format: str = "auto") -> str:
    """Resolve the effective input format."""
    if explicit_format != "auto":
        return explicit_format

    suffix = path.suffix.lower()
    if suffix in {".txt", ".csv"}:
        return "cve-list"
    if suffix == ".nessus":
        return "nessus-xml"
    if suffix == ".xml":
        root = _load_xml_root(path)
        if _looks_like_nessus_document(root):
            return "nessus-xml"
        if _looks_like_openvas_document(root):
            return "openvas-xml"
        raise ValueError(
            "Unable to auto-detect the XML input format. "
            "Use --input-format nessus-xml or --input-format openvas-xml."
        )
    if suffix != ".json":
        raise ValueError(
            "Unable to auto-detect the input format. "
            "Use --input-format for non-.txt/.csv/.json/.xml/.nessus files."
        )

    document = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(document, dict) and "Results" in document:
        return "trivy-json"
    if isinstance(document, dict) and "matches" in document:
        return "grype-json"
    if (
        isinstance(document, dict)
        and "bomFormat" in document
        and "CycloneDX" in str(document.get("bomFormat"))
    ):
        return "cyclonedx-json"
    if isinstance(document, dict) and "spdxVersion" in document:
        return "spdx-json"
    if isinstance(document, dict) and "scanInfo" in document and "dependencies" in document:
        return "dependency-check-json"
    if isinstance(document, list) or (
        isinstance(document, dict) and ("alerts" in document or "security_advisory" in document)
    ):
        return "github-alerts-json"
    raise ValueError("Unable to auto-detect the JSON input format.")


def load_asset_context_file(path: Path | None) -> dict[tuple[str, str], AssetContextRecord]:
    """Load exact-match asset context records from CSV."""
    if path is None:
        return {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("Asset context CSV is missing a header row.")
        required = {"target_kind", "target_ref", "asset_id"}
        missing = required - {field.strip() for field in reader.fieldnames if field}
        if missing:
            raise ValueError(
                "Asset context CSV must contain columns: target_kind, target_ref, asset_id."
            )

        records: dict[tuple[str, str], AssetContextRecord] = {}
        for row in reader:
            target_kind = (row.get("target_kind") or "").strip().lower()
            target_ref = (row.get("target_ref") or "").strip()
            asset_id = (row.get("asset_id") or "").strip()
            if not target_kind or not target_ref or not asset_id:
                continue
            records[(target_kind, target_ref)] = AssetContextRecord(
                target_kind=target_kind,
                target_ref=target_ref,
                asset_id=asset_id,
                criticality=(row.get("criticality") or "").strip() or None,
                exposure=(row.get("exposure") or "").strip() or None,
                environment=(row.get("environment") or "").strip() or None,
                owner=(row.get("owner") or "").strip() or None,
                business_service=(row.get("business_service") or "").strip() or None,
            )
    return records


def load_vex_files(paths: list[Path] | None) -> list[VexStatement]:
    """Load all supported VEX files."""
    statements: list[VexStatement] = []
    for path in paths or []:
        if not path.exists() or not path.is_file():
            raise ValueError(f"VEX file does not exist: {path}")
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and "statements" in document:
            statements.extend(_parse_openvex_document(document))
        elif (
            isinstance(document, dict)
            and "bomFormat" in document
            and "CycloneDX" in str(document.get("bomFormat"))
        ):
            statements.extend(_parse_cyclonedx_vex_document(document))
        else:
            raise ValueError(
                f"Unsupported VEX format for {path}. Use OpenVEX JSON or CycloneDX VEX JSON."
            )
    return statements


def _parse_cve_list(path: Path) -> ParsedInput:
    suffix = path.suffix.lower()
    if suffix not in {".txt", ".csv"}:
        raise ValueError("Unsupported input format. Use .txt or .csv files.")

    rows = _read_txt(path) if suffix == ".txt" else _read_csv(path)
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []

    for line_number, raw_value in rows:
        cve_id = normalize_cve_id(raw_value)
        if cve_id is None:
            warnings.append(f"Ignored invalid CVE identifier at line {line_number}: {raw_value!r}")
            continue
        occurrences.append(
            InputOccurrence(
                cve_id=cve_id,
                source_format="cve-list",
                source_record_id=f"line:{line_number}",
            )
        )

    return ParsedInput(
        input_format="cve-list",
        total_rows=len(rows),
        occurrences=occurrences,
        warnings=warnings,
    )


def _parse_trivy_json(path: Path) -> ParsedInput:
    document = json.loads(path.read_text(encoding="utf-8"))
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    total_rows = 0

    for result_index, result in enumerate(document.get("Results", []), start=1):
        target = result.get("Target")
        package_type = result.get("Type")
        for vuln_index, vulnerability in enumerate(result.get("Vulnerabilities", []), start=1):
            total_rows += 1
            cve_id = normalize_cve_id(vulnerability.get("VulnerabilityID"))
            if cve_id is None:
                warnings.append(
                    "Ignored non-CVE Trivy vulnerability identifier: "
                    f"{vulnerability.get('VulnerabilityID')!r}"
                )
                continue
            fix_versions = _split_versions(vulnerability.get("FixedVersion"))
            occurrences.append(
                InputOccurrence(
                    cve_id=cve_id,
                    source_format="trivy-json",
                    component_name=vulnerability.get("PkgName"),
                    component_version=vulnerability.get("InstalledVersion"),
                    purl=vulnerability.get("PkgIdentifier", {}).get("PURL"),
                    package_type=package_type,
                    file_path=vulnerability.get("PkgPath"),
                    fix_versions=fix_versions,
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


def _parse_grype_json(path: Path) -> ParsedInput:
    document = json.loads(path.read_text(encoding="utf-8"))
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    source_target = document.get("source", {}).get("target", {}).get("userInput") or document.get(
        "source", {}
    ).get("target", {}).get("name")

    for index, match in enumerate(document.get("matches", []), start=1):
        vulnerability = match.get("vulnerability", {})
        cve_id = normalize_cve_id(vulnerability.get("id"))
        if cve_id is None:
            warnings.append(
                f"Ignored non-CVE Grype vulnerability identifier: {vulnerability.get('id')!r}"
            )
            continue
        artifact = match.get("artifact", {})
        locations = artifact.get("locations", [])
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
                fix_versions=_as_string_list(match.get("fix", {}).get("versions")),
                source_record_id=f"match:{index}",
                raw_severity=vulnerability.get("severity"),
                target_kind="image",
                target_ref=source_target,
            )
        )

    return ParsedInput(
        input_format="grype-json",
        total_rows=len(document.get("matches", [])),
        occurrences=occurrences,
        warnings=warnings,
    )


def _parse_cyclonedx_json(path: Path) -> ParsedInput:
    document = json.loads(path.read_text(encoding="utf-8"))
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    component_by_ref = {
        component.get("bom-ref"): component
        for component in document.get("components", [])
        if component.get("bom-ref")
    }
    target_ref = document.get("metadata", {}).get("component", {}).get("name")

    for index, vulnerability in enumerate(document.get("vulnerabilities", []), start=1):
        cve_id = normalize_cve_id(vulnerability.get("id"))
        if cve_id is None:
            warnings.append(
                f"Ignored non-CVE CycloneDX vulnerability identifier: {vulnerability.get('id')!r}"
            )
            continue
        affects = vulnerability.get("affects", [])
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
                    file_path=component.get("evidence", {}).get("identity", {}).get("field"),
                    source_record_id=f"vulnerability:{index}:affect:{affect_index}",
                    raw_severity=_cyclonedx_rating(vulnerability),
                    target_kind="repository",
                    target_ref=target_ref,
                )
            )

    return ParsedInput(
        input_format="cyclonedx-json",
        total_rows=len(document.get("vulnerabilities", [])),
        occurrences=occurrences,
        warnings=warnings,
    )


def _parse_spdx_json(path: Path) -> ParsedInput:
    document = json.loads(path.read_text(encoding="utf-8"))
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    packages = {
        package.get("SPDXID"): package
        for package in document.get("packages", [])
        if package.get("SPDXID")
    }

    for index, vulnerability in enumerate(document.get("vulnerabilities", []), start=1):
        cve_id = normalize_cve_id(vulnerability.get("id"))
        if cve_id is None:
            warnings.append(
                f"Ignored non-CVE SPDX vulnerability identifier: {vulnerability.get('id')!r}"
            )
            continue
        affects = vulnerability.get("affects", [])
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
        total_rows=len(document.get("vulnerabilities", [])),
        occurrences=occurrences,
        warnings=warnings,
    )


def _parse_dependency_check_json(path: Path) -> ParsedInput:
    document = json.loads(path.read_text(encoding="utf-8"))
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    dependencies = document.get("dependencies", [])

    for dep_index, dependency in enumerate(dependencies, start=1):
        for vuln_index, vulnerability in enumerate(dependency.get("vulnerabilities", []), start=1):
            cve_id = normalize_cve_id(vulnerability.get("name"))
            if cve_id is None:
                warnings.append(
                    "Ignored non-CVE Dependency-Check vulnerability identifier: "
                    f"{vulnerability.get('name')!r}"
                )
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
                    target_ref=dependency.get("projectReferences", [None])[0],
                )
            )

    return ParsedInput(
        input_format="dependency-check-json",
        total_rows=len(dependencies),
        occurrences=occurrences,
        warnings=warnings,
    )


def _parse_github_alerts_json(path: Path) -> ParsedInput:
    document = json.loads(path.read_text(encoding="utf-8"))
    alerts = document if isinstance(document, list) else document.get("alerts", [document])
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []

    for index, alert in enumerate(alerts, start=1):
        advisory = alert.get("security_advisory", {})
        identifiers = advisory.get("identifiers", [])
        cve_id = normalize_cve_id(advisory.get("cve_id"))
        if cve_id is None:
            for identifier in identifiers:
                cve_id = normalize_cve_id(identifier.get("value"))
                if cve_id is not None:
                    break
        if cve_id is None:
            warnings.append(
                "Ignored GitHub alert without a resolvable CVE identifier: "
                f"{advisory.get('ghsa_id') or alert.get('number')!r}"
            )
            continue
        dependency = alert.get("dependency", {})
        package = dependency.get("package", {})
        occurrences.append(
            InputOccurrence(
                cve_id=cve_id,
                source_format="github-alerts-json",
                component_name=package.get("name"),
                component_version=dependency.get("manifest_path"),
                package_type=package.get("ecosystem"),
                file_path=dependency.get("manifest_path"),
                source_record_id=f"alert:{index}",
                raw_severity=advisory.get("severity"),
                target_kind="repository",
                target_ref=alert.get("html_url") or dependency.get("manifest_path"),
            )
        )

    return ParsedInput(
        input_format="github-alerts-json",
        total_rows=len(alerts),
        occurrences=occurrences,
        warnings=warnings,
    )


def _parse_nessus_xml(path: Path) -> ParsedInput:
    root = _load_xml_root(path)
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    report_hosts = _xml_descendants(root, "reporthost")

    total_rows = 0
    for host_index, report_host in enumerate(report_hosts, start=1):
        target_ref = _nessus_target_ref(report_host, host_index)
        report_items = [
            element for element in report_host if _xml_local_name(element.tag) == "reportitem"
        ]
        for item_index, report_item in enumerate(report_items, start=1):
            total_rows += 1
            cve_ids = _normalize_cve_tokens(
                _nessus_cve_tokens(report_item),
                source_name="Nessus",
                target_ref=target_ref,
                warnings=warnings,
            )
            if not cve_ids:
                continue
            component_name = report_item.attrib.get("pluginName") or _xml_child_text(
                report_item, "plugin_name"
            )
            service = _nessus_service_label(report_item)
            record_id = (
                f"host:{host_index}:target:{target_ref}:item:{item_index}:"
                f"plugin:{report_item.attrib.get('pluginID') or 'unknown'}"
            )
            for cve_id in cve_ids:
                occurrences.append(
                    InputOccurrence(
                        cve_id=cve_id,
                        source_format="nessus-xml",
                        component_name=component_name,
                        component_version=service,
                        package_type="nessus-plugin",
                        source_record_id=record_id,
                        raw_severity=_nessus_severity(report_item),
                        target_kind="host",
                        target_ref=target_ref,
                    )
                )

    return ParsedInput(
        input_format="nessus-xml",
        total_rows=total_rows,
        occurrences=occurrences,
        warnings=warnings,
    )


def _parse_openvas_xml(path: Path) -> ParsedInput:
    root = _load_xml_root(path)
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    results = _xml_descendants(root, "result")

    for result_index, result in enumerate(results, start=1):
        target_ref = (
            _xml_child_text(result, "host")
            or _xml_child_text(result, "hostname")
            or _xml_child_text(result, "ip")
            or f"openvas-target-{result_index}"
        )
        cve_ids = _normalize_cve_tokens(
            _openvas_cve_tokens(result),
            source_name="OpenVAS",
            target_ref=target_ref,
            warnings=warnings,
        )
        if not cve_ids:
            continue
        nvt = _xml_child(result, "nvt")
        component_name = _xml_child_text(result, "name") or (
            None if nvt is None else _xml_child_text(nvt, "name")
        )
        for cve_id in cve_ids:
            occurrences.append(
                InputOccurrence(
                    cve_id=cve_id,
                    source_format="openvas-xml",
                    component_name=component_name,
                    package_type="openvas-nvt",
                    source_record_id=f"result:{result_index}",
                    raw_severity=_xml_child_text(result, "severity")
                    or _xml_child_text(result, "threat"),
                    target_kind="host",
                    target_ref=target_ref,
                )
            )

    return ParsedInput(
        input_format="openvas-xml",
        total_rows=len(results),
        occurrences=occurrences,
        warnings=warnings,
    )


def _parse_openvex_document(document: dict) -> list[VexStatement]:
    statements: list[VexStatement] = []
    for index, statement in enumerate(document.get("statements", []), start=1):
        cve_id = normalize_cve_id(statement.get("vulnerability", {}).get("@id"))
        if cve_id is None:
            cve_id = normalize_cve_id(statement.get("vulnerability", {}).get("name"))
        if cve_id is None:
            continue
        for product in statement.get("products", []):
            statements.append(
                VexStatement(
                    source_format="openvex-json",
                    cve_id=cve_id,
                    status=(statement.get("status") or "").strip(),
                    purl=product.get("@id"),
                    target_kind=product.get("subcomponents", [{}])[0].get("kind"),
                    target_ref=product.get("subcomponents", [{}])[0].get("name"),
                    justification=statement.get("justification"),
                    action_statement=statement.get("action_statement"),
                    source_record_id=f"statement:{index}",
                )
            )
    return statements


def _parse_cyclonedx_vex_document(document: dict) -> list[VexStatement]:
    components = {
        component.get("bom-ref"): component
        for component in document.get("components", [])
        if component.get("bom-ref")
    }
    statements: list[VexStatement] = []
    for index, vulnerability in enumerate(document.get("vulnerabilities", []), start=1):
        cve_id = normalize_cve_id(vulnerability.get("id"))
        if cve_id is None:
            continue
        status = vulnerability.get("analysis", {}).get("state")
        if not status:
            continue
        for affect in vulnerability.get("affects", []):
            component = components.get(affect.get("ref"), {})
            statements.append(
                VexStatement(
                    source_format="cyclonedx-vex-json",
                    cve_id=cve_id,
                    status=status,
                    component_name=component.get("name"),
                    component_version=component.get("version"),
                    purl=component.get("purl"),
                    target_kind="repository",
                    target_ref=document.get("metadata", {}).get("component", {}).get("name"),
                    justification=vulnerability.get("analysis", {}).get("justification"),
                    action_statement=vulnerability.get("analysis", {}).get("response", [None])[0],
                    source_record_id=f"vulnerability:{index}",
                )
            )
    return statements


def _apply_manual_target(
    occurrence: InputOccurrence,
    *,
    target_kind: str | None,
    target_ref: str | None,
) -> InputOccurrence:
    if target_kind is None and target_ref is None:
        return occurrence
    if occurrence.target_ref:
        return occurrence
    return occurrence.model_copy(
        update={
            "target_kind": (target_kind or occurrence.target_kind).lower(),
            "target_ref": target_ref or occurrence.target_ref,
        }
    )


def _apply_asset_context(
    occurrences: list[InputOccurrence],
    asset_records: dict[tuple[str, str], AssetContextRecord],
) -> list[InputOccurrence]:
    if not asset_records:
        return occurrences

    enriched: list[InputOccurrence] = []
    for occurrence in occurrences:
        if not occurrence.target_ref:
            enriched.append(occurrence)
            continue
        asset = asset_records.get((occurrence.target_kind.lower(), occurrence.target_ref))
        if asset is None:
            enriched.append(occurrence)
            continue
        enriched.append(
            occurrence.model_copy(
                update={
                    "asset_id": asset.asset_id,
                    "asset_criticality": asset.criticality,
                    "asset_exposure": asset.exposure,
                    "asset_environment": asset.environment,
                    "asset_owner": asset.owner,
                    "asset_business_service": asset.business_service,
                }
            )
        )
    return enriched


def _apply_vex_statements(
    occurrences: list[InputOccurrence],
    statements: list[VexStatement],
) -> list[InputOccurrence]:
    if not statements:
        return occurrences

    resolved: list[InputOccurrence] = []
    for occurrence in occurrences:
        matched_statement = _match_vex_statement(occurrence, statements)
        if matched_statement is None:
            resolved.append(occurrence)
            continue
        resolved.append(
            occurrence.model_copy(
                update={
                    "vex_status": matched_statement.status,
                    "vex_justification": matched_statement.justification,
                    "vex_action_statement": matched_statement.action_statement,
                }
            )
        )
    return resolved


def _match_vex_statement(
    occurrence: InputOccurrence,
    statements: list[VexStatement],
) -> VexStatement | None:
    for statement in statements:
        if statement.cve_id != occurrence.cve_id:
            continue
        if statement.purl and occurrence.purl and statement.purl == occurrence.purl:
            return statement
        if (
            statement.component_name
            and occurrence.component_name
            and statement.component_name == occurrence.component_name
            and (
                statement.component_version is None
                or occurrence.component_version is None
                or statement.component_version == occurrence.component_version
            )
        ):
            return statement
        if (
            statement.target_kind
            and statement.target_ref
            and occurrence.target_ref
            and statement.target_kind.lower() == occurrence.target_kind.lower()
            and statement.target_ref == occurrence.target_ref
        ):
            return statement
    return None


def _finalize_occurrences(
    occurrences: list[InputOccurrence],
    *,
    input_format: str,
    warnings: list[str],
    total_rows: int,
    max_cves: int | None,
) -> ParsedInput:
    seen: set[str] = set()
    unique_cves: list[str] = []
    for occurrence in occurrences:
        if occurrence.cve_id in seen:
            continue
        seen.add(occurrence.cve_id)
        unique_cves.append(occurrence.cve_id)

    if max_cves is not None and len(unique_cves) > max_cves:
        allowed = set(unique_cves[:max_cves])
        warnings = warnings + [
            "Applied --max-cves "
            f"{max_cves}; truncated the analysis set from {len(unique_cves)} "
            f"to {max_cves} CVEs."
        ]
        unique_cves = unique_cves[:max_cves]
        occurrences = [occurrence for occurrence in occurrences if occurrence.cve_id in allowed]

    if not unique_cves:
        raise ValueError("No valid CVE identifiers were found in the input file.")

    source_stats = dict(Counter(occurrence.source_format for occurrence in occurrences))
    return ParsedInput(
        input_format=input_format,
        total_rows=total_rows,
        occurrences=occurrences,
        unique_cves=unique_cves,
        warnings=warnings,
        source_stats=source_stats,
    )


def _read_txt(path: Path) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            rows.append((line_number, stripped))
    return rows


def _read_csv(path: Path) -> list[tuple[int, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("CSV input is missing a header row.")
        field_map = {field.strip().lower(): field for field in reader.fieldnames if field}
        cve_field = field_map.get("cve") or field_map.get("cve_id")
        if not cve_field:
            raise ValueError("CSV input must contain a 'cve' or 'cve_id' column.")

        rows: list[tuple[int, str]] = []
        for row_number, row in enumerate(reader, start=2):
            value = (row.get(cve_field) or "").strip()
            if not value:
                continue
            rows.append((row_number, value))
        return rows


def _split_versions(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return _as_string_list(value)
    if not isinstance(value, str):
        return []
    separators = [",", "|"]
    result = [value]
    for separator in separators:
        parts: list[str] = []
        for item in result:
            parts.extend(item.split(separator))
        result = parts
    return [item.strip() for item in result if item.strip()]


def _as_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _cyclonedx_rating(vulnerability: dict) -> str | None:
    ratings = vulnerability.get("ratings", [])
    if not ratings:
        return None
    severity = ratings[0].get("severity")
    return str(severity) if severity else None


def _spdx_purl(package: dict) -> str | None:
    for reference in package.get("externalRefs", []):
        if reference.get("referenceType") == "purl":
            return reference.get("referenceLocator")
    return None


def _load_xml_root(path: Path) -> ET.Element:
    raw = path.read_bytes()
    uppercase = raw.upper()
    if b"<!DOCTYPE" in uppercase or b"<!ENTITY" in uppercase:
        raise ValueError(
            "XML input contains a DOCTYPE or ENTITY declaration, which is not supported."
        )
    try:
        return ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError(f"XML input is not valid XML: {path}") from exc


def _looks_like_nessus_document(root: ET.Element) -> bool:
    if _xml_local_name(root.tag) in {"nessusclientdata_v2", "nessusclientdata"}:
        return True
    return _xml_has_descendant(root, "reporthost")


def _looks_like_openvas_document(root: ET.Element) -> bool:
    return _xml_has_descendant(root, "result") and _xml_has_descendant(root, "nvt")


def _xml_local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", maxsplit=1)[1].lower()
    return tag.lower()


def _xml_child(element: ET.Element, name: str) -> ET.Element | None:
    for child in element:
        if _xml_local_name(child.tag) == name.lower():
            return child
    return None


def _xml_child_text(element: ET.Element, name: str) -> str | None:
    child = _xml_child(element, name)
    if child is None or child.text is None:
        return None
    text = child.text.strip()
    return text or None


def _xml_descendants(root: ET.Element, name: str) -> list[ET.Element]:
    expected_name = name.lower()
    return [element for element in root.iter() if _xml_local_name(element.tag) == expected_name]


def _xml_has_descendant(root: ET.Element, name: str) -> bool:
    expected_name = name.lower()
    return any(_xml_local_name(element.tag) == expected_name for element in root.iter())


def _nessus_target_ref(report_host: ET.Element, host_index: int) -> str:
    host_properties = _xml_child(report_host, "hostproperties")
    if host_properties is not None:
        preferred_names = ("host-fqdn", "host-ip", "host_dns", "netbios-name")
        tag_values: dict[str, str] = {}
        for tag in host_properties:
            if _xml_local_name(tag.tag) != "tag":
                continue
            name = (tag.attrib.get("name") or "").strip().lower()
            value = (tag.text or "").strip()
            if name and value:
                tag_values[name] = value
        for preferred_name in preferred_names:
            if preferred_name in tag_values:
                return tag_values[preferred_name]

    for key in ("name",):
        attr_value = report_host.attrib.get(key)
        if attr_value:
            return attr_value.strip()

    return f"nessus-host-{host_index}"


def _nessus_cve_tokens(report_item: ET.Element) -> list[str]:
    tokens: list[str] = []
    for child in report_item:
        if _xml_local_name(child.tag) != "cve" or child.text is None:
            continue
        tokens.extend(_split_cve_tokens(child.text))
    return _deduplicate_preserving_order(tokens)


def _openvas_cve_tokens(result: ET.Element) -> list[str]:
    tokens: list[str] = []
    nvt = _xml_child(result, "nvt")
    if nvt is not None:
        cve_field = _xml_child_text(nvt, "cve")
        if cve_field:
            tokens.extend(_split_cve_tokens(cve_field))
        refs = _xml_child(nvt, "refs")
        if refs is not None:
            for ref in refs:
                if _xml_local_name(ref.tag) != "ref":
                    continue
                if (ref.attrib.get("type") or "").strip().lower() != "cve":
                    continue
                ref_id = (ref.attrib.get("id") or ref.text or "").strip()
                if ref_id:
                    tokens.extend(_split_cve_tokens(ref_id))
    return _deduplicate_preserving_order(tokens)


def _normalize_cve_tokens(
    raw_tokens: list[str],
    *,
    source_name: str,
    target_ref: str,
    warnings: list[str],
) -> list[str]:
    cve_ids: list[str] = []
    for raw_cve in raw_tokens:
        cve_id = normalize_cve_id(raw_cve)
        if cve_id is None:
            warnings.append(
                f"Ignored non-CVE {source_name} identifier in {target_ref}: {raw_cve!r}"
            )
            continue
        cve_ids.append(cve_id)
    return cve_ids


def _split_cve_tokens(value: str) -> list[str]:
    return [token.strip() for token in re.split(r"[\s,;]+", value) if token.strip()]


def _deduplicate_preserving_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _nessus_service_label(report_item: ET.Element) -> str | None:
    svc_name = (report_item.attrib.get("svc_name") or "").strip()
    port = (report_item.attrib.get("port") or "").strip()
    protocol = (report_item.attrib.get("protocol") or "").strip()
    parts = [part for part in (svc_name, port, protocol) if part]
    if not parts:
        return None
    return "/".join(parts)


def _nessus_severity(report_item: ET.Element) -> str | None:
    risk_factor = _xml_child_text(report_item, "risk_factor")
    if risk_factor:
        return risk_factor
    severity = (report_item.attrib.get("severity") or "").strip()
    return severity or None
