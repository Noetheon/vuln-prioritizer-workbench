"""Input normalization for CVE lists, scanners, SBOMs, asset context, and VEX."""

from __future__ import annotations

import csv
import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, overload

from vuln_prioritizer.models import (
    AssetContextRecord,
    InputOccurrence,
    InputSourceSummary,
    ParsedInput,
    VexStatement,
)
from vuln_prioritizer.utils import normalize_cve_id

from . import _cve_support, _occurrence_support, _vex_support, _xml_support


@dataclass(frozen=True)
class AssetContextRule:
    rule_id: str
    target_kind: str
    target_ref: str
    asset_record: AssetContextRecord
    match_mode: str = "exact"
    precedence: int = 0
    order: int = 0


@dataclass(frozen=True)
class AssetContextLoadDiagnostics:
    total_rows: int
    loaded_rows: int
    exact_rules: int
    glob_rules: int
    legacy_schema: bool
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class AssetContextCatalog(Mapping[tuple[str, str], AssetContextRecord]):
    records: dict[tuple[str, str], AssetContextRecord]
    rules: tuple[AssetContextRule, ...]
    diagnostics: AssetContextLoadDiagnostics

    def __getitem__(self, key: tuple[str, str]) -> AssetContextRecord:
        return self.records[key]

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)


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
        asset_records: Mapping[tuple[str, str], AssetContextRecord] | None = None,
        vex_statements: list[VexStatement] | None = None,
    ) -> ParsedInput:
        return self.load_many(
            [InputSpec(path=path, input_format=input_format)],
            max_cves=max_cves,
            target_kind=target_kind,
            target_ref=target_ref,
            asset_records=asset_records,
            vex_statements=vex_statements,
        )

    def load_many(
        self,
        inputs: list[InputSpec],
        *,
        max_cves: int | None = None,
        target_kind: str | None = None,
        target_ref: str | None = None,
        asset_records: Mapping[tuple[str, str], AssetContextRecord] | None = None,
        vex_statements: list[VexStatement] | None = None,
    ) -> ParsedInput:
        if not inputs:
            raise ValueError("At least one input file must be provided.")

        warnings: list[str] = []
        occurrences: list[InputOccurrence] = []
        source_summaries: list[InputSourceSummary] = []
        resolved_formats: list[str] = []
        total_rows = 0
        asset_match_conflict_count = 0
        vex_conflict_count = 0

        catalog_diagnostics = getattr(asset_records, "diagnostics", None)
        if catalog_diagnostics and getattr(catalog_diagnostics, "warnings", None):
            warnings.extend(catalog_diagnostics.warnings)

        for spec in inputs:
            parsed = _load_single_input(spec.path, input_format=spec.input_format)
            resolved_formats.append(parsed.input_format)
            total_rows += parsed.total_rows
            warnings.extend(parsed.warnings)
            source_occurrences = [
                _occurrence_support.apply_manual_target(
                    occurrence,
                    target_kind=target_kind,
                    target_ref=target_ref,
                )
                for occurrence in parsed.occurrences
            ]
            source_occurrences, asset_diagnostics = _occurrence_support.apply_asset_context(
                source_occurrences,
                asset_records if asset_records is not None else {},
                return_diagnostics=True,
            )
            source_occurrences, vex_diagnostics = _vex_support.apply_vex_statements(
                source_occurrences,
                vex_statements or [],
                return_diagnostics=True,
            )
            warnings.extend(asset_diagnostics.warnings)
            warnings.extend(vex_diagnostics.warnings)
            asset_match_conflict_count += asset_diagnostics.ambiguous_occurrences
            vex_conflict_count += vex_diagnostics.conflict_occurrences
            occurrences.extend(source_occurrences)
            source_summaries.append(
                InputSourceSummary(
                    input_path=str(spec.path),
                    input_format=parsed.input_format,
                    total_rows=parsed.total_rows,
                    occurrence_count=len(source_occurrences),
                    unique_cves=_count_unique_cves(source_occurrences),
                    warning_count=len(parsed.warnings),
                )
            )

        return _occurrence_support.finalize_occurrences(
            occurrences,
            input_format=_effective_input_format(resolved_formats),
            warnings=warnings,
            total_rows=total_rows,
            max_cves=max_cves,
            input_paths=[str(spec.path) for spec in inputs],
            source_summaries=source_summaries,
            merged_input_count=len(inputs),
            asset_match_conflict_count=asset_match_conflict_count,
            vex_conflict_count=vex_conflict_count,
        )


@dataclass(frozen=True)
class InputSpec:
    path: Path
    input_format: str = "auto"


def _count_unique_cves(occurrences: list[InputOccurrence]) -> int:
    return len({occurrence.cve_id for occurrence in occurrences})


def _effective_input_format(resolved_formats: list[str]) -> str:
    unique_formats = {item for item in resolved_formats if item}
    if len(unique_formats) <= 1:
        return resolved_formats[0] if resolved_formats else "cve-list"
    return "mixed"


def _load_single_input(
    path: Path,
    *,
    input_format: str,
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
    return parsed


def build_inline_input(
    cve_id: str,
    *,
    target_kind: str | None = None,
    target_ref: str | None = None,
    asset_records: Mapping[tuple[str, str], AssetContextRecord] | None = None,
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
    occurrences, asset_diagnostics = _occurrence_support.apply_asset_context(
        [occurrence],
        asset_records if asset_records is not None else {},
        return_diagnostics=True,
    )
    occurrences, vex_diagnostics = _vex_support.apply_vex_statements(
        occurrences,
        vex_statements or [],
        return_diagnostics=True,
    )
    return _occurrence_support.finalize_occurrences(
        occurrences,
        input_format="cve-list",
        warnings=[
            *asset_diagnostics.warnings,
            *vex_diagnostics.warnings,
        ],
        total_rows=1,
        max_cves=1,
        asset_match_conflict_count=asset_diagnostics.ambiguous_occurrences,
        vex_conflict_count=vex_diagnostics.conflict_occurrences,
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
        root = _xml_support.load_xml_root(path)
        if _xml_support.looks_like_nessus_document(root):
            return "nessus-xml"
        if _xml_support.looks_like_openvas_document(root):
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


@overload
def load_asset_context_file(
    path: Path | None,
    *,
    return_diagnostics: Literal[False] = False,
) -> AssetContextCatalog: ...


@overload
def load_asset_context_file(
    path: Path | None,
    *,
    return_diagnostics: Literal[True],
) -> tuple[AssetContextCatalog, AssetContextLoadDiagnostics]: ...


def load_asset_context_file(
    path: Path | None,
    *,
    return_diagnostics: bool = False,
) -> AssetContextCatalog | tuple[AssetContextCatalog, AssetContextLoadDiagnostics]:
    """Load ordered asset context rules from CSV."""
    if path is None:
        empty = AssetContextCatalog(
            records={},
            rules=(),
            diagnostics=AssetContextLoadDiagnostics(
                total_rows=0,
                loaded_rows=0,
                exact_rules=0,
                glob_rules=0,
                legacy_schema=True,
            ),
        )
        return (empty, empty.diagnostics) if return_diagnostics else empty
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("Asset context CSV is missing a header row.")
        fieldnames = {field.strip() for field in reader.fieldnames if field}
        required = {"target_kind", "target_ref", "asset_id"}
        missing = required - fieldnames
        if missing:
            raise ValueError(
                "Asset context CSV must contain columns: target_kind, target_ref, asset_id."
            )

        optional_schema_fields = {"rule_id", "match_mode", "precedence"}
        legacy_schema = not bool(optional_schema_fields & fieldnames)
        records: dict[tuple[str, str], AssetContextRecord] = {}
        rules: list[AssetContextRule] = []
        exact_rule_count = 0
        glob_rule_count = 0
        loaded_rows = 0
        total_rows = 0
        warning_messages: list[str] = []
        duplicate_exact_rows = 0
        competing_rule_rows = 0
        seen_signatures: set[tuple[str, str, str, int]] = set()

        for order, row in enumerate(reader, start=1):
            total_rows += 1
            target_kind = (row.get("target_kind") or "").strip().lower()
            target_ref = (row.get("target_ref") or "").strip()
            asset_id = (row.get("asset_id") or "").strip()
            if not target_kind or not target_ref or not asset_id:
                continue
            loaded_rows += 1
            match_mode = (row.get("match_mode") or "exact").strip().lower()
            if match_mode not in {"exact", "glob"}:
                raise ValueError("Asset context CSV match_mode must be either exact or glob.")
            precedence_raw = (row.get("precedence") or "").strip()
            if precedence_raw:
                try:
                    precedence = int(precedence_raw)
                except ValueError as exc:
                    raise ValueError(
                        f"Asset context CSV precedence must be an integer, got {precedence_raw!r}."
                    ) from exc
            else:
                precedence = order
            rule_id = (row.get("rule_id") or "").strip() or f"asset-rule:{order}"
            signature = (target_kind, target_ref, match_mode, precedence)
            if legacy_schema and match_mode == "exact" and (target_kind, target_ref) in records:
                duplicate_exact_rows += 1
            elif signature in seen_signatures:
                competing_rule_rows += 1
            seen_signatures.add(signature)
            record = AssetContextRecord(
                target_kind=target_kind,
                target_ref=target_ref,
                asset_id=asset_id,
                rule_id=rule_id,
                match_mode=match_mode,
                precedence=precedence,
                row_number=order,
                criticality=(row.get("criticality") or "").strip() or None,
                exposure=(row.get("exposure") or "").strip() or None,
                environment=(row.get("environment") or "").strip() or None,
                owner=(row.get("owner") or "").strip() or None,
                business_service=(row.get("business_service") or "").strip() or None,
            )
            records[(target_kind, target_ref)] = record
            rules.append(
                AssetContextRule(
                    rule_id=rule_id,
                    target_kind=target_kind,
                    target_ref=target_ref,
                    asset_record=record,
                    match_mode=match_mode,
                    precedence=precedence,
                    order=order,
                )
            )
            if match_mode == "glob":
                glob_rule_count += 1
            else:
                exact_rule_count += 1

    if duplicate_exact_rows:
        warning_messages.append(
            "Asset context CSV contains "
            f"{duplicate_exact_rows} duplicate exact-match row(s); later rows remain preferred "
            "under legacy precedence, but conflicts are now reported."
        )
    if competing_rule_rows:
        warning_messages.append(
            "Asset context CSV contains "
            f"{competing_rule_rows} rule(s) that compete on the same target pattern or "
            "precedence and may require deterministic tie-breaking."
        )

    catalog = AssetContextCatalog(
        records=records,
        rules=tuple(rules),
        diagnostics=AssetContextLoadDiagnostics(
            total_rows=total_rows,
            loaded_rows=loaded_rows,
            exact_rules=exact_rule_count,
            glob_rules=glob_rule_count,
            legacy_schema=legacy_schema,
            warnings=tuple(warning_messages),
        ),
    )
    return (catalog, catalog.diagnostics) if return_diagnostics else catalog


def load_vex_files(paths: list[Path] | None) -> list[VexStatement]:
    """Load all supported VEX files."""
    statements: list[VexStatement] = []
    for file_order, path in enumerate(paths or [], start=1):
        if not path.exists() or not path.is_file():
            raise ValueError(f"VEX file does not exist: {path}")
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and "statements" in document:
            file_statements = _vex_support.parse_openvex_document(document)
        elif (
            isinstance(document, dict)
            and "bomFormat" in document
            and "CycloneDX" in str(document.get("bomFormat"))
        ):
            file_statements = _vex_support.parse_cyclonedx_vex_document(document)
        else:
            raise ValueError(
                f"Unsupported VEX format for {path}. Use OpenVEX JSON or CycloneDX VEX JSON."
            )
        for statement_order, statement in enumerate(file_statements, start=1):
            statements.append(
                statement.model_copy(
                    update={
                        "source_path": str(path),
                        "source_file_order": file_order,
                        "statement_order": statement_order,
                    }
                )
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
            cve_id = _cve_support.normalize_cve_or_warn(
                vulnerability.get("VulnerabilityID"),
                source_name="Trivy",
                warnings=warnings,
            )
            if cve_id is None:
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
        cve_id = _cve_support.normalize_cve_or_warn(
            vulnerability.get("id"),
            source_name="Grype",
            warnings=warnings,
        )
        if cve_id is None:
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
        cve_id = _cve_support.normalize_cve_or_warn(
            vulnerability.get("id"),
            source_name="CycloneDX",
            warnings=warnings,
        )
        if cve_id is None:
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
        cve_id = _cve_support.normalize_cve_or_warn(
            vulnerability.get("id"),
            source_name="SPDX",
            warnings=warnings,
        )
        if cve_id is None:
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
        cve_id = _cve_support.first_normalized_cve(
            [advisory.get("cve_id"), *(identifier.get("value") for identifier in identifiers)]
        )
        if cve_id is None:
            warnings.append(
                "Ignored GitHub alert without a resolvable CVE identifier: "
                f"{advisory.get('ghsa_id') or alert.get('number')!r}"
            )
            continue
        dependency = alert.get("dependency", {})
        package = dependency.get("package", {})
        vulnerability = alert.get("security_vulnerability", {})
        first_patched_version = vulnerability.get("first_patched_version", {})
        occurrences.append(
            InputOccurrence(
                cve_id=cve_id,
                source_format="github-alerts-json",
                component_name=package.get("name"),
                component_version=_first_present_string(
                    dependency.get("package_version"),
                    dependency.get("version"),
                    package.get("version"),
                    vulnerability.get("package_version"),
                    vulnerability.get("version"),
                ),
                package_type=package.get("ecosystem"),
                file_path=dependency.get("manifest_path"),
                fix_versions=_as_string_list([first_patched_version.get("identifier")]),
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
    root = _xml_support.load_xml_root(path)
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    report_hosts = _xml_support.xml_descendants(root, "reporthost")

    total_rows = 0
    for host_index, report_host in enumerate(report_hosts, start=1):
        target_ref = _xml_support.nessus_target_ref(report_host, host_index)
        report_items = [
            element
            for element in report_host
            if _xml_support.xml_local_name(element.tag) == "reportitem"
        ]
        for item_index, report_item in enumerate(report_items, start=1):
            total_rows += 1
            cve_ids = _xml_support.normalize_cve_tokens(
                _xml_support.nessus_cve_tokens(report_item),
                source_name="Nessus",
                target_ref=target_ref,
                warnings=warnings,
            )
            if not cve_ids:
                continue
            component_name = report_item.attrib.get("pluginName") or _xml_support.xml_child_text(
                report_item,
                "plugin_name",
            )
            service = _xml_support.nessus_service_label(report_item)
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
                        raw_severity=_xml_support.nessus_severity(report_item),
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
    root = _xml_support.load_xml_root(path)
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    results = _xml_support.xml_descendants(root, "result")

    for result_index, result in enumerate(results, start=1):
        target_ref = (
            _xml_support.xml_child_text(result, "host")
            or _xml_support.xml_child_text(result, "hostname")
            or _xml_support.xml_child_text(result, "ip")
            or f"openvas-target-{result_index}"
        )
        cve_ids = _xml_support.normalize_cve_tokens(
            _xml_support.openvas_cve_tokens(result),
            source_name="OpenVAS",
            target_ref=target_ref,
            warnings=warnings,
        )
        if not cve_ids:
            continue
        nvt = _xml_support.xml_child(result, "nvt")
        component_name = _xml_support.xml_child_text(result, "name") or (
            None if nvt is None else _xml_support.xml_child_text(nvt, "name")
        )
        for cve_id in cve_ids:
            occurrences.append(
                InputOccurrence(
                    cve_id=cve_id,
                    source_format="openvas-xml",
                    component_name=component_name,
                    package_type="openvas-nvt",
                    source_record_id=f"result:{result_index}",
                    raw_severity=_xml_support.xml_child_text(result, "severity")
                    or _xml_support.xml_child_text(result, "threat"),
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


def _first_present_string(*values: object) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


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
