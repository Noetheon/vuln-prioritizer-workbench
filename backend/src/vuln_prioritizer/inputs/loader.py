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

from . import _occurrence_support, _vex_support, _xml_support
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

GENERIC_OCCURRENCE_CVE_FIELDS = {"cve_id", "cve", "vulnerability_id"}
GENERIC_OCCURRENCE_HINT_FIELDS = {
    "component",
    "component_name",
    "version",
    "component_version",
    "installed_version",
    "purl",
    "package_type",
    "ecosystem",
    "file_path",
    "path",
    "dependency_path",
    "fix_versions",
    "fixed_versions",
    "fix_version",
    "target_kind",
    "target_ref",
    "target",
    "asset_ref",
    "asset_id",
    "criticality",
    "asset_criticality",
    "exposure",
    "asset_exposure",
    "environment",
    "asset_environment",
    "owner",
    "asset_owner",
    "business_service",
    "service",
    "asset_business_service",
    "severity",
    "raw_severity",
}


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
    skipped_rows: int
    exact_rules: int
    glob_rules: int
    legacy_schema: bool
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class VexLoadDiagnostics:
    file_count: int
    statement_count: int
    skipped_statements: int
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
        source_occurrence_groups: list[list[InputOccurrence]] = []
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
            source_occurrence_groups.append(source_occurrences)
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

        parsed = _occurrence_support.finalize_occurrences(
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
        included_cves = set(parsed.unique_cves)
        return parsed.model_copy(
            update={
                "source_summaries": [
                    summary.model_copy(
                        update={
                            "included_occurrence_count": len(
                                [
                                    occurrence
                                    for occurrence in source_occurrences
                                    if occurrence.cve_id in included_cves
                                ]
                            ),
                            "included_unique_cves": _count_unique_cves(
                                [
                                    occurrence
                                    for occurrence in source_occurrences
                                    if occurrence.cve_id in included_cves
                                ]
                            ),
                        }
                    )
                    for summary, source_occurrences in zip(
                        parsed.source_summaries,
                        source_occurrence_groups,
                        strict=True,
                    )
                ]
            }
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
    parser = _INPUT_PARSERS.get(resolved_format)
    if parser is None:
        raise ValueError(f"Unsupported input format: {resolved_format}")
    return parser(path)


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
    if suffix == ".csv" and _looks_like_generic_occurrence_csv(path):
        return "generic-occurrence-csv"
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
) -> AssetContextCatalog:
    raise NotImplementedError


@overload
def load_asset_context_file(
    path: Path | None,
    *,
    return_diagnostics: Literal[True],
) -> tuple[AssetContextCatalog, AssetContextLoadDiagnostics]:
    raise NotImplementedError


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
                skipped_rows=0,
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
        skipped_rows = 0
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
                skipped_rows += 1
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
                criticality=_normalize_asset_criticality(
                    (row.get("criticality") or "").strip() or None,
                    warnings=warning_messages,
                    row_number=order,
                ),
                exposure=_normalize_asset_exposure(
                    (row.get("exposure") or "").strip() or None,
                    warnings=warning_messages,
                    row_number=order,
                ),
                environment=_normalize_asset_environment(
                    (row.get("environment") or "").strip() or None,
                    warnings=warning_messages,
                    row_number=order,
                ),
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
            skipped_rows=skipped_rows,
            exact_rules=exact_rule_count,
            glob_rules=glob_rule_count,
            legacy_schema=legacy_schema,
            warnings=tuple(warning_messages),
        ),
    )
    return (catalog, catalog.diagnostics) if return_diagnostics else catalog


@overload
def load_vex_files(
    paths: list[Path] | None,
    *,
    return_diagnostics: Literal[False] = False,
) -> list[VexStatement]:
    raise NotImplementedError


@overload
def load_vex_files(
    paths: list[Path] | None,
    *,
    return_diagnostics: Literal[True],
) -> tuple[list[VexStatement], VexLoadDiagnostics]:
    raise NotImplementedError


def load_vex_files(
    paths: list[Path] | None,
    *,
    return_diagnostics: bool = False,
) -> list[VexStatement] | tuple[list[VexStatement], VexLoadDiagnostics]:
    """Load all supported VEX files."""
    statements: list[VexStatement] = []
    skipped_statements = 0
    warning_messages: list[str] = []
    for file_order, path in enumerate(paths or [], start=1):
        if not path.exists() or not path.is_file():
            raise ValueError(f"VEX file does not exist: {path}")
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and "statements" in document:
            if not isinstance(document.get("statements"), list):
                raise ValueError(f"OpenVEX JSON `statements` in {path} must be a list.")
            file_statements = _vex_support.parse_openvex_document(document)
            total_statements = len(document["statements"])
        elif (
            isinstance(document, dict)
            and "bomFormat" in document
            and "CycloneDX" in str(document.get("bomFormat"))
        ):
            if not isinstance(document.get("vulnerabilities"), list):
                raise ValueError(f"CycloneDX VEX JSON `vulnerabilities` in {path} must be a list.")
            file_statements = _vex_support.parse_cyclonedx_vex_document(document)
            total_statements = len(document["vulnerabilities"])
        else:
            raise ValueError(
                f"Unsupported VEX format for {path}. Use OpenVEX JSON or CycloneDX VEX JSON."
            )
        loaded_statement_ids = {
            statement.source_record_id
            for statement in file_statements
            if statement.source_record_id
        }
        file_skipped = max(total_statements - len(loaded_statement_ids), 0)
        skipped_statements += file_skipped
        if file_skipped:
            warning_messages.append(
                f"Skipped {file_skipped} VEX statement(s) in {path} because required "
                "CVE, status, product, or affect data was missing or unsupported."
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
    diagnostics = VexLoadDiagnostics(
        file_count=len(paths or []),
        statement_count=len(statements),
        skipped_statements=skipped_statements,
        warnings=tuple(warning_messages),
    )
    return (statements, diagnostics) if return_diagnostics else statements


def _looks_like_generic_occurrence_csv(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            header = next(reader, [])
    except csv.Error:
        return False
    normalized_header = {field.strip().lower() for field in header if field}
    return bool(
        normalized_header.intersection(GENERIC_OCCURRENCE_CVE_FIELDS)
        and normalized_header.intersection(GENERIC_OCCURRENCE_HINT_FIELDS)
    )


def _normalize_asset_criticality(
    value: str | None,
    *,
    warnings: list[str],
    row_number: int,
) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower().replace("_", "-")
    aliases = {
        "crit": "critical",
        "critical": "critical",
        "high": "high",
        "med": "medium",
        "medium": "medium",
        "low": "low",
    }
    resolved = aliases.get(normalized)
    if resolved is None:
        warnings.append(
            f"Ignored unknown asset criticality at row {row_number}: {value!r}. "
            "Allowed values are low, medium, high, critical."
        )
    return resolved


def _normalize_asset_exposure(
    value: str | None,
    *,
    warnings: list[str],
    row_number: int,
) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower().replace("_", "-")
    aliases = {
        "internal": "internal",
        "private": "internal",
        "dmz": "dmz",
        "internet": "internet-facing",
        "external": "internet-facing",
        "public": "internet-facing",
        "internet-facing": "internet-facing",
    }
    resolved = aliases.get(normalized)
    if resolved is None:
        warnings.append(
            f"Ignored unknown asset exposure at row {row_number}: {value!r}. "
            "Allowed values are internal, dmz, internet-facing."
        )
    return resolved


def _normalize_asset_environment(
    value: str | None,
    *,
    warnings: list[str],
    row_number: int,
) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower().replace("_", "-")
    aliases = {
        "prod": "prod",
        "production": "prod",
        "stage": "staging",
        "staging": "staging",
        "test": "test",
        "qa": "test",
        "dev": "dev",
        "development": "dev",
    }
    resolved = aliases.get(normalized)
    if resolved is None:
        warnings.append(
            f"Ignored unknown asset environment at row {row_number}: {value!r}. "
            "Allowed values are prod, staging, test, dev."
        )
    return resolved


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
