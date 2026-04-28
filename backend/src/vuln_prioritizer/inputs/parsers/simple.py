"""Parsers for plain CVE lists and generic occurrence CSVs."""

from __future__ import annotations

import csv
from pathlib import Path

from vuln_prioritizer.models import InputOccurrence, ParsedInput
from vuln_prioritizer.utils import normalize_cve_id

from .common import (
    csv_value,
    first_existing_field,
    normalize_asset_criticality,
    normalize_asset_environment,
    normalize_asset_exposure,
    split_versions,
)


def parse_cve_list(path: Path) -> ParsedInput:
    suffix = path.suffix.lower()
    if suffix not in {".txt", ".csv"}:
        raise ValueError("Unsupported input format. Use .txt or .csv files.")

    rows = _read_cve_txt(path) if suffix == ".txt" else _read_cve_csv(path)
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    seen: set[tuple[str, str | None, str | None, str | None]] = set()

    for line_number, raw_value, asset_ref, component, version in rows:
        cve_id = normalize_cve_id(raw_value)
        if cve_id is None:
            warnings.append(f"Ignored invalid CVE identifier at line {line_number}: {raw_value!r}")
            continue
        key = (cve_id, asset_ref, component, version)
        if key in seen:
            continue
        seen.add(key)
        occurrences.append(
            InputOccurrence(
                cve_id=cve_id,
                source_format="cve-list",
                source_record_id=f"line:{line_number}",
                component_name=component,
                component_version=version,
                target_ref=asset_ref,
            )
        )

    return ParsedInput(
        input_format="cve-list",
        total_rows=len(rows),
        occurrences=occurrences,
        warnings=warnings,
    )


def _read_cve_txt(path: Path) -> list[tuple[int, str, None, None, None]]:
    rows: list[tuple[int, str, None, None, None]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            rows.append((line_number, value, None, None, None))
    return rows


def _read_cve_csv(path: Path) -> list[tuple[int, str, str | None, str | None, str | None]]:
    indexed_lines = [
        (line_number, line)
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if line.strip() and not line.strip().startswith("#")
    ]
    if not indexed_lines:
        raise ValueError("CSV input is missing a header row.")

    reader = csv.DictReader([line for _, line in indexed_lines])
    if not reader.fieldnames:
        raise ValueError("CSV input is missing a header row.")
    field_map = {field.strip().lower(): field for field in reader.fieldnames if field}
    cve_field = first_existing_field(field_map, "cve_id", "cve")
    if cve_field is None:
        raise ValueError("CSV input must contain a 'cve_id' or 'cve' column.")

    rows: list[tuple[int, str, str | None, str | None, str | None]] = []
    data_line_numbers = [line_number for line_number, _ in indexed_lines[1:]]
    for row, row_number in zip(reader, data_line_numbers, strict=True):
        value = (row.get(cve_field) or "").strip()
        if not value:
            continue
        rows.append(
            (
                row_number,
                value,
                csv_value(row, field_map, "asset_ref"),
                csv_value(row, field_map, "component"),
                csv_value(row, field_map, "version"),
            )
        )
    return rows


def parse_generic_occurrence_csv(path: Path) -> ParsedInput:
    if path.suffix.lower() != ".csv":
        raise ValueError("generic-occurrence-csv input must be a .csv file.")

    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    total_rows = 0
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("generic-occurrence-csv is missing a header row.")
        field_map = {field.strip().lower(): field for field in reader.fieldnames if field}
        cve_field = first_existing_field(field_map, "cve_id", "cve", "vulnerability_id")
        if cve_field is None:
            raise ValueError("generic-occurrence-csv must contain a cve_id or cve column.")

        for row_number, row in enumerate(reader, start=2):
            total_rows += 1
            cve_id = normalize_cve_id(row.get(cve_field))
            if cve_id is None:
                warnings.append(
                    f"Ignored invalid CVE identifier at line {row_number}: {row.get(cve_field)!r}"
                )
                continue
            target_kind = csv_value(row, field_map, "target_kind") or "generic"
            target_ref = csv_value(row, field_map, "target_ref", "target", "asset_ref")
            occurrences.append(
                InputOccurrence(
                    cve_id=cve_id,
                    source_format="generic-occurrence-csv",
                    component_name=csv_value(row, field_map, "component_name", "component"),
                    component_version=csv_value(
                        row,
                        field_map,
                        "component_version",
                        "version",
                        "installed_version",
                    ),
                    purl=csv_value(row, field_map, "purl"),
                    package_type=csv_value(row, field_map, "package_type", "ecosystem"),
                    file_path=csv_value(row, field_map, "file_path", "path"),
                    dependency_path=csv_value(row, field_map, "dependency_path"),
                    fix_versions=split_versions(
                        csv_value(row, field_map, "fix_versions", "fixed_versions", "fix_version")
                    ),
                    source_record_id=f"row:{row_number}",
                    raw_severity=csv_value(row, field_map, "severity", "raw_severity"),
                    target_kind=target_kind.lower(),
                    target_ref=target_ref,
                    asset_id=csv_value(row, field_map, "asset_id"),
                    asset_criticality=normalize_asset_criticality(
                        csv_value(row, field_map, "criticality", "asset_criticality"),
                        warnings=warnings,
                        row_number=row_number,
                    ),
                    asset_exposure=normalize_asset_exposure(
                        csv_value(row, field_map, "exposure", "asset_exposure"),
                        warnings=warnings,
                        row_number=row_number,
                    ),
                    asset_environment=normalize_asset_environment(
                        csv_value(row, field_map, "environment", "asset_environment"),
                        warnings=warnings,
                        row_number=row_number,
                    ),
                    asset_owner=csv_value(row, field_map, "owner", "asset_owner"),
                    asset_business_service=csv_value(
                        row,
                        field_map,
                        "business_service",
                        "service",
                        "asset_business_service",
                    ),
                )
            )

    return ParsedInput(
        input_format="generic-occurrence-csv",
        total_rows=total_rows,
        occurrences=occurrences,
        warnings=warnings,
    )
