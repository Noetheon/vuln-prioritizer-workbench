"""Parsers for plain CVE lists and generic occurrence CSVs."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from app.domain.engine.models import InputOccurrence, ParsedInput
from app.domain.engine.security_redaction import redact_text
from app.domain.engine.utils import normalize_cve_id

from .common import (
    csv_value,
    first_existing_field,
    normalize_asset_criticality,
    normalize_asset_environment,
    normalize_asset_exposure,
    split_versions,
)

_COMMENT_PREFIX = "#"
_CSV_DELIMITERS = ",;\t|"
_GENERIC_OCCURRENCE_FIELDS = {
    "business_service",
    "component_name",
    "component_version",
    "criticality",
    "cve_id",
    "environment",
    "exposure",
    "fix_versions",
    "owner",
    "purl",
    "raw_severity",
    "source",
    "target_ref",
}


def parse_cve_list(path: Path) -> ParsedInput:
    """Parse cve list function."""
    suffix = path.suffix.lower()
    if suffix not in {".txt", ".csv"}:
        raise ValueError("Unsupported input format. Use .txt or .csv files.")

    rows = _read_cve_txt(path) if suffix == ".txt" else _read_cve_csv(path)
    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    seen: set[tuple[str, str | None, str | None, str | None]] = set()

    for line_number, raw_value, target_ref, component_name, component_version in rows:
        cve_id = normalize_cve_id(raw_value)
        if cve_id is None:
            safe_value = redact_text(repr(raw_value))
            warnings.append(f"Ignored invalid CVE identifier at line {line_number}: {safe_value}")
            continue
        key = (cve_id, target_ref, component_name, component_version)
        if key in seen:
            continue
        seen.add(key)
        occurrences.append(
            InputOccurrence(
                cve_id=cve_id,
                source_format="cve-list",
                source_record_id=f"line:{line_number}",
                component_name=component_name,
                component_version=component_version,
                target_ref=target_ref,
            )
        )

    return ParsedInput(
        input_format="cve-list",
        total_rows=len(rows),
        occurrences=occurrences,
        warnings=warnings,
    )


def _read_cve_txt(path: Path) -> list[tuple[int, str, None, None, None]]:
    """Read cve txt function."""
    rows: list[tuple[int, str, None, None, None]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            value = line.strip()
            if not value or value.startswith(_COMMENT_PREFIX):
                continue
            rows.append((line_number, value, None, None, None))
    return rows


def _read_cve_csv(path: Path) -> list[tuple[int, str, str | None, str | None, str | None]]:
    """Read cve csv function."""
    field_map, csv_rows = _read_csv_records(path, document_name="CSV input")
    cve_field = first_existing_field(field_map, "cve_id")
    if cve_field is None:
        raise ValueError("CSV input must contain a cve_id column.")

    rows: list[tuple[int, str, str | None, str | None, str | None]] = []
    for row_number, row in csv_rows:
        value = (row.get(cve_field) or "").strip()
        if not value:
            continue
        rows.append(
            (
                row_number,
                value,
                csv_value(row, field_map, "target_ref"),
                csv_value(row, field_map, "component_name"),
                csv_value(row, field_map, "component_version"),
            )
        )
    return rows


def parse_generic_occurrence_csv(path: Path) -> ParsedInput:
    """Parse generic occurrence csv function."""
    if path.suffix.lower() != ".csv":
        raise ValueError("generic-occurrence-csv input must be a .csv file.")

    warnings: list[str] = []
    occurrences: list[InputOccurrence] = []
    total_rows = 0
    field_map, rows = _read_csv_records(path, document_name="generic-occurrence-csv")
    unknown_fields = tuple(
        sorted(
            original
            for normalized, original in field_map.items()
            if normalized not in _GENERIC_OCCURRENCE_FIELDS
        )
    )
    if unknown_fields:
        warnings.append(
            "Ignored unknown generic-occurrence-csv columns: " + ", ".join(unknown_fields) + "."
        )
    cve_field = first_existing_field(field_map, "cve_id")
    if cve_field is None:
        raise ValueError("generic-occurrence-csv must contain a cve_id column.")

    for row_number, row in rows:
        total_rows += 1
        cve_id = normalize_cve_id(row.get(cve_field))
        if cve_id is None:
            warnings.append(
                f"Ignored invalid CVE identifier at line {row_number}: {row.get(cve_field)!r}"
            )
            continue
        target_ref = csv_value(row, field_map, "target_ref")
        occurrences.append(
            InputOccurrence(
                cve_id=cve_id,
                source_format=csv_value(row, field_map, "source") or "generic-occurrence-csv",
                component_name=csv_value(row, field_map, "component_name"),
                component_version=csv_value(row, field_map, "component_version"),
                purl=csv_value(row, field_map, "purl"),
                fix_versions=split_versions(csv_value(row, field_map, "fix_versions")),
                source_record_id=f"row:{row_number}",
                raw_severity=csv_value(row, field_map, "raw_severity"),
                target_kind="generic",
                target_ref=target_ref,
                asset_criticality=normalize_asset_criticality(
                    csv_value(row, field_map, "criticality"),
                    warnings=warnings,
                    row_number=row_number,
                ),
                asset_exposure=normalize_asset_exposure(
                    csv_value(row, field_map, "exposure"),
                    warnings=warnings,
                    row_number=row_number,
                ),
                asset_environment=normalize_asset_environment(
                    csv_value(row, field_map, "environment"),
                    warnings=warnings,
                    row_number=row_number,
                ),
                asset_owner=csv_value(row, field_map, "owner"),
                asset_business_service=csv_value(row, field_map, "business_service"),
                raw_evidence=_generic_raw_evidence(
                    row,
                    field_map=field_map,
                    line_number=row_number,
                    unknown_fields=unknown_fields,
                ),
            )
        )

    return ParsedInput(
        input_format="generic-occurrence-csv",
        total_rows=total_rows,
        occurrences=occurrences,
        warnings=warnings,
    )


def _read_csv_records(
    path: Path,
    *,
    document_name: str,
) -> tuple[dict[str, str], list[tuple[int, dict[str, str]]]]:
    """Read csv records function."""
    text = path.read_text(encoding="utf-8")
    try:
        dialect = csv.Sniffer().sniff(_csv_sample(text), delimiters=_CSV_DELIMITERS)
    except csv.Error:
        dialect = csv.excel

    reader = csv.reader(io.StringIO(text), dialect=dialect)
    header: list[str] | None = None
    rows: list[tuple[int, dict[str, str]]] = []
    previous_line_number = 0
    try:
        for record in reader:
            line_number = previous_line_number + 1
            previous_line_number = reader.line_num
            if _ignored_csv_record(record):
                continue
            if header is None:
                header = record
                continue
            if len(record) > len(header):
                raise ValueError(
                    f"{document_name} row at line {line_number} has {len(record)} columns; "
                    f"expected {len(header)}."
                )
            rows.append((line_number, _csv_row(header, record)))
    except csv.Error as exc:
        raise ValueError(f"{document_name} parse error near line {reader.line_num}: {exc}") from exc

    if not header:
        raise ValueError(f"{document_name} is missing a header row.")
    field_map = {field.strip().lower(): field for field in header if field}
    return field_map, rows


def _generic_raw_evidence(
    row: dict[str, str],
    *,
    field_map: dict[str, str],
    line_number: int,
    unknown_fields: tuple[str, ...],
) -> dict[str, object]:
    """Generic raw evidence function."""
    return {
        "input_type": "generic-occurrence-csv",
        "line_number": line_number,
        "source_record_id": f"row:{line_number}",
        "source": _csv_optional(row, field_map, "source"),
        "raw_severity": _csv_optional(row, field_map, "raw_severity"),
        "purl": _csv_optional(row, field_map, "purl"),
        "owner": _csv_optional(row, field_map, "owner"),
        "business_service": _csv_optional(row, field_map, "business_service"),
        "target_ref": _csv_optional(row, field_map, "target_ref"),
        "criticality": _csv_optional(row, field_map, "criticality"),
        "exposure": _csv_optional(row, field_map, "exposure"),
        "environment": _csv_optional(row, field_map, "environment"),
        "unknown_columns": _unknown_column_values(row, unknown_fields),
    }


def _csv_optional(row: dict[str, str], field_map: dict[str, str], *fields: str) -> str | None:
    """Csv optional function."""
    for field in fields:
        value = csv_value(row, field_map, field)
        if value:
            return value
    return None


def _unknown_column_values(row: dict[str, str], fields: tuple[str, ...]) -> dict[str, str]:
    """Unknown column values function."""
    return {field: value for field in fields if (value := (row.get(field) or "").strip())}


def _csv_sample(text: str) -> str:
    """Csv sample function."""
    sample = "\n".join(
        line
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith(_COMMENT_PREFIX)
    )
    return sample or text


def _ignored_csv_record(record: list[str]) -> bool:
    """Ignored csv record function."""
    if not record or all(not value.strip() for value in record):
        return True
    return record[0].strip().startswith(_COMMENT_PREFIX)


def _csv_row(header: list[str], record: list[str]) -> dict[str, str]:
    """Csv row function."""
    row = {field: "" for field in header}
    for index, value in enumerate(record):
        row[header[index]] = value
    return row
