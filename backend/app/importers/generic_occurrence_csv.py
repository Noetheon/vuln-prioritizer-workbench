"""Generic occurrence CSV importer for the template Workbench import boundary."""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass

from app.importers.contracts import (
    ImporterParseError,
    ImporterValidationError,
    InputPayload,
    NormalizedOccurrence,
)

GENERIC_OCCURRENCE_CSV_INPUT_TYPE = "generic-occurrence-csv"
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_COMMENT_PREFIX = "#"
_CSV_DELIMITERS = ",;\t|"
_KNOWN_FIELDS = {
    "asset_business_service",
    "asset_criticality",
    "asset_environment",
    "asset_exposure",
    "asset_id",
    "asset_owner",
    "asset_ref",
    "business_service",
    "component",
    "component_name",
    "component_version",
    "criticality",
    "cve",
    "cve_id",
    "dependency_path",
    "ecosystem",
    "environment",
    "exposure",
    "file_path",
    "fix_version",
    "fix_versions",
    "fixed_versions",
    "installed_version",
    "owner",
    "package_type",
    "path",
    "purl",
    "raw_severity",
    "scanner",
    "service",
    "severity",
    "target",
    "target_kind",
    "target_ref",
    "version",
    "vulnerability_id",
}


@dataclass(frozen=True, slots=True)
class GenericOccurrenceCsvImporter:
    """Parse generic occurrence CSV inputs into normalized occurrences."""

    input_type: str = GENERIC_OCCURRENCE_CSV_INPUT_TYPE

    def parse(
        self,
        payload: InputPayload,
        *,
        filename: str | None = None,
    ) -> list[NormalizedOccurrence]:
        if _filename_suffix(filename) not in {"", ".csv"}:
            raise ImporterParseError("generic-occurrence-csv supports .csv inputs.")
        text = _payload_to_text(payload)
        field_map, rows = _read_csv_rows(text)
        cve_field = _first_field(field_map, "cve_id", "cve", "vulnerability_id")
        if cve_field is None:
            raise ImporterParseError(
                "generic-occurrence-csv input must contain a cve_id, cve, "
                "or vulnerability_id column."
            )

        unknown_fields = tuple(
            sorted(
                original
                for normalized, original in field_map.items()
                if normalized not in _KNOWN_FIELDS
            )
        )
        occurrences: list[NormalizedOccurrence] = []
        row_errors: list[str] = []
        for line_number, row in rows:
            raw_cve = _csv_value(row, cve_field)
            cve = _normalize_cve(raw_cve, line_number=line_number, errors=row_errors)
            if cve is None:
                continue
            occurrences.append(
                NormalizedOccurrence(
                    cve=cve,
                    asset_ref=_first_csv_optional(
                        row, field_map, "asset_ref", "target_ref", "target"
                    ),
                    component=_first_csv_optional(row, field_map, "component_name", "component"),
                    version=_first_csv_optional(
                        row,
                        field_map,
                        "component_version",
                        "version",
                        "installed_version",
                    ),
                    source=GENERIC_OCCURRENCE_CSV_INPUT_TYPE,
                    fix_version=_first_fix_version(row, field_map),
                    raw_evidence=_raw_evidence(row, field_map, line_number, unknown_fields),
                )
            )

        if row_errors:
            raise ImporterParseError("generic-occurrence-csv row errors: " + "; ".join(row_errors))
        return occurrences


def _payload_to_text(payload: InputPayload) -> str:
    if isinstance(payload, str):
        return payload
    if isinstance(payload, bytes):
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ImporterParseError("generic-occurrence-csv input must be UTF-8 text.") from exc
    raise ImporterValidationError("generic-occurrence-csv payload must be bytes or string")


def _filename_suffix(filename: str | None) -> str:
    if not filename or "." not in filename:
        return ""
    return "." + filename.rsplit(".", 1)[1].strip().lower()


def _read_csv_rows(text: str) -> tuple[dict[str, str], list[tuple[int, dict[str, str]]]]:
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
                raise ImporterParseError(
                    "generic-occurrence-csv row errors: "
                    f"line {line_number}: expected {len(header)} columns, got {len(record)}"
                )
            rows.append((line_number, _csv_row(header, record)))
    except csv.Error as exc:
        raise ImporterParseError(
            f"generic-occurrence-csv parse error near line {reader.line_num}: {exc}"
        ) from exc

    if not header:
        raise ImporterParseError("generic-occurrence-csv input is missing a header row.")
    field_map = {field.strip().lower(): field for field in header if field}
    return field_map, rows


def _csv_sample(text: str) -> str:
    sample = "\n".join(
        line
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith(_COMMENT_PREFIX)
    )
    return sample or text


def _ignored_csv_record(record: list[str]) -> bool:
    if not record or all(not value.strip() for value in record):
        return True
    return record[0].strip().startswith(_COMMENT_PREFIX)


def _csv_row(header: list[str], record: list[str]) -> dict[str, str]:
    row = {field: "" for field in header}
    for index, value in enumerate(record):
        row[header[index]] = value
    return row


def _normalize_cve(value: str, *, line_number: int, errors: list[str]) -> str | None:
    candidate = value.strip().upper()
    if not _CVE_PATTERN.fullmatch(candidate):
        errors.append(f"line {line_number}: invalid CVE identifier {value!r}")
        return None
    return candidate


def _first_fix_version(row: dict[str, str], field_map: dict[str, str]) -> str | None:
    value = _first_csv_optional(row, field_map, "fix_version", "fix_versions", "fixed_versions")
    if value is None:
        return None
    for separator in (",", "|"):
        if separator in value:
            return next((item.strip() for item in value.split(separator) if item.strip()), None)
    return value


def _first_csv_optional(row: dict[str, str], field_map: dict[str, str], *fields: str) -> str | None:
    for field in fields:
        value = _csv_optional(row, field_map, field)
        if value is not None:
            return value
    return None


def _first_field(field_map: dict[str, str], *fields: str) -> str | None:
    for field in fields:
        mapped = field_map.get(field)
        if mapped is not None:
            return mapped
    return None


def _csv_optional(row: dict[str, str], field_map: dict[str, str], field_name: str) -> str | None:
    mapped = field_map.get(field_name)
    if mapped is None:
        return None
    value = _csv_value(row, mapped)
    return value or None


def _csv_value(row: dict[str, str], field_name: str) -> str:
    return (row.get(field_name) or "").strip()


def _unknown_column_values(row: dict[str, str], unknown_fields: tuple[str, ...]) -> dict[str, str]:
    return {field: value for field in unknown_fields if (value := _csv_value(row, field))}


def _raw_evidence(
    row: dict[str, str],
    field_map: dict[str, str],
    line_number: int,
    unknown_fields: tuple[str, ...],
) -> dict[str, object]:
    return {
        "input_type": GENERIC_OCCURRENCE_CSV_INPUT_TYPE,
        "line_number": line_number,
        "source_record_id": f"row:{line_number}",
        "scanner": _csv_optional(row, field_map, "scanner"),
        "severity": _first_csv_optional(row, field_map, "severity", "raw_severity"),
        "purl": _csv_optional(row, field_map, "purl"),
        "owner": _first_csv_optional(row, field_map, "owner", "asset_owner"),
        "business_service": _first_csv_optional(
            row,
            field_map,
            "business_service",
            "service",
            "asset_business_service",
        ),
        "target_kind": _csv_optional(row, field_map, "target_kind"),
        "target_ref": _first_csv_optional(row, field_map, "target_ref", "target", "asset_ref"),
        "asset_id": _csv_optional(row, field_map, "asset_id"),
        "asset_criticality": _first_csv_optional(
            row, field_map, "criticality", "asset_criticality"
        ),
        "asset_exposure": _first_csv_optional(row, field_map, "exposure", "asset_exposure"),
        "asset_environment": _first_csv_optional(
            row, field_map, "environment", "asset_environment"
        ),
        "package_type": _first_csv_optional(row, field_map, "package_type", "ecosystem"),
        "file_path": _first_csv_optional(row, field_map, "file_path", "path"),
        "dependency_path": _csv_optional(row, field_map, "dependency_path"),
        "unknown_columns": _unknown_column_values(row, unknown_fields),
    }
