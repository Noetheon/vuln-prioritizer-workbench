"""CVE list TXT/CSV importer for the template Workbench import boundary."""

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

CVE_LIST_INPUT_TYPE = "cve-list"
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_COMMENT_PREFIX = "#"


@dataclass(frozen=True, slots=True)
class CveListImporter:
    """Parse simple CVE TXT/CSV inputs into normalized occurrences."""

    input_type: str = CVE_LIST_INPUT_TYPE

    def parse(
        self,
        payload: InputPayload,
        *,
        filename: str | None = None,
    ) -> list[NormalizedOccurrence]:
        text = _payload_to_text(payload)
        suffix = _filename_suffix(filename)
        if suffix == ".csv":
            return _parse_csv(text)
        if suffix in {"", ".txt"}:
            return _parse_txt(text)
        raise ImporterParseError("cve-list supports .txt and .csv inputs.")


def _payload_to_text(payload: InputPayload) -> str:
    if isinstance(payload, str):
        return payload
    if isinstance(payload, bytes):
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ImporterParseError("cve-list input must be UTF-8 text.") from exc
    raise ImporterValidationError("cve-list payload must be bytes or string")


def _filename_suffix(filename: str | None) -> str:
    if not filename:
        return ""
    if "." not in filename:
        return ""
    return "." + filename.rsplit(".", 1)[1].strip().lower()


def _parse_txt(text: str) -> list[NormalizedOccurrence]:
    occurrences: list[NormalizedOccurrence] = []
    seen: set[tuple[str, str | None, str | None, str | None]] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        value = line.strip()
        if _skip_line(value):
            continue
        cve = _normalize_cve(value, line_number=line_number)
        _append_unique(
            occurrences,
            seen,
            cve=cve,
            asset_ref=None,
            component=None,
            version=None,
            line_number=line_number,
        )
    return occurrences


def _parse_csv(text: str) -> list[NormalizedOccurrence]:
    indexed_lines = [
        (line_number, line)
        for line_number, line in enumerate(text.splitlines(), start=1)
        if not _skip_line(line.strip())
    ]
    if not indexed_lines:
        raise ImporterParseError("cve-list CSV input is missing a header row.")

    reader = csv.DictReader(io.StringIO("\n".join(line for _, line in indexed_lines)))
    if not reader.fieldnames:
        raise ImporterParseError("cve-list CSV input is missing a header row.")
    field_map = {field.strip().lower(): field for field in reader.fieldnames if field}
    cve_field = field_map.get("cve_id") or field_map.get("cve")
    if cve_field is None:
        raise ImporterParseError("cve-list CSV input must contain a cve_id column.")

    occurrences: list[NormalizedOccurrence] = []
    seen: set[tuple[str, str | None, str | None, str | None]] = set()
    data_line_numbers = [line_number for line_number, _ in indexed_lines[1:]]
    for row, line_number in zip(reader, data_line_numbers, strict=True):
        raw_cve = _csv_value(row, cve_field)
        if _skip_line(raw_cve):
            continue
        cve = _normalize_cve(raw_cve, line_number=line_number)
        asset_ref = _csv_optional(row, field_map, "asset_ref")
        component = _csv_optional(row, field_map, "component")
        version = _csv_optional(row, field_map, "version")
        _append_unique(
            occurrences,
            seen,
            cve=cve,
            asset_ref=asset_ref,
            component=component,
            version=version,
            line_number=line_number,
        )
    return occurrences


def _append_unique(
    occurrences: list[NormalizedOccurrence],
    seen: set[tuple[str, str | None, str | None, str | None]],
    *,
    cve: str,
    asset_ref: str | None,
    component: str | None,
    version: str | None,
    line_number: int,
) -> None:
    key = (cve, asset_ref, component, version)
    if key in seen:
        return
    seen.add(key)
    occurrences.append(
        NormalizedOccurrence(
            cve=cve,
            component=component,
            version=version,
            asset_ref=asset_ref,
            source=CVE_LIST_INPUT_TYPE,
            raw_evidence={
                "input_type": CVE_LIST_INPUT_TYPE,
                "line_number": line_number,
                "source_record_id": f"line:{line_number}",
            },
        )
    )


def _normalize_cve(value: str, *, line_number: int) -> str:
    candidate = value.strip().upper()
    if not _CVE_PATTERN.fullmatch(candidate):
        raise ImporterParseError(f"Invalid CVE identifier at line {line_number}: {value!r}")
    return candidate


def _skip_line(value: str) -> bool:
    return not value or value.startswith(_COMMENT_PREFIX)


def _csv_value(row: dict[str, str], field_name: str) -> str:
    return (row.get(field_name) or "").strip()


def _csv_optional(row: dict[str, str], field_map: dict[str, str], field_name: str) -> str | None:
    mapped = field_map.get(field_name)
    if mapped is None:
        return None
    value = _csv_value(row, mapped)
    return value or None
