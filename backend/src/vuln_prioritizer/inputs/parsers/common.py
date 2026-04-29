"""Shared helpers for input parser families."""

from __future__ import annotations

import csv
import json
from pathlib import Path


def read_txt(path: Path) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            rows.append((line_number, stripped))
    return rows


def read_cve_csv(path: Path) -> list[tuple[int, str]]:
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


def first_existing_field(field_map: dict[str, str], *candidates: str) -> str | None:
    for candidate in candidates:
        field = field_map.get(candidate)
        if field is not None:
            return field
    return None


def csv_value(row: dict[str, str], field_map: dict[str, str], *candidates: str) -> str | None:
    field = first_existing_field(field_map, *candidates)
    if field is None:
        return None
    value = (row.get(field) or "").strip()
    return value or None


def normalize_asset_criticality(
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


def normalize_asset_exposure(
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


def normalize_asset_environment(
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


def split_versions(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return as_string_list(value)
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


def first_present_string(*values: object) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def as_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if item is not None and str(item).strip()]


def load_json_object(path: Path, document_name: str) -> dict:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{document_name} is invalid JSON: {exc.msg}.") from exc
    if not isinstance(document, dict):
        raise ValueError(f"{document_name} must be a top-level JSON object.")
    return document


def dict_value(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def dict_items(value: object) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def first_string_from_list(value: object) -> str | None:
    if not isinstance(value, list):
        return None
    for item in value:
        if isinstance(item, str) and item.strip():
            return item.strip()
    return None
