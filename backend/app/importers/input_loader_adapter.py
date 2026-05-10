"""Shared adapter from core input normalization into Workbench importer DTOs."""

from __future__ import annotations

import re
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from app.importers.contracts import (
    ImporterParseError,
    ImporterValidationError,
    InputPayload,
    NormalizedOccurrence,
)
from vuln_prioritizer.inputs.loader import InputLoader
from vuln_prioritizer.inputs.parsers import parse_cve_list, parse_generic_occurrence_csv
from vuln_prioritizer.models_input import InputOccurrence, ParsedInput


def parse_payload_with_input_loader(
    input_type: str,
    payload: InputPayload,
    *,
    default_suffix: str,
    filename: str | None = None,
    prefer_asset_id_as_asset_ref: bool = True,
    strict_invalid_cve_warnings: bool = False,
) -> list[NormalizedOccurrence]:
    """Parse an upload payload through the core InputLoader parser registry."""
    suffix = _payload_suffix(filename=filename, default_suffix=default_suffix)
    with TemporaryDirectory(prefix="vpw-import-") as temp_dir:
        input_path = Path(temp_dir) / f"input{suffix}"
        _write_payload(input_path, payload, input_type=input_type)
        try:
            parsed_input = _parse_input_path(
                input_path,
                input_type=input_type,
                preserve_parser_warnings=strict_invalid_cve_warnings,
            )
        except UnicodeDecodeError as exc:
            raise ImporterParseError(f"{input_type} input must be UTF-8 text.") from exc
        except Exception as exc:
            raise ImporterParseError(_workbench_parse_error(input_type, str(exc))) from exc

    if strict_invalid_cve_warnings:
        _raise_invalid_cve_warnings(input_type, parsed_input.warnings)

    return [
        _normalize_occurrence(
            item,
            input_type=input_type,
            prefer_asset_id_as_asset_ref=prefer_asset_id_as_asset_ref,
        )
        for item in parsed_input.occurrences
    ]


def _parse_input_path(
    path: Path,
    *,
    input_type: str,
    preserve_parser_warnings: bool,
) -> ParsedInput:
    if preserve_parser_warnings and input_type == "cve-list":
        return parse_cve_list(path)
    if preserve_parser_warnings and input_type == "generic-occurrence-csv":
        return parse_generic_occurrence_csv(path)
    return InputLoader().load(path, input_format=input_type)


def _write_payload(path: Path, payload: InputPayload, *, input_type: str) -> None:
    if isinstance(payload, bytes):
        path.write_bytes(payload)
        return
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
        return
    raise ImporterValidationError(f"{input_type} payload must be bytes or string")


def _payload_suffix(*, filename: str | None, default_suffix: str) -> str:
    if filename:
        suffix = Path(filename).suffix.lower()
        if suffix:
            return suffix
    return default_suffix


def _raise_invalid_cve_warnings(input_type: str, warnings: list[str]) -> None:
    messages = [
        warning.removeprefix("Ignored ").strip()
        for warning in warnings
        if "invalid CVE identifier" in warning
    ]
    if not messages:
        return
    if input_type == "generic-occurrence-csv":
        raise ImporterParseError("generic-occurrence-csv row errors: " + "; ".join(messages))
    raise ImporterParseError("; ".join(messages))


def _workbench_parse_error(input_type: str, message: str) -> str:
    if input_type == "cve-list" and "must contain a 'cve_id' or 'cve' column" in message:
        return "cve-list CSV input must contain a cve_id column."
    row_shape = re.fullmatch(
        r"(?P<name>.+) row at line (?P<line>\d+) has (?P<got>\d+) columns; "
        r"expected (?P<expected>\d+)\.",
        message,
    )
    if row_shape is not None:
        return (
            f"{input_type} row errors: line {row_shape.group('line')}: "
            f"expected {row_shape.group('expected')} columns, got {row_shape.group('got')}"
        )
    if input_type not in {"cve-list", "generic-occurrence-csv"} and input_type not in message:
        return f"Could not parse {input_type!r} input payload: {message}"
    return message


def _normalize_occurrence(
    occurrence: InputOccurrence,
    *,
    input_type: str,
    prefer_asset_id_as_asset_ref: bool,
) -> NormalizedOccurrence:
    raw_evidence = dict(occurrence.raw_evidence)
    if not raw_evidence:
        raw_evidence = _raw_evidence(occurrence, input_type=input_type)
    return NormalizedOccurrence(
        cve=occurrence.cve_id,
        component=occurrence.component_name,
        version=occurrence.component_version,
        asset_ref=_asset_ref(
            occurrence,
            prefer_asset_id_as_asset_ref=prefer_asset_id_as_asset_ref,
        ),
        source=occurrence.source_format,
        fix_version=occurrence.fix_versions[0] if occurrence.fix_versions else None,
        raw_evidence=raw_evidence,
    )


def _asset_ref(
    occurrence: InputOccurrence,
    *,
    prefer_asset_id_as_asset_ref: bool,
) -> str | None:
    if prefer_asset_id_as_asset_ref:
        return occurrence.asset_id or occurrence.target_ref
    return occurrence.target_ref


def _raw_evidence(occurrence: InputOccurrence, *, input_type: str) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "input_type": input_type,
        "source_format": occurrence.source_format,
        "source_id": occurrence.source_id,
        "source_record_id": occurrence.source_record_id,
        "purl": occurrence.purl,
        "package_type": occurrence.package_type,
        "file_path": occurrence.file_path,
        "dependency_path": occurrence.dependency_path,
        "fix_versions": list(occurrence.fix_versions),
        "raw_severity": occurrence.raw_severity,
        "target_kind": occurrence.target_kind,
        "target_ref": occurrence.target_ref,
        "asset_id": occurrence.asset_id,
    }
    line_number = _line_number_from_record_id(occurrence.source_record_id)
    if line_number is not None:
        evidence["line_number"] = line_number
    return evidence


def _line_number_from_record_id(value: str | None) -> int | None:
    if not value:
        return None
    match = re.fullmatch(r"(?:line|row):(?P<line>\d+)", value)
    return int(match.group("line")) if match else None
