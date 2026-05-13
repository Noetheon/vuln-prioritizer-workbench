"""Parse, asset-context, and VEX stages for Workbench import execution."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.domain.import_asset_context import (
    input_occurrence_from_workbench_occurrence as _input_occurrence_from_workbench_occurrence,
)
from app.domain.import_asset_context import (
    workbench_occurrence_with_asset_context as _workbench_occurrence_with_asset_context,
)
from app.domain.import_asset_context import (
    workbench_occurrence_with_vex as _workbench_occurrence_with_vex,
)
from app.importers.contracts import NormalizedOccurrence
from app.services.import_execution_parsing import summary_warnings as _summary_warnings
from app.services.import_uploads import (
    sanitize_parser_error_message as _sanitize_parser_error_message,
)
from vuln_prioritizer.inputs._occurrence_support import apply_asset_context, finalize_occurrences
from vuln_prioritizer.inputs._vex_support import apply_vex_statements
from vuln_prioritizer.inputs.loader import load_asset_context_file, load_vex_files
from vuln_prioritizer.models import InputSourceSummary, ParsedInput


def _apply_workbench_asset_context(
    occurrences: list[NormalizedOccurrence],
    *,
    asset_context_path: Path,
) -> tuple[list[NormalizedOccurrence], dict[str, Any]]:
    catalog, load_diagnostics = load_asset_context_file(
        asset_context_path,
        return_diagnostics=True,
    )
    input_occurrences = [
        _input_occurrence_from_workbench_occurrence(occurrence) for occurrence in occurrences
    ]
    enriched_occurrences, match_diagnostics = apply_asset_context(
        input_occurrences,
        catalog,
        return_diagnostics=True,
    )
    return (
        [
            _workbench_occurrence_with_asset_context(original, enriched)
            for original, enriched in zip(occurrences, enriched_occurrences, strict=True)
        ],
        {
            "total_rows": load_diagnostics.total_rows,
            "loaded_rows": load_diagnostics.loaded_rows,
            "skipped_rows": load_diagnostics.skipped_rows,
            "exact_rules": load_diagnostics.exact_rules,
            "contains_rules": load_diagnostics.contains_rules,
            "regex_rules": load_diagnostics.regex_rules,
            "glob_rules": load_diagnostics.glob_rules,
            "matched_occurrences": match_diagnostics.matched_occurrences,
            "unmatched_occurrences": match_diagnostics.unmatched_occurrences,
            "ambiguous_occurrences": match_diagnostics.ambiguous_occurrences,
            "warnings": [
                *load_diagnostics.warnings,
                *match_diagnostics.warnings,
            ],
        },
    )


def _apply_workbench_vex(
    occurrences: list[NormalizedOccurrence],
    *,
    vex_path: Path,
) -> tuple[list[NormalizedOccurrence], dict[str, Any]]:
    statements, load_diagnostics = load_vex_files(
        [vex_path],
        return_diagnostics=True,
    )
    input_occurrences = [
        _input_occurrence_from_workbench_occurrence(occurrence) for occurrence in occurrences
    ]
    enriched_occurrences, match_diagnostics = apply_vex_statements(
        input_occurrences,
        statements,
        return_diagnostics=True,
    )
    return (
        [
            _workbench_occurrence_with_vex(original, enriched)
            for original, enriched in zip(occurrences, enriched_occurrences, strict=True)
        ],
        {
            "file_count": load_diagnostics.file_count,
            "statement_count": load_diagnostics.statement_count,
            "skipped_statements": load_diagnostics.skipped_statements,
            "matched_occurrences": match_diagnostics.matched_occurrences,
            "unmatched_occurrences": match_diagnostics.unmatched_occurrences,
            "ambiguous_occurrences": match_diagnostics.ambiguous_occurrences,
            "conflict_occurrences": match_diagnostics.conflict_occurrences,
            "warnings": [
                *load_diagnostics.warnings,
                *match_diagnostics.warnings,
            ],
        },
    )


def _parsed_input_from_workbench_occurrences(
    occurrences: list[NormalizedOccurrence],
    *,
    input_path: Path,
    input_type: str,
    base_parsed_input: ParsedInput | None = None,
    asset_context_summary: dict[str, Any] | None,
    vex_summary: dict[str, Any] | None,
) -> ParsedInput:
    input_occurrences = [
        _input_occurrence_from_workbench_occurrence(occurrence) for occurrence in occurrences
    ]
    warnings = [
        *(base_parsed_input.warnings if base_parsed_input is not None else []),
        *_summary_warnings(asset_context_summary),
        *_summary_warnings(vex_summary),
    ]
    total_rows = (
        base_parsed_input.total_rows if base_parsed_input is not None else len(input_occurrences)
    )
    warning_count = (
        len(base_parsed_input.warnings) if base_parsed_input is not None else len(warnings)
    )
    return finalize_occurrences(
        input_occurrences,
        input_format=base_parsed_input.input_format
        if base_parsed_input is not None
        else input_type,
        warnings=warnings,
        total_rows=total_rows,
        max_cves=None,
        input_paths=[str(input_path)],
        source_summaries=[
            InputSourceSummary(
                input_path=str(input_path),
                input_format=input_type,
                total_rows=total_rows,
                occurrence_count=len(input_occurrences),
                unique_cves=len({occurrence.cve_id for occurrence in input_occurrences}),
                warning_count=warning_count,
            )
        ],
        asset_match_conflict_count=int(
            (asset_context_summary or {}).get("ambiguous_occurrences") or 0
        ),
        vex_conflict_count=int((vex_summary or {}).get("conflict_occurrences") or 0),
    )


def _parse_errors(
    exc: Exception,
    *,
    filename: str,
    input_type: str,
) -> list[dict[str, Any]]:
    message = _sanitize_parser_error_message(str(exc))
    row_prefix = "generic-occurrence-csv row errors: "
    messages = (
        [item.strip() for item in message.removeprefix(row_prefix).split(";") if item.strip()]
        if message.startswith(row_prefix)
        else [message]
    )
    return [
        _parse_error_payload(
            item,
            filename=filename,
            input_type=input_type,
            error_type=exc.__class__.__name__,
        )
        for item in messages
    ]


def _parse_error_payload(
    message: str,
    *,
    filename: str,
    input_type: str,
    error_type: str,
) -> dict[str, Any]:
    return {
        "input_type": input_type,
        "filename": filename,
        "message": message,
        "error_type": error_type,
        "line": _parse_error_line(message),
        "field": _parse_error_field(message),
        "value": _parse_error_value(message),
    }


def _parse_error_line(message: str) -> int | None:
    match = re.search(r"\bline (?P<line>\d+)\b", message)
    return int(match.group("line")) if match else None


def _parse_error_field(message: str) -> str | None:
    lower_message = message.lower()
    return (
        "cve_id"
        if any(marker in lower_message for marker in ("cve_id column", "cve identifier"))
        else None
    )


def _parse_error_value(message: str) -> str | None:
    match = re.search(r"(?P<quote>['\"])(?P<value>.+?)(?P=quote)", message)
    return match.group("value") if match else None
