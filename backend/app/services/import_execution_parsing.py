"""Initial Workbench import parsing stage."""

from __future__ import annotations

from dataclasses import dataclass

from app.domain.import_asset_context import (
    canonicalize_occurrence_asset_context as _canonicalize_occurrence_asset_context,
)
from app.importers import ImporterValidationError, NormalizedOccurrence, build_importer_registry
from app.importers.input_loader_adapter import ParsedWorkbenchInput
from app.services.import_execution_types import PreparedImportUpload


@dataclass(frozen=True, slots=True)
class ParsedPreparedUpload:
    """Data representation and logic for Parsed Prepared Upload."""

    occurrences: list[NormalizedOccurrence]
    parsed_input: ParsedWorkbenchInput


def parse_prepared_upload(prepared: PreparedImportUpload) -> ParsedPreparedUpload:
    """Parse prepared upload function."""
    importer = build_importer_registry().get(prepared.input_type)
    parse_with_metadata = getattr(importer, "parse_with_metadata", None)
    if not callable(parse_with_metadata):
        raise ImporterValidationError(
            f"Importer {prepared.input_type!r} does not expose parsed input metadata."
        )
    parsed_input = parse_with_metadata(
        prepared.upload_bytes,
        filename=prepared.stored_filename,
    )
    return ParsedPreparedUpload(
        occurrences=[
            _canonicalize_occurrence_asset_context(item) for item in parsed_input.occurrences
        ],
        parsed_input=parsed_input,
    )


def summary_warnings(summary: dict[str, object] | None) -> list[str]:
    """Summary warnings function."""
    if summary is None:
        return []
    raw_warnings = summary.get("warnings")
    if not isinstance(raw_warnings, list):
        return []
    return [str(warning) for warning in raw_warnings if warning]
