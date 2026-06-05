"""Generic occurrence CSV importer for the Workbench import boundary."""

from __future__ import annotations

from dataclasses import dataclass

from app.importers.contracts import (
    ImporterParseError,
    InputPayload,
    NormalizedOccurrence,
)
from app.importers.input_loader_adapter import (
    ParsedWorkbenchInput,
    parse_payload_with_input_loader_result,
)

GENERIC_OCCURRENCE_CSV_INPUT_TYPE = "generic-occurrence-csv"


@dataclass(frozen=True, slots=True)
class GenericOccurrenceCsvImporter:
    """Parse generic occurrence CSV inputs through the shared core loader."""

    input_type: str = GENERIC_OCCURRENCE_CSV_INPUT_TYPE

    def parse(
        self,
        payload: InputPayload,
        *,
        filename: str | None = None,
    ) -> list[NormalizedOccurrence]:
        """Parse method for GenericOccurrenceCsvImporter."""
        return self.parse_with_metadata(payload, filename=filename).occurrences

    def parse_with_metadata(
        self,
        payload: InputPayload,
        *,
        filename: str | None = None,
    ) -> ParsedWorkbenchInput:
        """Parse with metadata method for GenericOccurrenceCsvImporter."""
        if _filename_suffix(filename) not in {"", ".csv"}:
            raise ImporterParseError("generic-occurrence-csv supports .csv inputs.")
        return parse_payload_with_input_loader_result(
            GENERIC_OCCURRENCE_CSV_INPUT_TYPE,
            payload,
            default_suffix=".csv",
            filename=filename,
            prefer_asset_id_as_target_ref=False,
            strict_invalid_cve_warnings=True,
        )


def _filename_suffix(filename: str | None) -> str:
    """Filename suffix function."""
    if not filename or "." not in filename:
        return ""
    return "." + filename.rsplit(".", 1)[1].strip().lower()
