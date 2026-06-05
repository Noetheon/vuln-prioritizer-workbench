"""Adapters from the offline input loader into the active importer contract."""

from __future__ import annotations

from dataclasses import dataclass

from app.domain.engine.options import InputFormat
from app.importers.contracts import (
    Importer,
    ImporterValidationError,
    InputPayload,
    NormalizedOccurrence,
)
from app.importers.cve_list import CveListImporter
from app.importers.generic_occurrence_csv import GenericOccurrenceCsvImporter
from app.importers.input_loader_adapter import (
    ParsedWorkbenchInput,
    parse_payload_with_input_loader_result,
)
from app.services.workbench_capabilities import (
    default_import_suffix_by_input_type,
    supported_import_input_types,
)

DEFAULT_IMPORT_INPUT_TYPES = supported_import_input_types()
_DEFAULT_SUFFIX_BY_INPUT_TYPE = default_import_suffix_by_input_type()


@dataclass(frozen=True, slots=True)
class OfflineInputLoaderImporter:
    """Importer backed by the existing offline input-normalization loader."""

    input_type: str

    def parse(
        self,
        payload: InputPayload,
        *,
        filename: str | None = None,
    ) -> list[NormalizedOccurrence]:
        """Parse method for OfflineInputLoaderImporter."""
        return self.parse_with_metadata(payload, filename=filename).occurrences

    def parse_with_metadata(
        self,
        payload: InputPayload,
        *,
        filename: str | None = None,
    ) -> ParsedWorkbenchInput:
        """Parse with metadata method for OfflineInputLoaderImporter."""
        if self.input_type not in DEFAULT_IMPORT_INPUT_TYPES:
            raise ImporterValidationError(f"Unsupported input type: {self.input_type!r}")
        return parse_payload_with_input_loader_result(
            self.input_type,
            payload,
            default_suffix=_DEFAULT_SUFFIX_BY_INPUT_TYPE[self.input_type],
            filename=filename,
            prefer_asset_id_as_target_ref=True,
        )


def default_importers() -> tuple[Importer, ...]:
    """Return importers for the currently supported local Workbench input types."""
    offline_loader_importers = tuple(
        OfflineInputLoaderImporter(input_type)
        for input_type in DEFAULT_IMPORT_INPUT_TYPES
        if input_type
        not in {
            InputFormat.cve_list.value,
            InputFormat.generic_occurrence_csv.value,
        }
    )
    return (CveListImporter(), GenericOccurrenceCsvImporter(), *offline_loader_importers)
