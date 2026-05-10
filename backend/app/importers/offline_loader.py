"""Adapters from the offline CLI input loader into the active importer contract."""

from __future__ import annotations

from dataclasses import dataclass

from app.importers.contracts import (
    Importer,
    ImporterValidationError,
    InputPayload,
    NormalizedOccurrence,
)
from app.importers.cve_list import CveListImporter
from app.importers.generic_occurrence_csv import GenericOccurrenceCsvImporter
from app.importers.input_loader_adapter import parse_payload_with_input_loader
from vuln_prioritizer.cli_options import InputFormat

DEFAULT_IMPORT_INPUT_TYPES = (
    InputFormat.cve_list.value,
    InputFormat.generic_occurrence_csv.value,
    InputFormat.trivy_json.value,
    InputFormat.grype_json.value,
    InputFormat.cyclonedx_json.value,
    InputFormat.spdx_json.value,
    InputFormat.dependency_check_json.value,
    InputFormat.github_alerts_json.value,
    InputFormat.nessus_xml.value,
    InputFormat.openvas_xml.value,
)
_DEFAULT_SUFFIX_BY_INPUT_TYPE = {
    InputFormat.cve_list.value: ".txt",
    InputFormat.generic_occurrence_csv.value: ".csv",
    InputFormat.trivy_json.value: ".json",
    InputFormat.grype_json.value: ".json",
    InputFormat.cyclonedx_json.value: ".json",
    InputFormat.spdx_json.value: ".json",
    InputFormat.dependency_check_json.value: ".json",
    InputFormat.github_alerts_json.value: ".json",
    InputFormat.nessus_xml.value: ".nessus",
    InputFormat.openvas_xml.value: ".xml",
}


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
        if self.input_type not in DEFAULT_IMPORT_INPUT_TYPES:
            raise ImporterValidationError(f"Unsupported input type: {self.input_type!r}")
        return parse_payload_with_input_loader(
            self.input_type,
            payload,
            default_suffix=_DEFAULT_SUFFIX_BY_INPUT_TYPE[self.input_type],
            filename=filename,
            prefer_asset_id_as_asset_ref=True,
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
