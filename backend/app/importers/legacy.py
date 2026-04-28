"""Adapters from the existing local input loader into the template importer contract."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from app.importers.contracts import (
    Importer,
    ImporterParseError,
    ImporterValidationError,
    InputPayload,
    NormalizedOccurrence,
)
from app.importers.cve_list import CveListImporter
from vuln_prioritizer.cli_options import InputFormat
from vuln_prioritizer.inputs.loader import InputLoader
from vuln_prioritizer.models_input import InputOccurrence

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
class LegacyInputLoaderImporter:
    """Importer backed by the existing offline input-normalization loader."""

    input_type: str

    def parse(
        self,
        payload: InputPayload,
        *,
        filename: str | None = None,
    ) -> list[NormalizedOccurrence]:
        if self.input_type not in DEFAULT_IMPORT_INPUT_TYPES:
            raise ImporterValidationError(f"Unsupported legacy input type: {self.input_type!r}")
        path_suffix = _payload_suffix(input_type=self.input_type, filename=filename)
        with TemporaryDirectory(prefix="vpw-import-") as temp_dir:
            input_path = Path(temp_dir) / f"input{path_suffix}"
            _write_payload(input_path, payload)
            try:
                parsed_input = InputLoader().load(input_path, input_format=self.input_type)
            except Exception as exc:
                raise ImporterParseError(
                    f"Could not parse {self.input_type!r} input payload."
                ) from exc
        return [_normalize_occurrence(item) for item in parsed_input.occurrences]


def default_importers() -> tuple[Importer, ...]:
    """Return importers for the currently supported local Workbench input types."""
    legacy_importers = tuple(
        LegacyInputLoaderImporter(input_type)
        for input_type in DEFAULT_IMPORT_INPUT_TYPES
        if input_type != InputFormat.cve_list.value
    )
    return (CveListImporter(), *legacy_importers)


def _write_payload(path: Path, payload: InputPayload) -> None:
    if isinstance(payload, bytes):
        path.write_bytes(payload)
        return
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
        return
    raise ImporterValidationError("Importer payload must be bytes or string")


def _payload_suffix(*, input_type: str, filename: str | None) -> str:
    if filename:
        suffix = Path(filename).suffix.lower()
        if suffix:
            return suffix
    return _DEFAULT_SUFFIX_BY_INPUT_TYPE[input_type]


def _normalize_occurrence(occurrence: InputOccurrence) -> NormalizedOccurrence:
    return NormalizedOccurrence(
        cve=occurrence.cve_id,
        component=occurrence.component_name,
        version=occurrence.component_version,
        asset_ref=occurrence.asset_id or occurrence.target_ref,
        source=occurrence.source_format,
        fix_version=occurrence.fix_versions[0] if occurrence.fix_versions else None,
        raw_evidence=_raw_evidence(occurrence),
    )


def _raw_evidence(occurrence: InputOccurrence) -> dict[str, Any]:
    return {
        "source_format": occurrence.source_format,
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
