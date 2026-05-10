"""CVE list TXT/CSV importer for the Workbench import boundary."""

from __future__ import annotations

from dataclasses import dataclass

from app.importers.contracts import (
    ImporterParseError,
    InputPayload,
    NormalizedOccurrence,
)
from app.importers.input_loader_adapter import parse_payload_with_input_loader

CVE_LIST_INPUT_TYPE = "cve-list"


@dataclass(frozen=True, slots=True)
class CveListImporter:
    """Parse simple CVE TXT/CSV inputs through the shared core loader."""

    input_type: str = CVE_LIST_INPUT_TYPE

    def parse(
        self,
        payload: InputPayload,
        *,
        filename: str | None = None,
    ) -> list[NormalizedOccurrence]:
        suffix = _filename_suffix(filename)
        if suffix not in {"", ".txt", ".csv"}:
            raise ImporterParseError("cve-list supports .txt and .csv inputs.")
        return parse_payload_with_input_loader(
            CVE_LIST_INPUT_TYPE,
            payload,
            default_suffix=".csv" if suffix == ".csv" else ".txt",
            filename=filename,
            prefer_asset_id_as_asset_ref=False,
            strict_invalid_cve_warnings=True,
        )


def _filename_suffix(filename: str | None) -> str:
    if not filename:
        return ""
    if "." not in filename:
        return ""
    return "." + filename.rsplit(".", 1)[1].strip().lower()
