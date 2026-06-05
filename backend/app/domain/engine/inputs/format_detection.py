"""Input format detection helpers."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from . import _xml_support

GENERIC_OCCURRENCE_CVE_FIELDS = {"cve_id"}

GENERIC_OCCURRENCE_HINT_FIELDS = {
    "component_name",
    "component_version",
    "purl",
    "fix_versions",
    "target_ref",
    "source",
    "criticality",
    "exposure",
    "environment",
    "owner",
    "business_service",
    "raw_severity",
}

_COMMENT_PREFIX = "#"

_CSV_DELIMITERS = ",;\t|"


def detect_input_format(path: Path, *, explicit_format: str = "auto") -> str:
    """Resolve the effective input format."""
    if explicit_format != "auto":
        return explicit_format

    suffix = path.suffix.lower()
    if suffix == ".csv" and _looks_like_generic_occurrence_csv(path):
        return "generic-occurrence-csv"
    if suffix in {".txt", ".csv"}:
        return "cve-list"
    if suffix == ".nessus":
        return "nessus-xml"
    if suffix == ".xml":
        root = _xml_support.load_xml_root(path)
        if _xml_support.looks_like_nessus_document(root):
            return "nessus-xml"
        if _xml_support.looks_like_openvas_document(root):
            return "openvas-xml"
        raise ValueError(
            "Unable to auto-detect the XML input format. "
            "Use --input-format nessus-xml or --input-format openvas-xml."
        )
    if suffix != ".json":
        raise ValueError(
            "Unable to auto-detect the input format. "
            "Use --input-format for non-.txt/.csv/.json/.xml/.nessus files."
        )

    document = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(document, dict) and "Results" in document:
        return "trivy-json"
    if isinstance(document, dict) and "matches" in document:
        return "grype-json"
    if (
        isinstance(document, dict)
        and "bomFormat" in document
        and "CycloneDX" in str(document.get("bomFormat"))
    ):
        return "cyclonedx-json"
    if isinstance(document, dict) and "spdxVersion" in document:
        return "spdx-json"
    if isinstance(document, dict) and "scanInfo" in document and "dependencies" in document:
        return "dependency-check-json"
    if isinstance(document, list) or (
        isinstance(document, dict) and ("alerts" in document or "security_advisory" in document)
    ):
        return "github-alerts-json"
    raise ValueError("Unable to auto-detect the JSON input format.")


def _looks_like_generic_occurrence_csv(path: Path) -> bool:
    """Looks like generic occurrence csv function."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    try:
        dialect = csv.Sniffer().sniff(_csv_sample(text), delimiters=_CSV_DELIMITERS)
    except csv.Error:
        dialect = csv.excel
    try:
        reader = csv.reader(text.splitlines(), dialect=dialect)
        header = next((record for record in reader if not _ignored_csv_record(record)), [])
    except csv.Error:
        return False
    normalized_header = {field.strip().lower() for field in header if field}
    return bool(
        normalized_header.intersection(GENERIC_OCCURRENCE_CVE_FIELDS)
        and normalized_header.intersection(GENERIC_OCCURRENCE_HINT_FIELDS)
    )


def _csv_sample(text: str) -> str:
    """Csv sample function."""
    sample = "\n".join(
        line
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith(_COMMENT_PREFIX)
    )
    return sample or text


def _ignored_csv_record(record: list[str]) -> bool:
    """Ignored csv record function."""
    if not record or all(not value.strip() for value in record):
        return True
    return record[0].strip().startswith(_COMMENT_PREFIX)


__all__ = [
    "GENERIC_OCCURRENCE_CVE_FIELDS",
    "GENERIC_OCCURRENCE_HINT_FIELDS",
    "_COMMENT_PREFIX",
    "_CSV_DELIMITERS",
    "detect_input_format",
    "_looks_like_generic_occurrence_csv",
    "_csv_sample",
    "_ignored_csv_record",
]
