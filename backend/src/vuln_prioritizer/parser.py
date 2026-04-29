"""Compatibility facade for the richer input loader."""

from __future__ import annotations

from pathlib import Path

from vuln_prioritizer.inputs import InputLoader
from vuln_prioritizer.models import InputItem


def parse_input_file(
    path: Path,
    max_cves: int | None = None,
) -> tuple[list[InputItem], list[str], int]:
    """Parse an input file and return normalized, deduplicated CVE identifiers."""
    parsed = InputLoader().load(path, input_format="cve-list", max_cves=max_cves)
    items = [
        InputItem(cve_id=cve_id, source_format=parsed.input_format) for cve_id in parsed.unique_cves
    ]
    return items, parsed.warnings, parsed.total_rows
