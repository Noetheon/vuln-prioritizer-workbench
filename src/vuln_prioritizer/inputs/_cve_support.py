"""Private CVE normalization helpers for input parsers."""

from __future__ import annotations

from collections.abc import Iterable

from vuln_prioritizer.utils import normalize_cve_id


def normalize_cve_or_warn(
    raw_value: str | None,
    *,
    source_name: str,
    warnings: list[str],
) -> str | None:
    """Normalize a scanner/SBOM CVE field and emit the existing warning on failure."""
    cve_id = normalize_cve_id(raw_value)
    if cve_id is None:
        warnings.append(f"Ignored non-CVE {source_name} vulnerability identifier: {raw_value!r}")
    return cve_id


def first_normalized_cve(values: Iterable[str | None]) -> str | None:
    """Return the first value that normalizes to a CVE identifier."""
    for value in values:
        cve_id = normalize_cve_id(value)
        if cve_id is not None:
            return cve_id
    return None
