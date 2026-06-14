"""Private CVE normalization helpers for input parsers."""

from __future__ import annotations

from collections.abc import Iterable

from app.domain.engine.security_redaction import redact_text
from app.domain.engine.utils import normalize_cve_id


def normalize_cve_or_warn(
    raw_value: str | None,
    *,
    source_name: str,
    warnings: list[str],
) -> str | None:
    """Normalize a scanner/SBOM CVE field and emit the existing warning on failure."""
    cve_id = normalize_cve_id(raw_value)
    if cve_id is None:
        safe_value = redact_text(repr(raw_value))
        warnings.append(f"Ignored non-CVE {source_name} vulnerability identifier: {safe_value}")
    return cve_id


def first_normalized_cve(values: Iterable[str | None]) -> str | None:
    """Return the first value that normalizes to a CVE identifier."""
    for value in values:
        cve_id = normalize_cve_id(value)
        if cve_id is not None:
            return cve_id
    return None


def all_normalized_cves(values: Iterable[str | None]) -> list[str]:
    """Return every distinct CVE identifier in input order."""
    cve_ids: list[str] = []
    seen: set[str] = set()
    for value in values:
        cve_id = normalize_cve_id(value)
        if cve_id is None or cve_id in seen:
            continue
        seen.add(cve_id)
        cve_ids.append(cve_id)
    return cve_ids
