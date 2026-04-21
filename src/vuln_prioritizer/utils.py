"""Utility helpers shared across modules."""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import UTC, datetime

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def normalize_cve_id(raw_value: str | None) -> str | None:
    """Normalize a CVE identifier to uppercase if it is valid."""
    if raw_value is None:
        return None
    normalized = raw_value.strip().upper()
    if not normalized:
        return None
    if not CVE_ID_RE.fullmatch(normalized):
        return None
    return normalized


def safe_float(value: object) -> float | None:
    """Best-effort float conversion."""
    if value in (None, "", "N.A."):
        return None
    if not isinstance(value, str | int | float):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def chunk_cve_ids(cve_ids: Iterable[str], max_chars: int) -> list[list[str]]:
    """Chunk CVE identifiers so their comma-joined query stays below the limit."""
    chunks: list[list[str]] = []
    current: list[str] = []
    current_length = 0

    for cve_id in cve_ids:
        candidate_length = len(cve_id) if not current else current_length + 1 + len(cve_id)
        if current and candidate_length > max_chars:
            chunks.append(current)
            current = [cve_id]
            current_length = len(cve_id)
        else:
            current.append(cve_id)
            current_length = candidate_length

    if current:
        chunks.append(current)

    return chunks


def iso_utc_now() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""
    return datetime.now(tz=UTC).replace(microsecond=0).isoformat()


def comma_join(values: Iterable[str]) -> str:
    """Join non-empty values with commas."""
    return ", ".join(value for value in values if value)
