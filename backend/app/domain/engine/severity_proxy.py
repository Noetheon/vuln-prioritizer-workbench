"""Source-reported severity as a transparent stand-in for missing NVD CVSS."""

from __future__ import annotations

from collections.abc import Iterable

from app.domain.engine.models import InputOccurrence, SeverityProxy

# Lower bound of each CVSS v3 qualitative severity band. A proxy never claims a
# score higher than the band a source reported, so it can only prevent a
# finding from being treated as safe while NVD analysis is pending.
SEVERITY_BAND_CVSS_FLOORS: dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 0.1,
}
_BAND_ORDER = ("critical", "high", "medium", "low")
_LABEL_ALIASES = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
}
# Nessus falls back to its 0-4 severity attribute when no risk factor exists.
_NESSUS_LEVELS = {"4": "critical", "3": "high", "2": "medium", "1": "low"}


def normalize_reported_severity(raw_value: str | None, *, source_format: str) -> str | None:
    """Map a source-reported severity label or score to a CVSS qualitative band."""
    value = (raw_value or "").strip().lower()
    if not value:
        return None
    if value in _LABEL_ALIASES:
        return _LABEL_ALIASES[value]
    if source_format == "nessus-xml" and value in _NESSUS_LEVELS:
        return _NESSUS_LEVELS[value]
    try:
        score = float(value)
    except ValueError:
        return None
    return _band_for_score(score)


def severity_proxy_for_occurrences(
    occurrences: Iterable[InputOccurrence],
) -> SeverityProxy | None:
    """Return the highest source-reported band for one finding scope, if any."""
    best: SeverityProxy | None = None
    for occurrence in occurrences:
        band = normalize_reported_severity(
            occurrence.raw_severity,
            source_format=occurrence.source_format,
        )
        if band is None:
            continue
        candidate = SeverityProxy(
            severity=band,
            cvss_floor=SEVERITY_BAND_CVSS_FLOORS[band],
            raw_value=(occurrence.raw_severity or "").strip(),
            source_format=occurrence.source_format,
        )
        if best is None or _proxy_sort_key(candidate) < _proxy_sort_key(best):
            best = candidate
    return best


def _band_for_score(score: float) -> str | None:
    if score != score or score <= 0.0 or score > 10.0:  # NaN, "none", or out of range
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _proxy_sort_key(proxy: SeverityProxy) -> tuple[int, str, str]:
    return (_BAND_ORDER.index(proxy.severity), proxy.source_format, proxy.raw_value)
