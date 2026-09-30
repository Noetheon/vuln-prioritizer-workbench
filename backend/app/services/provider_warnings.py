"""Readable provider warnings for import runs."""

from __future__ import annotations

import re
from collections.abc import Sequence

_NVD_FAILURE = re.compile(
    r"^NVD lookup failed for (?P<cve>CVE-\d{4}-\d{4,}): (?P<reason>.*)$", re.S
)
_EPSS_FAILURE = re.compile(r"^EPSS lookup failed for chunk (?P<cves>[^:]*): (?P<reason>.*)$", re.S)
_KEV_STALE_PREFIX = "KEV catalog load failed; using expired cached catalog"
_KEV_FAILURE_PREFIXES = ("KEV catalog load failed:", "KEV provider failed:")
_UNREACHABLE_MARKERS = (
    "connection",
    "max retries",
    "name or service not known",
    "name resolution",
    "proxy",
    "timed out",
    "timeout",
    "unreachable",
)
_KEV_STALE_NOTE = "The KEV catalog could not be refreshed, so an expired cached copy was used."
_KEV_FAILURE_NOTE = "The KEV catalog could not be loaded, so KEV status is unknown for this import."
# The per-source lines summarize_provider_warnings writes.
_SOURCE_SUMMARY = re.compile(
    r"^(NVD|EPSS) (could not be reached|rate-limited the lookups|lookups failed) "
    r"for \d+ CVEs?, so "
)


def summarize_provider_warnings(warnings: Sequence[str]) -> list[str]:
    """
    Replace per-CVE provider failures with one readable line per source.

    A run that could not reach EPSS says what that means for its priorities
    instead of listing one connection error per CVE; other warnings stay.
    """
    nvd_cves: list[str] = []
    nvd_reasons: list[str] = []
    epss_cves: list[str] = []
    epss_reasons: list[str] = []
    kev_note: str | None = None
    others: list[str] = []
    for warning in warnings:
        if nvd := _NVD_FAILURE.match(warning):
            nvd_cves.append(nvd.group("cve"))
            nvd_reasons.append(nvd.group("reason"))
        elif epss := _EPSS_FAILURE.match(warning):
            epss_cves.extend(cve.strip() for cve in epss.group("cves").split(",") if cve.strip())
            epss_reasons.append(epss.group("reason"))
        elif warning.startswith(_KEV_STALE_PREFIX):
            kev_note = _KEV_STALE_NOTE
        elif warning.startswith(_KEV_FAILURE_PREFIXES):
            kev_note = _KEV_FAILURE_NOTE
        else:
            others.append(warning)

    summary: list[str] = []
    if nvd_cves:
        count = len(set(nvd_cves))
        summary.append(
            f"NVD {_failure_phrase(nvd_reasons)} for {_cve_count(count)}, so "
            + (
                "its CVSS score and description are missing."
                if count == 1
                else "their CVSS scores and descriptions are missing."
            )
        )
    if epss_cves:
        count = len(set(epss_cves))
        summary.append(
            f"EPSS {_failure_phrase(epss_reasons)} for {_cve_count(count)}, so "
            + (
                "its priority was computed without EPSS."
                if count == 1
                else "their priorities were computed without EPSS."
            )
        )
    if kev_note:
        summary.append(kev_note)
    return [*summary, *others]


def provider_warning_lines(warnings: Sequence[str]) -> list[str]:
    """
    Return only the provider lines of a run's warnings, summarized.

    Works for runs recorded before warnings were summarized and after.
    """
    return [
        warning
        for warning in summarize_provider_warnings(warnings)
        if _SOURCE_SUMMARY.match(warning) or warning in (_KEV_STALE_NOTE, _KEV_FAILURE_NOTE)
    ]


def _failure_phrase(reasons: Sequence[str]) -> str:
    text = " ".join(reasons).lower()
    if "429" in text or "rate limit" in text:
        return "rate-limited the lookups"
    if any(marker in text for marker in _UNREACHABLE_MARKERS):
        return "could not be reached"
    return "lookups failed"


def _cve_count(count: int) -> str:
    return "1 CVE" if count == 1 else f"{count} CVEs"
