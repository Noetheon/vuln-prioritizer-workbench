"""Private CVE normalization helpers for input parsers."""

from __future__ import annotations

import re
from collections.abc import Iterable

from app.domain.engine.security_redaction import redact_text
from app.domain.engine.utils import normalize_cve_id

NON_CVE_SUMMARY_PREFIX = "Not imported: "
_NON_CVE_WARNING = re.compile(r"^Ignored non-CVE .*?identifier(?: in [^:]*)?: (?P<value>.+)$")
_NON_CVE_SAMPLE_SIZE = 5


def summarize_non_cve_identifiers(warnings: list[str]) -> list[str]:
    """
    Lead with one summary of vulnerabilities skipped because they have no CVE.

    Per-identifier warnings stay for diagnostics; the summary makes advisories
    such as GHSA, GO, RUSTSEC, or PYSEC entries visible at a glance. Applying
    it twice keeps a single, current summary.
    """
    detail = [warning for warning in warnings if not warning.startswith(NON_CVE_SUMMARY_PREFIX)]
    identifiers: list[str] = []
    for warning in detail:
        match = _NON_CVE_WARNING.match(warning)
        if match is None:
            continue
        value = match.group("value").strip().strip("'\"")
        if value and value != "None":
            identifiers.append(value)
    unique = list(dict.fromkeys(identifiers))
    if not unique:
        return detail
    sample = ", ".join(unique[:_NON_CVE_SAMPLE_SIZE])
    if len(unique) > _NON_CVE_SAMPLE_SIZE:
        sample = f"{sample}, +{len(unique) - _NON_CVE_SAMPLE_SIZE} more"
    noun = "vulnerability" if len(unique) == 1 else "vulnerabilities"
    summary = (
        f"{NON_CVE_SUMMARY_PREFIX}{len(unique)} {noun} without a CVE identifier ({sample}). "
        "The Workbench prioritizes CVE-identified findings; review these in the source report."
    )
    return [summary, *detail]


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
