"""Provider data-quality projection helpers for analysis findings."""

from __future__ import annotations

from app.domain.engine.models import PrioritizedFinding, ProviderDataQualityFlag


def attach_provider_data_quality_flags(
    findings: list[PrioritizedFinding],
    flags_by_source: dict[str, list[ProviderDataQualityFlag]],
) -> list[PrioritizedFinding]:
    """Copy run-level provider quality flags onto affected findings."""
    if not flags_by_source:
        return findings
    all_flags = [flag for flags in flags_by_source.values() for flag in flags]
    enriched: list[PrioritizedFinding] = []
    for finding in findings:
        finding_flags = _finding_data_quality_flags(cve_id=finding.cve_id, flags=all_flags)
        enriched.append(
            finding.model_copy(
                update={
                    "data_quality_flags": finding_flags,
                    "data_quality_confidence": _finding_data_quality_confidence(finding_flags),
                }
            )
        )
    return enriched


def _finding_data_quality_flags(
    *,
    cve_id: str,
    flags: list[ProviderDataQualityFlag],
) -> list[ProviderDataQualityFlag]:
    """Return the provider quality flags that materially affect one finding."""
    scoped_sources = {
        flag.source
        for flag in flags
        if flag.cve_id is not None
        and flag.code in {"nvd_missing", "nvd_cvss_missing", "epss_missing"}
    }
    return [
        flag
        for flag in flags
        if flag.cve_id == cve_id
        or (
            flag.cve_id is None
            and flag.code != "provider_missing_data"
            and not (
                flag.code == "provider_error"
                and flag.source in scoped_sources
                and not any(
                    scoped_flag.source == flag.source and scoped_flag.cve_id == cve_id
                    for scoped_flag in flags
                )
            )
        )
    ]


def _finding_data_quality_confidence(flags: list[ProviderDataQualityFlag]) -> str:
    """Summarize finding confidence from material provider quality flags."""
    material_flags = [flag for flag in flags if flag.code != "snapshot_locked"]
    if any(flag.severity == "error" for flag in material_flags):
        return "low"
    if material_flags:
        return "medium"
    return "high"
