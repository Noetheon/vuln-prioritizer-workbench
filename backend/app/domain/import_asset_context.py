"""Asset-context mapping for the Workbench import boundary."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from app.importers.contracts import NormalizedOccurrence
from app.models import AssetCriticality, AssetEnvironment, AssetExposure
from vuln_prioritizer.inputs.parsers.common import (
    normalize_asset_criticality as _core_normalize_asset_criticality,
)
from vuln_prioritizer.inputs.parsers.common import (
    normalize_asset_environment as _core_normalize_asset_environment,
)
from vuln_prioritizer.inputs.parsers.common import (
    normalize_asset_exposure as _core_normalize_asset_exposure,
)
from vuln_prioritizer.models import InputOccurrence

_UNKNOWN = "unknown"


def canonicalize_occurrence_asset_context(
    occurrence: NormalizedOccurrence,
) -> NormalizedOccurrence:
    """Return an occurrence whose asset context evidence uses core canonical values."""
    evidence = dict(occurrence.raw_evidence)
    _canonicalize_evidence_key(
        evidence,
        "asset_criticality",
        canonicalize_asset_criticality_value,
    )
    _canonicalize_evidence_key(
        evidence,
        "asset_exposure",
        canonicalize_asset_exposure_value,
    )
    _canonicalize_evidence_key(
        evidence,
        "asset_environment",
        canonicalize_asset_environment_value,
    )
    return NormalizedOccurrence(
        cve=occurrence.cve,
        component=occurrence.component,
        version=occurrence.version,
        asset_ref=occurrence.asset_ref,
        source=occurrence.source,
        fix_version=occurrence.fix_version,
        raw_evidence=evidence,
    )


def input_occurrence_from_template_occurrence(
    occurrence: NormalizedOccurrence,
) -> InputOccurrence:
    """Map a Workbench importer occurrence back to the core occurrence model."""
    evidence = occurrence.raw_evidence
    fix_versions = [occurrence.fix_version] if occurrence.fix_version else []
    return InputOccurrence(
        cve_id=occurrence.cve,
        source_format=occurrence.source,
        source_id=string_evidence(evidence, "source_id"),
        source_record_id=string_evidence(evidence, "source_record_id"),
        component_name=occurrence.component,
        component_version=occurrence.version,
        purl=string_evidence(evidence, "purl"),
        package_type=string_evidence(evidence, "package_type"),
        file_path=string_evidence(evidence, "file_path"),
        dependency_path=string_evidence(evidence, "dependency_path"),
        fix_versions=fix_versions,
        raw_severity=string_evidence(evidence, "raw_severity")
        or string_evidence(evidence, "severity"),
        target_kind=string_evidence(evidence, "target_kind") or "generic",
        target_ref=string_evidence(evidence, "target_ref") or occurrence.asset_ref,
        asset_id=string_evidence(evidence, "asset_id"),
        asset_criticality=string_evidence(evidence, "asset_criticality"),
        asset_exposure=string_evidence(evidence, "asset_exposure")
        or string_evidence(evidence, "exposure"),
        asset_environment=string_evidence(evidence, "asset_environment"),
        asset_owner=string_evidence(evidence, "asset_owner") or string_evidence(evidence, "owner"),
        asset_business_service=string_evidence(evidence, "asset_business_service")
        or string_evidence(evidence, "business_service"),
    )


def template_occurrence_with_asset_context(
    occurrence: NormalizedOccurrence,
    enriched: InputOccurrence,
) -> NormalizedOccurrence:
    """Return a Workbench occurrence enriched with canonical core asset context."""
    evidence = dict(occurrence.raw_evidence)
    updates: dict[str, Any] = {
        "target_kind": enriched.target_kind,
        "target_ref": enriched.target_ref,
        "asset_id": enriched.asset_id,
        "asset_criticality": canonicalize_asset_criticality_value(enriched.asset_criticality),
        "asset_exposure": canonicalize_asset_exposure_value(enriched.asset_exposure),
        "asset_environment": canonicalize_asset_environment_value(enriched.asset_environment),
        "asset_owner": enriched.asset_owner,
        "asset_business_service": enriched.asset_business_service,
        "owner": enriched.asset_owner,
        "business_service": enriched.asset_business_service,
        "asset_match_rule_id": enriched.asset_match_rule_id,
        "asset_match_row": enriched.asset_match_row,
        "asset_match_mode": enriched.asset_match_mode,
        "asset_match_pattern": enriched.asset_match_pattern,
        "asset_match_precedence": enriched.asset_match_precedence,
        "asset_match_candidate_count": enriched.asset_match_candidate_count,
    }
    evidence.update({key: value for key, value in updates.items() if value not in {None, ""}})
    return NormalizedOccurrence(
        cve=occurrence.cve,
        component=occurrence.component,
        version=occurrence.version,
        asset_ref=enriched.asset_id or occurrence.asset_ref or enriched.target_ref,
        source=occurrence.source,
        fix_version=occurrence.fix_version,
        raw_evidence=evidence,
    )


def template_occurrence_with_vex(
    occurrence: NormalizedOccurrence,
    enriched: InputOccurrence,
) -> NormalizedOccurrence:
    """Return a Workbench occurrence enriched with core VEX match data."""
    evidence = dict(occurrence.raw_evidence)
    updates: dict[str, Any] = {
        "vex_status": enriched.vex_status,
        "vex_justification": enriched.vex_justification,
        "vex_action_statement": enriched.vex_action_statement,
        "vex_match_type": enriched.vex_match_type,
        "vex_source_format": enriched.vex_source_format,
        "vex_source_record_id": enriched.vex_source_record_id,
        "vex_source_path": Path(enriched.vex_source_path).name
        if enriched.vex_source_path
        else None,
        "vex_candidate_count": enriched.vex_candidate_count,
    }
    evidence.update({key: value for key, value in updates.items() if value not in {None, ""}})
    return NormalizedOccurrence(
        cve=occurrence.cve,
        component=occurrence.component,
        version=occurrence.version,
        asset_ref=occurrence.asset_ref,
        source=occurrence.source,
        fix_version=occurrence.fix_version,
        raw_evidence=evidence,
    )


def asset_exposure_from_evidence(evidence: Mapping[str, Any]) -> AssetExposure:
    canonical = canonicalize_asset_exposure_value(string_evidence(evidence, "asset_exposure"))
    return {
        "internet-facing": AssetExposure.INTERNET_FACING,
        "internal": AssetExposure.INTERNAL,
        _UNKNOWN: AssetExposure.UNKNOWN,
    }.get(canonical or _UNKNOWN, AssetExposure.UNKNOWN)


def asset_environment_from_evidence(evidence: Mapping[str, Any]) -> AssetEnvironment:
    canonical = canonicalize_asset_environment_value(string_evidence(evidence, "asset_environment"))
    return {
        "prod": AssetEnvironment.PRODUCTION,
        "production": AssetEnvironment.PRODUCTION,
        "staging": AssetEnvironment.STAGING,
        "test": AssetEnvironment.TEST,
        "dev": AssetEnvironment.DEVELOPMENT,
        "development": AssetEnvironment.DEVELOPMENT,
        _UNKNOWN: AssetEnvironment.UNKNOWN,
    }.get(canonical or _UNKNOWN, AssetEnvironment.UNKNOWN)


def asset_criticality_from_evidence(evidence: Mapping[str, Any]) -> AssetCriticality:
    canonical = canonicalize_asset_criticality_value(string_evidence(evidence, "asset_criticality"))
    return {
        "critical": AssetCriticality.CRITICAL,
        "high": AssetCriticality.HIGH,
        "medium": AssetCriticality.MEDIUM,
        "low": AssetCriticality.LOW,
        _UNKNOWN: AssetCriticality.UNKNOWN,
    }.get(canonical or _UNKNOWN, AssetCriticality.UNKNOWN)


def canonicalize_asset_criticality_value(value: str | None) -> str | None:
    if _is_unknown(value):
        return _UNKNOWN
    return _core_normalize_asset_criticality(
        value,
        warnings=[],
        row_number=0,
    )


def canonicalize_asset_exposure_value(value: str | None) -> str | None:
    if _is_unknown(value):
        return _UNKNOWN
    return _core_normalize_asset_exposure(
        value,
        warnings=[],
        row_number=0,
    )


def canonicalize_asset_environment_value(value: str | None) -> str | None:
    if _is_unknown(value):
        return _UNKNOWN
    return _core_normalize_asset_environment(
        value,
        warnings=[],
        row_number=0,
    )


def string_evidence(evidence: Mapping[str, Any], key: str) -> str | None:
    value = evidence.get(key)
    return str(value) if value else None


def _canonicalize_evidence_key(
    evidence: dict[str, Any],
    key: str,
    canonicalizer: Callable[[str | None], str | None],
) -> None:
    canonical = canonicalizer(string_evidence(evidence, key))
    if canonical is not None:
        evidence[key] = canonical


def _is_unknown(value: str | None) -> bool:
    return value is not None and value.strip().lower().replace("_", "-") == _UNKNOWN
