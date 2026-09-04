"""Evidence-bound component fields shared by reads and SQL projections."""

from __future__ import annotations

from dataclasses import dataclass

from packageurl import PackageURL

from app.decision_core.contracts import FindingDecisionEvidenceV2


@dataclass(frozen=True, slots=True)
class ComponentDecisionProjection:
    """Queryable component coordinates derived only from typed decision evidence."""

    name: str | None
    version: str | None
    purl: str | None
    package_type: str | None
    ecosystem: str | None


def project_component_decision(
    evidence: FindingDecisionEvidenceV2,
) -> ComponentDecisionProjection:
    """Resolve component fields without consulting mutable relational aliases."""
    scope = evidence.occurrence_scope
    purl = _clean_text(scope.purl) or _single_occurrence_text(evidence, "purl")
    parsed_purl = _parse_purl(purl)
    package_type = (
        _clean_text(scope.package_type)
        or _single_occurrence_text(evidence, "package_type")
        or _purl_text(parsed_purl, "type")
    )
    return ComponentDecisionProjection(
        name=(
            _clean_text(scope.component_name)
            or _single_occurrence_text(evidence, "component_name")
            or _purl_text(parsed_purl, "name")
        ),
        version=(
            _clean_text(scope.component_version)
            or _single_occurrence_text(evidence, "component_version")
            or _purl_text(parsed_purl, "version")
        ),
        purl=purl,
        package_type=package_type,
        # The v2 evidence contract has one typed package ecosystem coordinate.
        # Persist it under both query names used by the legacy component model.
        ecosystem=package_type,
    )


def _clean_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None


def _single_occurrence_text(
    evidence: FindingDecisionEvidenceV2,
    field_name: str,
) -> str | None:
    values = {
        value
        for occurrence in evidence.occurrences
        if (value := _clean_text(getattr(occurrence, field_name, None))) is not None
    }
    return next(iter(values)) if len(values) == 1 else None


def _parse_purl(purl: str | None) -> PackageURL | None:
    if purl is None:
        return None
    try:
        return PackageURL.from_string(purl)
    except ValueError:
        return None


def _purl_text(parsed: PackageURL | None, field_name: str) -> str | None:
    return _clean_text(getattr(parsed, field_name, None))


__all__ = ["ComponentDecisionProjection", "project_component_decision"]
