"""Deterministic remediation derivation from occurrence-level evidence."""

from __future__ import annotations

import re
from collections.abc import Iterable

from vuln_prioritizer.config import PRIORITY_RECOMMENDATIONS
from vuln_prioritizer.models import (
    FindingProvenance,
    InputOccurrence,
    RemediationComponent,
    RemediationPlan,
)

DEFAULT_REMEDIATION_FALLBACK = "Review remediation options."

_PURL_ECOSYSTEMS = {
    "apk": "apk",
    "cargo": "cargo",
    "composer": "composer",
    "deb": "deb",
    "gem": "rubygems",
    "generic": None,
    "golang": "go",
    "hex": "hex",
    "maven": "maven",
    "npm": "npm",
    "nuget": "nuget",
    "oci": "oci",
    "pypi": "pypi",
    "rpm": "rpm",
}

_PACKAGE_TYPE_ECOSYSTEMS = {
    "apk": "apk",
    "cargo": "cargo",
    "composer": "composer",
    "deb": "deb",
    "gem": "rubygems",
    "go": "go",
    "golang": "go",
    "jar": "maven",
    "maven": "maven",
    "nodejs": "npm",
    "npm": "npm",
    "nuget": "nuget",
    "pip": "pypi",
    "python": "pypi",
    "rpm": "rpm",
    "rubygems": "rubygems",
}


class RemediationService:
    """Derive stable remediation hints from normalized occurrence evidence."""

    def derive(self, evidence: FindingProvenance | Iterable[InputOccurrence]) -> RemediationPlan:
        occurrences = _coerce_occurrences(evidence)
        components = _collect_components(occurrences)
        if not components:
            return RemediationPlan()

        actionable_components = [component for component in components if component.fixed_versions]
        if actionable_components:
            return RemediationPlan(
                strategy="upgrade",
                ecosystem=_resolve_single_ecosystem(actionable_components),
                components=actionable_components,
            )

        return RemediationPlan(
            strategy="review-upgrade-options",
            ecosystem=_resolve_single_ecosystem(components),
            components=components,
        )

    def build_action(
        self,
        evidence: FindingProvenance | Iterable[InputOccurrence],
        *,
        priority_label: str,
    ) -> tuple[RemediationPlan, str]:
        remediation = self.derive(evidence)
        return remediation, render_recommended_action(remediation, priority_label=priority_label)


def derive_remediation(
    evidence: FindingProvenance | Iterable[InputOccurrence],
) -> RemediationPlan:
    """Convenience wrapper around :class:`RemediationService`."""
    return RemediationService().derive(evidence)


def render_recommended_action(remediation: RemediationPlan, *, priority_label: str) -> str:
    """Render a human-readable remediation action from the structured plan."""
    generic_guidance = PRIORITY_RECOMMENDATIONS[priority_label]

    if remediation.strategy == "upgrade" and remediation.components:
        return _render_upgrade_action(remediation, generic_guidance)

    if remediation.strategy == "review-upgrade-options" and remediation.components:
        return _render_review_action(remediation, generic_guidance)

    return generic_guidance


def _coerce_occurrences(
    evidence: FindingProvenance | Iterable[InputOccurrence],
) -> list[InputOccurrence]:
    if isinstance(evidence, FindingProvenance):
        return list(evidence.occurrences)
    return list(evidence)


def _collect_components(occurrences: list[InputOccurrence]) -> list[RemediationComponent]:
    ComponentKey = tuple[str | None, str | None, str | None, str | None, str | None]
    buckets: dict[ComponentKey, RemediationComponent] = {}
    fixed_version_sets: dict[ComponentKey, set[str]] = {}

    for occurrence in occurrences:
        component = _build_component_seed(occurrence)
        if component is None:
            continue

        key: ComponentKey = (
            component.name,
            component.current_version,
            component.package_type,
            component.purl,
            component.path,
        )
        if key not in buckets:
            buckets[key] = component
            fixed_version_sets[key] = set(component.fixed_versions)
            continue
        fixed_version_sets[key].update(component.fixed_versions)

    components: list[RemediationComponent] = []
    for key, component in buckets.items():
        fixed_versions = fixed_version_sets[key]
        components.append(
            component.model_copy(
                update={
                    "fixed_versions": sorted(fixed_versions, key=_natural_sort_key),
                }
            )
        )

    components.sort(key=_component_sort_key)
    return components


def _build_component_seed(occurrence: InputOccurrence) -> RemediationComponent | None:
    path = _clean_text(occurrence.dependency_path) or _clean_text(occurrence.file_path)
    purl = _clean_text(occurrence.purl)
    name = _clean_text(occurrence.component_name) or _name_from_purl(purl)
    current_version = _clean_text(occurrence.component_version)
    package_type = _clean_text(occurrence.package_type)
    fixed_versions = [
        cleaned_version
        for cleaned_version in (_clean_text(item) for item in occurrence.fix_versions)
        if cleaned_version
    ]

    if not any([name, current_version, package_type, purl, path, fixed_versions]):
        return None

    return RemediationComponent(
        name=name,
        current_version=current_version,
        fixed_versions=sorted(set(fixed_versions), key=_natural_sort_key),
        package_type=package_type,
        purl=purl,
        path=path,
    )


def _resolve_single_ecosystem(components: list[RemediationComponent]) -> str | None:
    ecosystems = {
        ecosystem
        for ecosystem in (_resolve_ecosystem(component) for component in components)
        if ecosystem
    }
    if len(ecosystems) == 1:
        return next(iter(ecosystems))
    return None


def _resolve_ecosystem(component: RemediationComponent) -> str | None:
    if component.purl:
        purl_type = _purl_type(component.purl)
        if purl_type:
            return _PURL_ECOSYSTEMS.get(purl_type, purl_type)
    if component.package_type:
        return _PACKAGE_TYPE_ECOSYSTEMS.get(component.package_type.casefold())
    return None


def _purl_type(purl: str) -> str | None:
    if not purl.startswith("pkg:"):
        return None
    remainder = purl[4:]
    if "/" not in remainder:
        return remainder.casefold() or None
    return remainder.split("/", 1)[0].casefold() or None


def _name_from_purl(purl: str | None) -> str | None:
    if not purl:
        return None
    if "/" not in purl:
        return None
    tail = purl.rsplit("/", 1)[-1]
    return _clean_text(tail.split("@", 1)[0])


def _component_sort_key(component: RemediationComponent) -> tuple[object, ...]:
    return (
        0 if component.fixed_versions else 1,
        _natural_sort_key(component.name or component.purl or component.package_type or ""),
        _natural_sort_key(component.current_version or ""),
        _natural_sort_key(component.path or ""),
    )


def _render_upgrade_action(remediation: RemediationPlan, generic_guidance: str) -> str:
    component_snippets = [
        _format_component_upgrade(component) for component in remediation.components[:2]
    ]
    if len(remediation.components) > 2:
        component_snippets.append(f"and {len(remediation.components) - 2} more component(s)")

    intro = "Upgrade affected components with known fixes"
    if remediation.ecosystem:
        intro += f" in {remediation.ecosystem}"
    intro += ": " + "; ".join(component_snippets) + "."
    return intro + " " + generic_guidance


def _render_review_action(remediation: RemediationPlan, generic_guidance: str) -> str:
    component_snippets = [
        _format_component_target(component) for component in remediation.components[:2]
    ]
    if len(remediation.components) > 2:
        component_snippets.append(f"and {len(remediation.components) - 2} more component(s)")

    intro = "Review available upgrade options"
    if remediation.ecosystem:
        intro += f" in {remediation.ecosystem}"
    intro += " for " + ", ".join(component_snippets)
    intro += "; no fixed version was captured in the input."
    return intro + " " + generic_guidance


def _format_component_upgrade(component: RemediationComponent) -> str:
    target = _format_component_target(component)
    fix_versions = component.fixed_versions[:3]
    version_text = ", ".join(fix_versions)
    if len(component.fixed_versions) > 3:
        version_text += ", ..."
    return f"{target} -> {version_text}"


def _format_component_target(component: RemediationComponent) -> str:
    label = component.name or component.purl or component.package_type or "affected component"
    if component.current_version:
        label += f" {component.current_version}"
    if component.path:
        label += f" ({component.path})"
    return label


def _clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _natural_sort_key(value: str) -> tuple[object, ...]:
    parts: list[object] = []
    for chunk in re.findall(r"\d+|\D+", value.casefold()):
        if chunk.isdigit():
            parts.append(int(chunk))
        else:
            parts.append(chunk)
    return tuple(parts)
