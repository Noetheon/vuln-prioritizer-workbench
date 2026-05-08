"""Shared SARIF contract helpers for CLI and Workbench reports."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Any

SARIF_FINGERPRINT_KEY = "vuln-prioritizer/v1"
SARIF_WORKBENCH_FINGERPRINT_KEY = "vuln-prioritizer-workbench/v1"


def sarif_rule_id(cve_id: str) -> str:
    """Return the stable CVE-addressable SARIF rule id."""
    return f"vuln-prioritizer/{cve_id.lower()}"


def sarif_priority_label(value: str) -> str:
    """Normalize priority strings from API enums, CLI models, and JSON payloads."""
    normalized = value.split(".", maxsplit=1)[-1].strip().lower()
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }.get(normalized, "Low")


def sarif_level(priority: str) -> str:
    """Return the SARIF result level for a normalized priority."""
    return {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
    }[sarif_priority_label(priority)]


def sarif_security_severity(*, priority: str, cvss_base_score: float | int | None) -> str:
    """Return the SARIF security-severity string used by all report surfaces."""
    if cvss_base_score is not None:
        return f"{min(max(float(cvss_base_score), 0.0), 10.0):.1f}"
    return {
        "Critical": "9.0",
        "High": "7.0",
        "Medium": "5.0",
        "Low": "3.0",
    }[sarif_priority_label(priority)]


def sarif_fingerprint(
    *,
    cve_id: str,
    artifact_uri: str | None,
    components: Iterable[object],
    asset_ids: Iterable[object],
) -> str:
    """Return the stable SARIF partial fingerprint identity.

    The identity intentionally excludes score, priority, and governance state so
    GitHub Code Scanning can track the same supplied vulnerability occurrence
    across enrichment changes.
    """
    component_identity = sarif_component_identities(components=components)
    asset_identity = sarif_asset_identities(asset_ids=asset_ids)
    identity = "|".join(
        [
            cve_id,
            artifact_uri or "",
            _stable_join(component_identity),
            _stable_join(asset_identity),
        ]
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def sarif_partial_fingerprints(
    *,
    cve_id: str,
    artifact_uri: str | None,
    components: Iterable[object],
    asset_ids: Iterable[object],
    include_workbench_alias: bool = False,
) -> dict[str, str]:
    """Return SARIF partialFingerprints with an optional Workbench alias."""
    fingerprint = sarif_fingerprint(
        cve_id=cve_id,
        artifact_uri=artifact_uri,
        components=components,
        asset_ids=asset_ids,
    )
    fingerprints = {SARIF_FINGERPRINT_KEY: fingerprint}
    if include_workbench_alias:
        fingerprints[SARIF_WORKBENCH_FINGERPRINT_KEY] = fingerprint
    return fingerprints


def sarif_result_location(
    *,
    artifact_uri: str,
    uri_base_id: str | None = None,
    logical_location: str | None = None,
    logical_kind: str = "component",
) -> dict[str, Any]:
    """Return the canonical SARIF location block for CLI and Workbench reports."""
    artifact_location: dict[str, Any] = {"uri": artifact_uri}
    if uri_base_id is not None:
        artifact_location["uriBaseId"] = uri_base_id
    location: dict[str, Any] = {
        "physicalLocation": {"artifactLocation": artifact_location},
    }
    if logical_location:
        location["logicalLocations"] = [
            {
                "fullyQualifiedName": logical_location,
                "kind": logical_kind,
            }
        ]
    return location


def sarif_rule_properties(
    *,
    cve_id: str,
    priority: str,
    cvss_base_score: float | int | None,
    references: list[str],
    priority_property: str | None = None,
) -> dict[str, Any]:
    """Return common SARIF rule properties shared by all report renderers."""
    rendered_priority = priority_property or priority
    return {
        "cve": cve_id,
        "priority": rendered_priority,
        "precision": "very-high",
        "security-severity": sarif_security_severity(
            priority=priority,
            cvss_base_score=cvss_base_score,
        ),
        "tags": ["security", "external/cve", f"priority/{rendered_priority.lower()}"],
        "references": references,
    }


def sarif_component_identities(
    *,
    components: Iterable[object] = (),
    component_purls: Iterable[object] = (),
) -> list[str]:
    """Return canonical component identity material, preferring PURLs."""
    purls = _stable_values(component_purls)
    return purls or _stable_values(components)


def sarif_asset_identities(*, asset_ids: Iterable[object] = ()) -> list[str]:
    """Return canonical asset identity material."""
    return _stable_values(asset_ids)


def sarif_target_identity(target_kind: object | None, target_ref: object | None) -> str | None:
    """Return canonical target identity material for location/fingerprint fallback."""
    ref = _stable_value(target_ref)
    if not ref:
        return None
    kind = _stable_value(target_kind)
    if kind and not ref.startswith(f"{kind}:"):
        return f"{kind}:{ref}"
    return ref


def sarif_artifact_uri(
    *,
    affected_paths: Iterable[object] = (),
    target_refs: Iterable[object] = (),
    fallback: object | None = None,
) -> str:
    """Return the canonical artifact URI used by SARIF locations and fingerprints."""
    for values in (affected_paths, target_refs, (fallback,)):
        candidates = _stable_values(values)
        if candidates:
            return candidates[0]
    return "workbench-input"


def _stable_join(values: Iterable[object]) -> str:
    return ",".join(_stable_values(values))


def _stable_values(values: Iterable[object]) -> list[str]:
    return sorted({value for item in values if (value := _stable_value(item))})


def _stable_value(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
