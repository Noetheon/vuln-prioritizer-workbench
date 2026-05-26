"""Local MITRE ATT&CK STIX bundle parser for technique metadata."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vuln_prioritizer.models import AttackTechnique


@dataclass(frozen=True)
class AttackStixTacticRecord:
    """Parsed ATT&CK tactic object from a STIX bundle."""

    tactic_id: str
    stix_id: str
    name: str
    short_name: str | None
    description: str | None
    url: str | None
    revoked: bool = False
    deprecated: bool = False


@dataclass(frozen=True)
class AttackStixTechniqueRecord:
    """Parsed ATT&CK technique or sub-technique object from a STIX bundle."""

    technique_id: str
    stix_id: str
    name: str
    tactic_ids: list[str] = field(default_factory=list)
    tactic_short_names: list[str] = field(default_factory=list)
    description: str | None = None
    url: str | None = None
    revoked: bool = False
    deprecated: bool = False
    is_subtechnique: bool = False


@dataclass(frozen=True)
class AttackStixMitigationRecord:
    """Parsed ATT&CK mitigation/course-of-action object from a STIX bundle."""

    mitigation_id: str
    stix_id: str
    name: str
    description: str | None
    url: str | None
    revoked: bool = False
    deprecated: bool = False


@dataclass(frozen=True)
class AttackStixMitigationRelationshipRecord:
    """Parsed relationship connecting one mitigation to one technique."""

    relationship_id: str
    mitigation_id: str
    technique_id: str
    description: str | None = None


@dataclass(frozen=True)
class AttackStixSnapshotBundle:
    """Versioned ATT&CK STIX catalog parsed from one bundle."""

    tactics: dict[str, AttackStixTacticRecord]
    techniques: dict[str, AttackStixTechniqueRecord]
    mitigations: dict[str, AttackStixMitigationRecord]
    mitigation_relationships: list[AttackStixMitigationRelationshipRecord]
    metadata: dict[str, str | None]
    object_counts: dict[str, int]
    warnings: list[str]


class AttackStixProvider:
    """Extract ATT&CK technique metadata from a pinned STIX bundle JSON file."""

    def load_payload(
        self,
        payload: dict[str, Any],
        *,
        source_path: Path,
        raw_content: bytes,
    ) -> tuple[dict[str, AttackTechnique], dict[str, str | None], list[str]]:
        """Load payload method for AttackStixProvider."""
        snapshot = self.load_snapshot_payload(
            payload,
            source_path=source_path,
            raw_content=raw_content,
        )
        techniques = {
            technique_id: AttackTechnique(
                attack_object_id=technique_id,
                name=technique.name,
                tactics=technique.tactic_short_names,
                url=technique.url,
                revoked=technique.revoked,
                deprecated=technique.deprecated,
            )
            for technique_id, technique in snapshot.techniques.items()
        }
        return techniques, snapshot.metadata, snapshot.warnings

    def load_snapshot_payload(
        self,
        payload: dict[str, Any],
        *,
        source_path: Path,
        raw_content: bytes,
    ) -> AttackStixSnapshotBundle:
        """Parse a STIX 2.1 bundle into a versioned ATT&CK catalog snapshot."""
        if payload.get("type") != "bundle":
            raise ValueError("ATT&CK STIX metadata must be a STIX bundle.")
        objects = payload.get("objects")
        if not isinstance(objects, list):
            raise ValueError("ATT&CK STIX metadata bundle is missing an objects array.")

        warnings: list[str] = []
        tactics: dict[str, AttackStixTacticRecord] = {}
        techniques: dict[str, AttackStixTechniqueRecord] = {}
        mitigations: dict[str, AttackStixMitigationRecord] = {}
        mitigation_relationships: list[AttackStixMitigationRelationshipRecord] = []
        attack_pattern_stix_to_id: dict[str, str] = {}
        mitigation_stix_to_id: dict[str, str] = {}
        tactic_short_name_to_id: dict[str, str] = {}
        domains: list[str] = []
        stix_spec_versions: list[str] = []
        attack_versions: list[str] = []
        object_counts: dict[str, int] = {}

        for index, raw_object in enumerate(objects, start=1):
            if not isinstance(raw_object, dict):
                warnings.append(f"Ignored STIX object #{index} because it is not a JSON object.")
                continue
            object_type = _normalize_optional_string(raw_object.get("type"))
            if object_type is None:
                warnings.append(f"Ignored STIX object #{index} because it has no type.")
                continue
            object_counts[object_type] = object_counts.get(object_type, 0) + 1

            _collect_domains_and_spec_versions(
                raw_object,
                domains=domains,
                stix_spec_versions=stix_spec_versions,
            )
            if object_type == "x-mitre-collection":
                _collect_collection_metadata(raw_object, attack_versions=attack_versions)

            if object_type != "x-mitre-tactic":
                continue

            tactic_id, url = _mitre_attack_external_reference(raw_object, prefixes=("TA",))
            name = _normalize_optional_string(raw_object.get("name"))
            if not tactic_id or not name:
                warnings.append(
                    "Ignored ATT&CK STIX tactic without ATT&CK external ID or name "
                    f"at index {index}."
                )
                continue

            if tactic_id in tactics:
                warnings.append(f"ATT&CK STIX snapshot overrides duplicate tactic {tactic_id}.")

            short_name = _normalize_optional_string(raw_object.get("x_mitre_shortname"))
            if short_name:
                tactic_short_name_to_id[short_name] = tactic_id

            tactics[tactic_id] = AttackStixTacticRecord(
                tactic_id=tactic_id,
                stix_id=str(raw_object.get("id") or ""),
                name=name,
                short_name=short_name,
                description=_normalize_optional_string(raw_object.get("description")),
                url=url,
                revoked=bool(raw_object.get("revoked", False)),
                deprecated=bool(raw_object.get("x_mitre_deprecated", False)),
            )

        for index, raw_object in enumerate(objects, start=1):
            if not isinstance(raw_object, dict):
                continue
            if raw_object.get("type") != "attack-pattern":
                continue

            attack_id, url = _mitre_attack_external_reference(raw_object, prefixes=("T",))
            name = _normalize_optional_string(raw_object.get("name"))
            if not attack_id or not name:
                warnings.append(
                    "Ignored ATT&CK STIX attack-pattern without ATT&CK external ID or name "
                    f"at index {index}."
                )
                continue

            if attack_id in techniques:
                warnings.append(f"ATT&CK STIX snapshot overrides duplicate {attack_id}.")

            tactic_short_names = _kill_chain_tactics(raw_object)
            tactic_ids = [
                tactic_short_name_to_id[tactic]
                for tactic in tactic_short_names
                if tactic in tactic_short_name_to_id
            ]
            attack_pattern_stix_to_id[str(raw_object.get("id") or "")] = attack_id
            techniques[attack_id] = AttackStixTechniqueRecord(
                technique_id=attack_id,
                stix_id=str(raw_object.get("id") or ""),
                name=name,
                tactic_ids=tactic_ids,
                tactic_short_names=tactic_short_names,
                description=_normalize_optional_string(raw_object.get("description")),
                url=url,
                revoked=bool(raw_object.get("revoked", False)),
                deprecated=bool(raw_object.get("x_mitre_deprecated", False)),
                is_subtechnique=bool(raw_object.get("x_mitre_is_subtechnique", False)),
            )

        for index, raw_object in enumerate(objects, start=1):
            if not isinstance(raw_object, dict):
                continue
            if raw_object.get("type") != "course-of-action":
                continue

            mitigation_id, url = _mitre_attack_external_reference(raw_object, prefixes=None)
            name = _normalize_optional_string(raw_object.get("name"))
            if not mitigation_id or not name:
                warnings.append(
                    "Ignored ATT&CK STIX mitigation without MITRE ATT&CK external ID or name "
                    f"at index {index}."
                )
                continue

            if mitigation_id in mitigations:
                warnings.append(
                    f"ATT&CK STIX snapshot overrides duplicate mitigation {mitigation_id}."
                )

            mitigation_stix_to_id[str(raw_object.get("id") or "")] = mitigation_id
            mitigations[mitigation_id] = AttackStixMitigationRecord(
                mitigation_id=mitigation_id,
                stix_id=str(raw_object.get("id") or ""),
                name=name,
                description=_normalize_optional_string(raw_object.get("description")),
                url=url,
                revoked=bool(raw_object.get("revoked", False)),
                deprecated=bool(raw_object.get("x_mitre_deprecated", False)),
            )

        for index, raw_object in enumerate(objects, start=1):
            if not isinstance(raw_object, dict):
                continue
            if raw_object.get("type") != "relationship":
                continue
            if raw_object.get("relationship_type") != "mitigates":
                continue

            mitigation_id = mitigation_stix_to_id.get(str(raw_object.get("source_ref") or ""))
            technique_id = attack_pattern_stix_to_id.get(str(raw_object.get("target_ref") or ""))
            if not mitigation_id or not technique_id:
                warnings.append(
                    "Ignored ATT&CK STIX mitigates relationship without known source mitigation "
                    f"or target technique at index {index}."
                )
                continue
            mitigation_relationships.append(
                AttackStixMitigationRelationshipRecord(
                    relationship_id=str(raw_object.get("id") or ""),
                    mitigation_id=mitigation_id,
                    technique_id=technique_id,
                    description=_normalize_optional_string(raw_object.get("description")),
                )
            )

        attack_version = _normalize_optional_string(
            payload.get("x_mitre_attack_version")
            or payload.get("attack_version")
            or payload.get("x_attack_version")
        ) or (attack_versions[0] if attack_versions else None)
        bundle_spec_version = _normalize_optional_string(payload.get("spec_version"))
        if bundle_spec_version and bundle_spec_version not in stix_spec_versions:
            stix_spec_versions.insert(0, bundle_spec_version)

        metadata = {
            "attack_version": attack_version,
            "domain": _normalize_domain(domains[0]) if domains else None,
            "metadata_source": "mitre-attack-stix",
            "metadata_format": "stix-bundle",
            "metadata_file_sha256": hashlib.sha256(raw_content).hexdigest(),
            "metadata_file": str(source_path),
            "stix_spec_version": stix_spec_versions[0] if stix_spec_versions else None,
        }
        return AttackStixSnapshotBundle(
            tactics=tactics,
            techniques=techniques,
            mitigations=mitigations,
            mitigation_relationships=mitigation_relationships,
            metadata=metadata,
            object_counts=object_counts,
            warnings=warnings,
        )


def _mitre_attack_external_reference(
    raw_object: dict[str, Any],
    *,
    prefixes: tuple[str, ...] | None,
) -> tuple[str | None, str | None]:
    """Mitre attack external reference function."""
    references = raw_object.get("external_references")
    if not isinstance(references, list):
        return None, None
    for reference in references:
        if not isinstance(reference, dict):
            continue
        source_name = str(reference.get("source_name") or "").strip().lower()
        external_id = _normalize_optional_string(reference.get("external_id"))
        if not external_id:
            continue
        prefix_matches = prefixes is None or any(
            external_id.startswith(prefix) for prefix in prefixes
        )
        if source_name == "mitre-attack" and prefix_matches:
            return external_id, _normalize_optional_string(reference.get("url"))
    return None, None


def _kill_chain_tactics(raw_object: dict[str, Any]) -> list[str]:
    """Kill chain tactics function."""
    phases = raw_object.get("kill_chain_phases")
    if not isinstance(phases, list):
        return []
    tactics: list[str] = []
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        kill_chain_name = str(phase.get("kill_chain_name") or "").strip().lower()
        tactic = _normalize_optional_string(phase.get("phase_name"))
        if kill_chain_name in {"mitre-attack", "mitre-enterprise-attack"} and tactic:
            if tactic not in tactics:
                tactics.append(tactic)
    return tactics


def _normalize_domain(value: str) -> str:
    """Normalize domain function."""
    normalized = value.strip().lower()
    return normalized.removesuffix("-attack") if normalized.endswith("-attack") else normalized


def _collect_domains_and_spec_versions(
    raw_object: dict[str, Any],
    *,
    domains: list[str],
    stix_spec_versions: list[str],
) -> None:
    """Collect domains and spec versions function."""
    object_domains = _normalize_string_list(raw_object.get("x_mitre_domains"))
    for domain in object_domains:
        if domain not in domains:
            domains.append(domain)

    spec_version = _normalize_optional_string(raw_object.get("spec_version"))
    if spec_version and spec_version not in stix_spec_versions:
        stix_spec_versions.append(spec_version)


def _collect_collection_metadata(
    raw_object: dict[str, Any],
    *,
    attack_versions: list[str],
) -> None:
    """Collect collection metadata function."""
    attack_version = _normalize_optional_string(
        raw_object.get("x_mitre_version")
        or raw_object.get("x_mitre_attack_version")
        or raw_object.get("attack_version")
    )
    if attack_version and attack_version not in attack_versions:
        attack_versions.append(attack_version)


def _normalize_optional_string(value: object) -> str | None:
    """Normalize optional string function."""
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _normalize_string_list(value: object) -> list[str]:
    """Normalize string list function."""
    if not isinstance(value, list):
        return []
    normalized: list[str] = []
    for item in value:
        entry = _normalize_optional_string(item)
        if entry and entry not in normalized:
            normalized.append(entry)
    return normalized
