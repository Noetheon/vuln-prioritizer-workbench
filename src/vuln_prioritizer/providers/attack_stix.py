"""Local MITRE ATT&CK STIX bundle parser for technique metadata."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from vuln_prioritizer.models import AttackTechnique


class AttackStixProvider:
    """Extract ATT&CK technique metadata from a pinned STIX bundle JSON file."""

    def load_payload(
        self,
        payload: dict[str, Any],
        *,
        source_path: Path,
        raw_content: bytes,
    ) -> tuple[dict[str, AttackTechnique], dict[str, str | None], list[str]]:
        if payload.get("type") != "bundle":
            raise ValueError("ATT&CK STIX metadata must be a STIX bundle.")
        objects = payload.get("objects")
        if not isinstance(objects, list):
            raise ValueError("ATT&CK STIX metadata bundle is missing an objects array.")

        warnings: list[str] = []
        techniques: dict[str, AttackTechnique] = {}
        domains: list[str] = []
        stix_spec_versions: list[str] = []

        for index, raw_object in enumerate(objects, start=1):
            if not isinstance(raw_object, dict):
                warnings.append(f"Ignored STIX object #{index} because it is not a JSON object.")
                continue
            if raw_object.get("type") != "attack-pattern":
                continue

            attack_id, url = _attack_external_reference(raw_object)
            name = _normalize_optional_string(raw_object.get("name"))
            if not attack_id or not name:
                warnings.append(
                    "Ignored ATT&CK STIX attack-pattern without ATT&CK external ID or name "
                    f"at index {index}."
                )
                continue

            object_domains = _normalize_string_list(raw_object.get("x_mitre_domains"))
            for domain in object_domains:
                if domain not in domains:
                    domains.append(domain)

            spec_version = _normalize_optional_string(raw_object.get("spec_version"))
            if spec_version and spec_version not in stix_spec_versions:
                stix_spec_versions.append(spec_version)

            if attack_id in techniques:
                warnings.append(f"ATT&CK STIX metadata overrides duplicate {attack_id}.")

            techniques[attack_id] = AttackTechnique(
                attack_object_id=attack_id,
                name=name,
                tactics=_kill_chain_tactics(raw_object),
                url=url,
                revoked=bool(raw_object.get("revoked", False)),
                deprecated=bool(raw_object.get("x_mitre_deprecated", False)),
            )

        attack_version = _normalize_optional_string(
            payload.get("x_mitre_attack_version")
            or payload.get("attack_version")
            or payload.get("x_attack_version")
        )
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
        return techniques, metadata, warnings


def _attack_external_reference(raw_object: dict[str, Any]) -> tuple[str | None, str | None]:
    references = raw_object.get("external_references")
    if not isinstance(references, list):
        return None, None
    for reference in references:
        if not isinstance(reference, dict):
            continue
        source_name = str(reference.get("source_name") or "").strip().lower()
        external_id = _normalize_optional_string(reference.get("external_id"))
        if source_name == "mitre-attack" and external_id and external_id.startswith("T"):
            return external_id, _normalize_optional_string(reference.get("url"))
    return None, None


def _kill_chain_tactics(raw_object: dict[str, Any]) -> list[str]:
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
    normalized = value.strip().lower()
    return normalized.removesuffix("-attack") if normalized.endswith("-attack") else normalized


def _normalize_optional_string(value: object) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _normalize_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    normalized: list[str] = []
    for item in value:
        entry = _normalize_optional_string(item)
        if entry and entry not in normalized:
            normalized.append(entry)
    return normalized
