"""Provider for local CTID Mappings Explorer JSON artifacts."""

from __future__ import annotations

import json
from json import JSONDecodeError
from pathlib import Path

from vuln_prioritizer.models import AttackMapping
from vuln_prioritizer.utils import normalize_cve_id


class CtidMappingsProvider:
    """Load CTID Mappings Explorer JSON artifacts from local files."""

    def load(
        self,
        offline_file: Path,
    ) -> tuple[dict[str, list[AttackMapping]], dict[str, str | None], list[str]]:
        if not offline_file.exists() or not offline_file.is_file():
            raise FileNotFoundError(f"ATT&CK mapping file not found: {offline_file}")
        if offline_file.suffix.lower() != ".json":
            raise ValueError("CTID ATT&CK mapping file must be a JSON file.")

        try:
            payload = json.loads(offline_file.read_text(encoding="utf-8"))
        except JSONDecodeError as exc:
            raise ValueError(f"CTID ATT&CK mapping JSON is not valid JSON: {exc.msg}.") from exc
        metadata = payload.get("metadata")
        if not isinstance(metadata, dict):
            raise ValueError("CTID ATT&CK mapping JSON is missing a metadata object.")

        mapping_objects = payload.get("mapping_objects")
        if not isinstance(mapping_objects, list):
            raise ValueError("CTID ATT&CK mapping JSON is missing a mapping_objects array.")

        valid_mapping_types = {
            str(name)
            for name in (metadata.get("mapping_types") or {}).keys()
            if isinstance(name, str) and name
        }
        warnings: list[str] = []
        grouped: dict[str, list[AttackMapping]] = {}
        seen_keys: set[tuple[str, str, str | None, str | None]] = set()

        for index, raw_object in enumerate(mapping_objects, start=1):
            if not isinstance(raw_object, dict):
                warnings.append(
                    f"Ignored CTID mapping object #{index} because it is not a JSON object."
                )
                continue

            capability_id = normalize_cve_id(raw_object.get("capability_id"))
            if capability_id is None:
                raw_capability = raw_object.get("capability_id")
                warnings.append(
                    "Ignored CTID mapping object with invalid capability_id "
                    f"at index {index}: {raw_capability!r}"
                )
                continue

            attack_object_id = str(raw_object.get("attack_object_id") or "").strip()
            if not attack_object_id:
                warnings.append(
                    f"Ignored CTID mapping object for {capability_id} without attack_object_id."
                )
                continue

            mapping_type = _normalize_optional_string(raw_object.get("mapping_type"))
            if mapping_type and valid_mapping_types and mapping_type not in valid_mapping_types:
                warnings.append(f"Unknown CTID mapping_type for {capability_id}: {mapping_type!r}.")

            dedupe_key = (
                capability_id,
                attack_object_id,
                mapping_type,
                _normalize_optional_string(raw_object.get("capability_group")),
            )
            if dedupe_key in seen_keys:
                warnings.append(
                    "Ignored duplicate CTID mapping for "
                    f"{capability_id} / {attack_object_id} / {mapping_type or 'unknown'}."
                )
                continue
            seen_keys.add(dedupe_key)

            grouped.setdefault(capability_id, []).append(
                AttackMapping(
                    capability_id=capability_id,
                    attack_object_id=attack_object_id,
                    attack_object_name=_normalize_optional_string(
                        raw_object.get("attack_object_name")
                    ),
                    mapping_type=mapping_type,
                    capability_group=_normalize_optional_string(raw_object.get("capability_group")),
                    capability_description=_normalize_optional_string(
                        raw_object.get("capability_description")
                    ),
                    comments=_normalize_optional_string(raw_object.get("comments")),
                    references=_normalize_references(raw_object.get("references")),
                )
            )

        normalized_metadata = {
            "mapping_framework": _normalize_optional_string(metadata.get("mapping_framework")),
            "mapping_framework_version": _normalize_optional_string(
                metadata.get("mapping_framework_version")
            ),
            "mapping_version": _normalize_optional_string(metadata.get("mapping_version")),
            "attack_version": _normalize_optional_string(metadata.get("attack_version")),
            "domain": _normalize_optional_string(metadata.get("technology_domain")),
        }
        return grouped, normalized_metadata, warnings


def _normalize_optional_string(value: object) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _normalize_references(value: object) -> list[str]:
    if not isinstance(value, list):
        return []

    normalized: list[str] = []
    for item in value:
        if item is None:
            continue
        reference = str(item).strip()
        if reference and reference not in normalized:
            normalized.append(reference)
    return normalized
