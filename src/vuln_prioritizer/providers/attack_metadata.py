"""Provider for local ATT&CK technique metadata fixtures."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from vuln_prioritizer.models import AttackTechnique
from vuln_prioritizer.providers.attack_stix import AttackStixProvider


class AttackMetadataProvider:
    """Load local ATT&CK technique metadata JSON files."""

    def load(
        self,
        offline_file: Path,
    ) -> tuple[dict[str, AttackTechnique], dict[str, str | None], list[str]]:
        if not offline_file.exists() or not offline_file.is_file():
            raise FileNotFoundError(f"ATT&CK technique metadata file not found: {offline_file}")
        if offline_file.suffix.lower() != ".json":
            raise ValueError("ATT&CK technique metadata file must be a JSON file.")

        raw_content = offline_file.read_bytes()
        try:
            payload = json.loads(raw_content.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"ATT&CK technique metadata JSON is not valid JSON: {exc.msg}."
            ) from exc
        if isinstance(payload, dict) and payload.get("type") == "bundle":
            return AttackStixProvider().load_payload(
                payload,
                source_path=offline_file,
                raw_content=raw_content,
            )
        techniques = payload.get("techniques")
        if not isinstance(techniques, list):
            raise ValueError("ATT&CK technique metadata JSON is missing a techniques array.")

        warnings: list[str] = []
        by_id: dict[str, AttackTechnique] = {}

        for index, raw_object in enumerate(techniques, start=1):
            if not isinstance(raw_object, dict):
                warnings.append(
                    f"Ignored ATT&CK technique entry #{index} because it is not a JSON object."
                )
                continue

            attack_object_id = _normalize_optional_string(raw_object.get("attack_object_id"))
            name = _normalize_optional_string(raw_object.get("name"))
            if not attack_object_id or not name:
                warnings.append(
                    "Ignored ATT&CK technique entry without attack_object_id or name "
                    f"at index {index}."
                )
                continue

            if attack_object_id in by_id:
                warnings.append(
                    f"ATT&CK technique metadata overrides duplicate {attack_object_id}."
                )

            by_id[attack_object_id] = AttackTechnique(
                attack_object_id=attack_object_id,
                name=name,
                tactics=_normalize_string_list(raw_object.get("tactics")),
                url=_normalize_optional_string(raw_object.get("url")),
                revoked=bool(raw_object.get("revoked", False)),
                deprecated=bool(raw_object.get("deprecated", False)),
            )

        normalized_metadata = {
            "attack_version": _normalize_optional_string(payload.get("attack_version")),
            "domain": _normalize_optional_string(payload.get("domain")),
            "metadata_source": "local-technique-metadata",
            "metadata_format": "vuln-prioritizer-technique-json",
            "metadata_file_sha256": hashlib.sha256(raw_content).hexdigest(),
            "metadata_file": str(offline_file),
            "stix_spec_version": None,
        }
        return by_id, normalized_metadata, warnings


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
        if item is None:
            continue
        entry = str(item).strip()
        if entry and entry not in normalized:
            normalized.append(entry)
    return normalized
