"""Provider for local CTID Mappings Explorer JSON artifacts."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Final

from app.domain.engine.attack_sources import ATTACK_SOURCE_CTID_MAPPINGS_EXPLORER
from app.domain.engine.models import AttackConfidence, AttackMapping, AttackReviewStatus
from app.domain.engine.utils import normalize_cve_id

CTID_MAPPING_CONFIDENCE: Final[AttackConfidence] = "high"
CTID_MAPPING_REVIEW_STATUS: Final[AttackReviewStatus] = "reviewed"
CTID_MAPPING_DEFENSIVE_NOTE: Final = (
    "Source-backed CTID Mappings Explorer mapping; use as defensive ATT&CK context only."
)


class CtidMappingsProvider:
    """Load CTID Mappings Explorer JSON artifacts from local files."""

    def load(
        self,
        offline_file: Path,
    ) -> tuple[dict[str, list[AttackMapping]], dict[str, str | None], list[str]]:
        """Load method for CtidMappingsProvider."""
        if not offline_file.exists() or not offline_file.is_file():
            raise FileNotFoundError(f"ATT&CK mapping file not found: {offline_file}")
        if offline_file.suffix.lower() != ".json":
            raise ValueError("CTID ATT&CK mapping file must be a JSON file.")

        raw_content = offline_file.read_bytes()
        try:
            payload = json.loads(raw_content.decode("utf-8"))
        except json.JSONDecodeError as exc:
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
                    source=ATTACK_SOURCE_CTID_MAPPINGS_EXPLORER,
                    confidence=CTID_MAPPING_CONFIDENCE,
                    review_status=CTID_MAPPING_REVIEW_STATUS,
                    defensive_note=CTID_MAPPING_DEFENSIVE_NOTE,
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
            "mapping_file_sha256": hashlib.sha256(raw_content).hexdigest(),
            "mapping_file": str(offline_file),
            "creation_date": _normalize_optional_string(metadata.get("creation_date")),
            "last_update": _normalize_optional_string(metadata.get("last_update")),
            "organization": _normalize_optional_string(metadata.get("organization")),
            "author": _normalize_optional_string(metadata.get("author")),
            "contact": _normalize_optional_string(metadata.get("contact")),
        }
        return grouped, normalized_metadata, warnings

    def build_quality_report(
        self,
        mappings_by_cve: dict[str, list[AttackMapping]],
        metadata: dict[str, str | None],
        *,
        comparison_mappings_by_cve: dict[str, list[AttackMapping]] | None = None,
        comparison_source: str | None = None,
        comparison_file: str | None = None,
        comparison_file_sha256: str | None = None,
    ) -> dict[str, object]:
        """Build a deterministic CTID mapping quality/provenance summary."""
        mappings = [mapping for items in mappings_by_cve.values() for mapping in items]
        conflict_rows = _find_ctid_mapping_conflicts(mappings_by_cve)
        local_ctid_conflicts = _find_local_ctid_conflicts(
            mappings_by_cve,
            comparison_mappings_by_cve or {},
        )
        confidence_counts = Counter(mapping.confidence or "unknown" for mapping in mappings)
        review_status_counts = Counter(
            mapping.review_status or "unreviewed" for mapping in mappings
        )

        return {
            "schema_version": "1.0.0",
            "source": ATTACK_SOURCE_CTID_MAPPINGS_EXPLORER,
            "mapping_file": metadata.get("mapping_file"),
            "mapping_file_sha256": metadata.get("mapping_file_sha256"),
            "mapping_framework": metadata.get("mapping_framework"),
            "mapping_framework_version": metadata.get("mapping_framework_version"),
            "mapping_created_at": metadata.get("creation_date"),
            "mapping_updated_at": metadata.get("last_update"),
            "mapping_count": len(mappings),
            "unique_cves": len(mappings_by_cve),
            "unique_techniques": len({mapping.attack_object_id for mapping in mappings}),
            "source_counts": dict(
                sorted(Counter(mapping.source or "unknown" for mapping in mappings).items())
            ),
            "confidence_counts": dict(sorted(confidence_counts.items())),
            "review_status_counts": dict(sorted(review_status_counts.items())),
            "mapping_type_counts": dict(
                sorted(Counter(mapping.mapping_type or "unknown" for mapping in mappings).items())
            ),
            "low_confidence_count": confidence_counts.get("low", 0),
            "conflict_count": len(conflict_rows),
            "conflicts": conflict_rows,
            "conflict_policy": (
                "ctid-json and local-curated sources are explicit alternatives; mappings are "
                "not silently merged. Divergent duplicate CTID contexts are surfaced here."
            ),
            "comparison_source": comparison_source,
            "comparison_file": comparison_file,
            "comparison_file_sha256": comparison_file_sha256,
            "local_ctid_conflict_count": len(local_ctid_conflicts),
            "local_ctid_conflicts": local_ctid_conflicts,
            "safety_review": {
                "source_backed_ctid_context": True,
                "heuristic_or_llm_sources_rejected": True,
                "unmapped_cves_remain_unmapped": True,
            },
        }


def _find_ctid_mapping_conflicts(
    mappings_by_cve: dict[str, list[AttackMapping]],
) -> list[dict[str, object]]:
    """Find ctid mapping conflicts function."""
    conflicts: list[dict[str, object]] = []
    for cve_id, mappings in sorted(mappings_by_cve.items()):
        contexts_by_technique: dict[str, set[tuple[str, str]]] = {}
        for mapping in mappings:
            contexts_by_technique.setdefault(mapping.attack_object_id, set()).add(
                (
                    mapping.mapping_type or "unknown",
                    mapping.capability_group or "unknown",
                )
            )

        for technique_id, contexts in sorted(contexts_by_technique.items()):
            if len(contexts) <= 1:
                continue
            conflicts.append(
                {
                    "cve_id": cve_id,
                    "technique_id": technique_id,
                    "contexts": [
                        {
                            "mapping_type": mapping_type,
                            "capability_group": capability_group,
                        }
                        for mapping_type, capability_group in sorted(contexts)
                    ],
                }
            )
    return conflicts


def _find_local_ctid_conflicts(
    ctid_mappings_by_cve: dict[str, list[AttackMapping]],
    local_mappings_by_cve: dict[str, list[AttackMapping]],
) -> list[dict[str, object]]:
    """Find local ctid conflicts function."""
    conflicts: list[dict[str, object]] = []
    for cve_id in sorted(set(ctid_mappings_by_cve).intersection(local_mappings_by_cve)):
        ctid_mappings = ctid_mappings_by_cve[cve_id]
        local_mappings = local_mappings_by_cve[cve_id]
        ctid_techniques = {mapping.attack_object_id for mapping in ctid_mappings}
        local_techniques = {mapping.attack_object_id for mapping in local_mappings}
        shared_techniques = ctid_techniques.intersection(local_techniques)
        ctid_types = _mapping_type_set(ctid_mappings)
        local_types = _mapping_type_set(local_mappings)

        if ctid_techniques == local_techniques and ctid_types == local_types:
            continue

        conflicts.append(
            {
                "cve_id": cve_id,
                "shared_techniques": sorted(shared_techniques),
                "ctid_only_techniques": sorted(ctid_techniques - local_techniques),
                "local_only_techniques": sorted(local_techniques - ctid_techniques),
                "ctid_mapping_types": sorted(ctid_types),
                "local_mapping_types": sorted(local_types),
            }
        )
    return conflicts


def _mapping_type_set(mappings: list[AttackMapping]) -> set[str]:
    """Mapping type set function."""
    return {mapping.mapping_type or "unknown" for mapping in mappings}


def _normalize_optional_string(value: object) -> str | None:
    """Normalize optional string function."""
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _normalize_references(value: object) -> list[str]:
    """Normalize references function."""
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
