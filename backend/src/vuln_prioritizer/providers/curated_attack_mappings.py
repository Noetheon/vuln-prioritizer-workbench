"""Provider for reviewed local CVE-to-ATT&CK mapping artifacts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import yaml
from pydantic import ValidationError

from vuln_prioritizer.attack_sources import (
    ATTACK_SOURCE_LOCAL_CURATED,
    WORKBENCH_DISALLOWED_MAPPING_SOURCE_PREFIXES,
    WORKBENCH_DISALLOWED_MAPPING_SOURCES,
)
from vuln_prioritizer.models import (
    AttackConfidence,
    AttackMapping,
    AttackMappingType,
    AttackReviewStatus,
    AttackTechnique,
    CveAttackMapping,
)
from vuln_prioritizer.utils import normalize_cve_id

CONFIDENCE_BY_LABEL = {"low": 0.3, "medium": 0.6, "high": 0.9}
LOW_CONFIDENCE_THRESHOLD = 0.4
REVIEW_STATUSES_REQUIRING_REVIEWER = {"reviewed", "rejected", "stale"}
TACTIC_ID_TO_SHORT_NAME = {
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion",
    "TA0006": "credential-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0010": "exfiltration",
    "TA0011": "command-and-control",
    "TA0040": "impact",
    "TA0042": "resource-development",
    "TA0043": "reconnaissance",
}


class CuratedAttackMappingValidationError(ValueError):
    """Raised when a curated ATT&CK mapping artifact is structurally invalid."""


@dataclass(frozen=True)
class CuratedAttackMappingBundle:
    """Data representation and logic for Curated Attack Mapping Bundle."""

    mappings_by_cve: dict[str, list[AttackMapping]]
    techniques_by_id: dict[str, AttackTechnique]
    metadata: dict[str, str | None]
    warnings: list[str]
    quality_report: dict[str, Any]


class CuratedAttackMappingProvider:
    """Load reviewed YAML/JSON CVE-to-ATT&CK mappings from local files."""

    def load(self, mapping_file: Path) -> CuratedAttackMappingBundle:
        """Load method for CuratedAttackMappingProvider."""
        raw_content = _read_mapping_bytes(mapping_file)
        payload = _decode_payload(mapping_file, raw_content)
        metadata = _require_object(payload.get("metadata"), "metadata")
        mapping_objects = _require_array(payload.get("mapping_objects"), "mapping_objects")

        errors: list[str] = []
        warnings: list[str] = []
        _validate_metadata(metadata, errors)

        mappings_by_cve: dict[str, list[AttackMapping]] = {}
        techniques_by_id: dict[str, AttackTechnique] = {}
        parsed_mappings: list[CveAttackMapping] = []
        confidence_labels: list[str] = []
        seen_keys: set[tuple[str, str, str]] = set()

        for index, raw_object in enumerate(mapping_objects, start=1):
            location = f"mapping_objects[{index - 1}]"
            if not isinstance(raw_object, dict):
                errors.append(f"{location} must be an object.")
                continue

            parsed, confidence_label = _parse_mapping_object(raw_object, location, errors)
            if parsed is None or confidence_label is None:
                continue

            dedupe_key = (parsed.cve_id, parsed.technique_id, parsed.mapping_type)
            if dedupe_key in seen_keys:
                errors.append(
                    f"{location} duplicates {parsed.cve_id} / {parsed.technique_id} / "
                    f"{parsed.mapping_type}."
                )
                continue
            seen_keys.add(dedupe_key)
            parsed_mappings.append(parsed)
            confidence_labels.append(confidence_label)
            if confidence_label == "low" or parsed.confidence <= LOW_CONFIDENCE_THRESHOLD:
                warnings.append(
                    "Low-confidence curated ATT&CK mapping marked for review: "
                    f"{parsed.cve_id} / {parsed.technique_id}."
                )
            if parsed.review_status in {"unreviewed", "needs_review"}:
                warnings.append(
                    "Curated ATT&CK mapping is not fully reviewed: "
                    f"{parsed.cve_id} / {parsed.technique_id} has status "
                    f"{parsed.review_status}."
                )

            mappings_by_cve.setdefault(parsed.cve_id, []).append(
                AttackMapping(
                    capability_id=parsed.cve_id,
                    attack_object_id=parsed.technique_id,
                    attack_object_name=parsed.technique_name,
                    mapping_type=parsed.mapping_type,
                    capability_group=_optional_string(raw_object.get("capability_group"))
                    or parsed.mapping_type,
                    capability_description=parsed.rationale,
                    comments=_curated_mapping_comment(parsed, confidence_label),
                    source=ATTACK_SOURCE_LOCAL_CURATED,
                    confidence=cast(AttackConfidence, confidence_label),
                    review_status=parsed.review_status,
                    defensive_note=parsed.defensive_note,
                    reviewer=parsed.metadata.get("reviewer"),
                    reviewed_at=parsed.metadata.get("reviewed_at"),
                    references=parsed.references,
                )
            )
            techniques_by_id.setdefault(
                parsed.technique_id,
                AttackTechnique(
                    attack_object_id=parsed.technique_id,
                    name=parsed.technique_name or parsed.technique_id,
                    tactics=_tactic_short_names(parsed.tactic_ids),
                    url=None,
                    revoked=False,
                    deprecated=False,
                ),
            )

        if errors:
            message = "Curated ATT&CK mapping validation failed:\n- " + "\n- ".join(errors)
            raise CuratedAttackMappingValidationError(message)

        normalized_metadata = _normalize_metadata(metadata, mapping_file, raw_content)
        quality_report = _build_quality_report(
            metadata=normalized_metadata,
            mappings=parsed_mappings,
            confidence_labels=confidence_labels,
            warnings=warnings,
        )
        return CuratedAttackMappingBundle(
            mappings_by_cve=mappings_by_cve,
            techniques_by_id=techniques_by_id,
            metadata=normalized_metadata,
            warnings=warnings,
            quality_report=quality_report,
        )


def _read_mapping_bytes(mapping_file: Path) -> bytes:
    """Read mapping bytes function."""
    if not mapping_file.exists() or not mapping_file.is_file():
        raise FileNotFoundError(f"Curated ATT&CK mapping file not found: {mapping_file}")
    if mapping_file.suffix.lower() not in {".json", ".yaml", ".yml"}:
        raise ValueError("Curated ATT&CK mapping file must be JSON, YAML, or YML.")
    return mapping_file.read_bytes()


def _decode_payload(mapping_file: Path, raw_content: bytes) -> dict[str, Any]:
    """Decode payload function."""
    try:
        if mapping_file.suffix.lower() == ".json":
            payload = json.loads(raw_content.decode("utf-8"))
        else:
            payload = yaml.safe_load(raw_content.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Curated ATT&CK mapping JSON is not valid JSON: {exc.msg}.") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"Curated ATT&CK mapping YAML is not valid YAML: {exc}.") from exc

    if not isinstance(payload, dict):
        raise ValueError("Curated ATT&CK mapping file must contain a top-level object.")
    return payload


def _require_object(value: Any, field_name: str) -> dict[str, Any]:
    """Require object function."""
    if not isinstance(value, dict):
        raise ValueError(f"Curated ATT&CK mapping file is missing a {field_name} object.")
    return value


def _require_array(value: Any, field_name: str) -> list[Any]:
    """Require array function."""
    if not isinstance(value, list):
        raise ValueError(f"Curated ATT&CK mapping file is missing a {field_name} array.")
    if not value:
        raise ValueError(f"Curated ATT&CK mapping {field_name} array must not be empty.")
    return value


def _validate_metadata(metadata: dict[str, Any], errors: list[str]) -> None:
    """Validate metadata function."""
    for field_name in (
        "mapping_framework",
        "mapping_framework_version",
        "attack_version",
        "technology_domain",
        "mapping_types",
    ):
        value = metadata.get(field_name)
        if field_name == "mapping_types":
            if not isinstance(value, dict) or not value:
                errors.append("metadata.mapping_types must be a non-empty object.")
            continue
        if _optional_string(value) is None:
            errors.append(f"metadata.{field_name} is required.")


def _parse_mapping_object(
    raw_object: dict[str, Any],
    location: str,
    errors: list[str],
) -> tuple[CveAttackMapping | None, str | None]:
    """Parse mapping object function."""
    confidence, confidence_label = _normalize_confidence(raw_object.get("confidence"))
    cve_id = normalize_cve_id(_coalesce(raw_object, "cve_id", "capability_id"))
    technique_id = _optional_string(_coalesce(raw_object, "technique_id", "attack_object_id"))
    source = _optional_string(raw_object.get("source"))
    review_status = _optional_string(raw_object.get("review_status")) or "unreviewed"
    reviewer = _optional_string(raw_object.get("reviewer"))
    reviewed_at = _optional_string(raw_object.get("reviewed_at"))
    local_errors: list[str] = []

    if cve_id is None:
        local_errors.append(f"{location}.cve_id must be a valid CVE identifier.")
    if technique_id is None:
        local_errors.append(f"{location}.technique_id is required.")
    if confidence is None or confidence_label is None:
        local_errors.append(f"{location}.confidence must be one of low, medium, or high.")
    elif confidence_label == "high" and review_status != "reviewed":
        local_errors.append(f"{location}.confidence high requires review_status reviewed.")
    if source is None:
        local_errors.append(f"{location}.source is required.")
    elif _is_disallowed_source(source):
        local_errors.append(
            f"{location}.source must not be heuristic or LLM-generated mapping evidence."
        )
    if review_status in REVIEW_STATUSES_REQUIRING_REVIEWER and reviewer is None:
        local_errors.append(
            f"{location}.reviewer is required when review_status is {review_status}."
        )
    if review_status in REVIEW_STATUSES_REQUIRING_REVIEWER and reviewed_at is None:
        local_errors.append(
            f"{location}.reviewed_at is required when review_status is {review_status}."
        )

    if local_errors:
        errors.extend(local_errors)
        return None, None

    assert cve_id is not None
    assert technique_id is not None
    assert source is not None
    assert confidence is not None
    assert confidence_label is not None

    metadata = _string_metadata(
        {
            "confidence_label": confidence_label,
            "reviewer": reviewer,
            "reviewed_at": reviewed_at,
            "curated_source": ATTACK_SOURCE_LOCAL_CURATED,
        }
    )
    try:
        return (
            CveAttackMapping(
                cve_id=cve_id,
                technique_id=technique_id,
                technique_name=_optional_string(
                    _coalesce(raw_object, "technique_name", "attack_object_name")
                ),
                tactic_ids=_string_list(raw_object.get("tactic_ids")),
                mapping_type=cast(
                    AttackMappingType,
                    _optional_string(raw_object.get("mapping_type")) or "exploitation",
                ),
                source=source,
                source_url=_optional_string(raw_object.get("source_url")),
                confidence=confidence,
                rationale=_optional_string(raw_object.get("rationale")) or "",
                review_status=cast(AttackReviewStatus, review_status),
                defensive_note=_optional_string(raw_object.get("defensive_note")) or "",
                references=_string_list(raw_object.get("references")),
                metadata=metadata,
            ),
            confidence_label,
        )
    except ValidationError as exc:
        errors.extend(f"{location}.{error['loc'][0]}: {error['msg']}" for error in exc.errors())
    return None, None


def _normalize_confidence(value: Any) -> tuple[float | None, str | None]:
    """Normalize confidence function."""
    if isinstance(value, str):
        label = value.strip().lower()
        if label in CONFIDENCE_BY_LABEL:
            return CONFIDENCE_BY_LABEL[label], label
        return None, None
    if value is None:
        return None, None
    return None, None


def _confidence_label(confidence: float) -> str:
    """Confidence label function."""
    if confidence <= LOW_CONFIDENCE_THRESHOLD:
        return "low"
    if confidence <= 0.75:
        return "medium"
    return "high"


def _is_disallowed_source(source: str) -> bool:
    """Is disallowed source function."""
    normalized = source.strip().lower().replace("-", "_").replace(" ", "_")
    return normalized in WORKBENCH_DISALLOWED_MAPPING_SOURCES or normalized.startswith(
        WORKBENCH_DISALLOWED_MAPPING_SOURCE_PREFIXES
    )


def _normalize_metadata(
    metadata: dict[str, Any],
    mapping_file: Path,
    raw_content: bytes,
) -> dict[str, str | None]:
    """Normalize metadata function."""
    suffix = mapping_file.suffix.lower().lstrip(".")
    return {
        "mapping_framework": _optional_string(metadata.get("mapping_framework")),
        "mapping_framework_version": _optional_string(metadata.get("mapping_framework_version")),
        "mapping_version": _optional_string(metadata.get("mapping_version")),
        "attack_version": _optional_string(metadata.get("attack_version")),
        "domain": _optional_string(metadata.get("technology_domain")),
        "mapping_file_sha256": hashlib.sha256(raw_content).hexdigest(),
        "mapping_file": str(mapping_file),
        "creation_date": _optional_string(metadata.get("creation_date")),
        "last_update": _optional_string(metadata.get("last_update")),
        "organization": _optional_string(metadata.get("organization")),
        "author": _optional_string(metadata.get("author")),
        "contact": _optional_string(metadata.get("contact")),
        "metadata_format": f"vuln-prioritizer-curated-{suffix}",
        "metadata_source": ATTACK_SOURCE_LOCAL_CURATED,
    }


def _build_quality_report(
    *,
    metadata: dict[str, str | None],
    mappings: list[CveAttackMapping],
    confidence_labels: list[str],
    warnings: list[str],
) -> dict[str, Any]:
    """Build quality report function."""
    review_status_counts = _count_values(mapping.review_status for mapping in mappings)
    confidence_counts = _count_values(confidence_labels)
    mapping_type_counts = _count_values(mapping.mapping_type for mapping in mappings)
    low_confidence_mappings = [
        {
            "cve_id": mapping.cve_id,
            "technique_id": mapping.technique_id,
            "review_status": mapping.review_status,
            "confidence": mapping.metadata.get(
                "confidence_label", _confidence_label(mapping.confidence)
            ),
        }
        for mapping in mappings
        if mapping.metadata.get("confidence_label") == "low"
        or mapping.confidence <= LOW_CONFIDENCE_THRESHOLD
    ]
    return {
        "schema_version": "1.0.0",
        "source": ATTACK_SOURCE_LOCAL_CURATED,
        "mapping_file": metadata["mapping_file"],
        "mapping_file_sha256": metadata["mapping_file_sha256"],
        "mapping_count": len(mappings),
        "unique_cves": len({mapping.cve_id for mapping in mappings}),
        "unique_techniques": len({mapping.technique_id for mapping in mappings}),
        "review_status_counts": review_status_counts,
        "confidence_counts": confidence_counts,
        "mapping_type_counts": mapping_type_counts,
        "low_confidence_count": len(low_confidence_mappings),
        "low_confidence_mappings": low_confidence_mappings,
        "safety_review": {
            "defensive_notes_required": True,
            "reviewer_required_for_reviewed_status": True,
            "heuristic_or_llm_sources_rejected": True,
            "free_text_requires_human_review": True,
        },
        "warnings": warnings,
    }


def _curated_mapping_comment(mapping: CveAttackMapping, confidence_label: str) -> str:
    """Curated mapping comment function."""
    suffix = (
        f" Review status: {mapping.review_status}; confidence: {confidence_label}; "
        "local curated mapping."
    )
    return mapping.defensive_note.rstrip(".") + "." + suffix


def _tactic_short_names(tactic_ids: list[str]) -> list[str]:
    """Tactic short names function."""
    names: list[str] = []
    for tactic_id in tactic_ids:
        name = TACTIC_ID_TO_SHORT_NAME.get(tactic_id, tactic_id)
        if name not in names:
            names.append(name)
    return names


def _count_values(values: Any) -> dict[str, int]:
    """Count values function."""
    counts: dict[str, int] = {}
    for value in values:
        counts[str(value)] = counts.get(str(value), 0) + 1
    return dict(sorted(counts.items()))


def _coalesce(mapping: dict[str, Any], *keys: str) -> Any:
    """Coalesce function."""
    for key in keys:
        value = mapping.get(key)
        if _optional_string(value) is not None:
            return value
    return None


def _optional_string(value: Any) -> str | None:
    """Optional string function."""
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _string_list(value: Any) -> list[str]:
    """String list function."""
    if not isinstance(value, list):
        return []
    normalized: list[str] = []
    for item in value:
        text = _optional_string(item)
        if text is not None and text not in normalized:
            normalized.append(text)
    return normalized


def _string_metadata(value: dict[str, str | None]) -> dict[str, str]:
    """String metadata function."""
    return {key: item for key, item in value.items() if item is not None}
