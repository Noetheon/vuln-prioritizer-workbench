"""Deduplication key helpers for Workbench import persistence."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping

from app.domain.import_asset_context import string_evidence as _string_evidence
from app.importers.contracts import NormalizedOccurrence


def _dedup_key_parts(project_id: uuid.UUID, occurrence: NormalizedOccurrence) -> dict[str, str]:
    source_id = _normalized_identity_value(
        _string_evidence(occurrence.raw_evidence, "source_id")
        or _string_evidence(occurrence.raw_evidence, "vulnerability_id")
        or occurrence.cve
    )
    purl = _normalized_identity_value(_string_evidence(occurrence.raw_evidence, "purl"))
    component_identity = purl
    if component_identity == "__none__" and occurrence.component:
        component_identity = "|".join(
            [
                "component",
                _normalized_identity_value(occurrence.component),
                _normalized_identity_value(occurrence.version),
                _normalized_identity_value(
                    _string_evidence(occurrence.raw_evidence, "package_type")
                ),
            ]
        )
    return {
        "project_id": str(project_id),
        "source_id": source_id,
        "component_identity": component_identity,
        "asset_ref": _normalized_identity_value(occurrence.asset_ref),
    }


def _finding_dedup_key(parts: Mapping[str, str]) -> str:
    material = json.dumps(parts, sort_keys=True, separators=(",", ":"))
    return "vpw019:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def _normalized_identity_value(value: str | None) -> str:
    if value is None:
        return "__none__"
    normalized = value.strip()
    return normalized or "__none__"
